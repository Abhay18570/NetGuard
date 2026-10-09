"""Incident workflow tests use actual packet-derived findings and temporary databases."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import csv
import io
import secrets
import time
import pytest
from sqlalchemy import select, func, text
from backend.app import create_app
from backend.database.models import InvestigationIncident, IncidentAlert, IncidentAudit, SecurityAlert
from backend.database.store import Database
from backend.incidents.policy import IncidentLimits
from backend.incidents.service import IncidentService
from backend.tests.test_detection import packet
from backend.errors import APIError


@pytest.fixture
def incident_app():
    app = create_app({'TESTING': True, 'ADMIN_TOKEN': secrets.token_urlsafe(32), 'ADMIN_ACTOR': 'investigator', 'REPLAY_INTERVAL': 0})
    yield app
    app.extensions['monitor'].stop(); app.extensions['detection'].close(); app.extensions['incidents'].close()


def evidence(app, source='offline', session='test', interface='en0'):
    detector = app.extensions['detection']
    for record in (packet(source=source, session=session), packet(2, 1, mac='02:00:00:00:00:03', source=source, session=session)):
        if source == 'live': record['interface'] = interface
        detector.process(record)
    app.extensions['incidents'].drain()
    return app.extensions['incidents'].page()['items'][0]


def auth(app): return {'Authorization': 'Bearer ' + app.config['ADMIN_TOKEN']}


def change(app, row, **fields):
    return app.test_client().patch('/api/incidents/' + row['id'], headers=auth(app), json={'version': row['version'], 'reason': 'Reviewed synthetic evidence', **fields})


def test_empty_state_and_no_client_creation(incident_app):
    client = incident_app.test_client()
    assert client.get('/api/incidents').json['items'] == []
    assert client.get('/api/defense/summary').json['counts']['live']['Open'] == 0
    assert client.post('/api/incidents', json={}).status_code == 405


def test_correlation_multiple_alerts_and_packet_references(incident_app):
    row = evidence(incident_app)
    detector = incident_app.extensions['detection']
    detector.process(packet(3, 60)); detector.process(packet(4, 61, mac='02:00:00:00:00:03'))
    incident_app.extensions['incidents'].drain()
    page = incident_app.extensions['incidents'].page()
    assert page['total'] == 1 and len(page['items'][0]['alertIds']) == 3
    detail = incident_app.test_client().get('/api/incidents/' + row['id']).json
    assert len(detail['alerts']) == len(detail['findingIds']) == 3
    assert set(detail['packetIds']) == {'test:1', 'test:2', 'test:3', 'test:4'}
    assert detail['classification'] == 'suspicious_observation'
    assert detail['source'] == 'offline' and detail['interface'] is None
    assert incident_app.extensions['incidents'].audit(row['id'])['total'] == 3


def test_duplicate_and_concurrent_reconciliation(incident_app):
    row = evidence(incident_app)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: incident_app.extensions['incidents'].reconcile(), range(30)))
    incident_app.extensions['detection'].process(packet(2, 1, mac='02:00:00:00:00:03'))
    assert incident_app.extensions['incidents'].page()['total'] == 1
    assert incident_app.extensions['incidents'].audit(row['id'])['total'] == 1


@pytest.mark.parametrize('source,session,interface', [('offline', 'other', 'en0'), ('live', 'test', 'en0'), ('live', 'other', 'en1')])
def test_source_session_isolation(incident_app, source, session, interface):
    evidence(incident_app)
    # Packet identities are capture-session-owned; distinct sessions have distinct IDs.
    evidence(incident_app, source, session + '-new', interface)
    assert incident_app.extensions['incidents'].page()['total'] == 2


def test_window_does_not_chain_forever(incident_app):
    evidence(incident_app)
    detector = incident_app.extensions['detection']
    detector.process(packet(3, 400)); detector.process(packet(4, 401, mac='02:00:00:00:00:03'))
    incident_app.extensions['incidents'].drain()
    assert incident_app.extensions['incidents'].page()['total'] == 2


def test_exact_rules_not_merged(incident_app):
    from backend.tests.test_detection import baseline
    detector = incident_app.extensions['detection']; baseline(detector)
    evidence(incident_app, 'live')
    rows = incident_app.extensions['incidents'].page()['items']
    assert len(rows) == 2
    assert {r['ruleId'] for r in rows} == {'ARP_CLAIM_CONFLICT', 'ARP_GATEWAY_MISMATCH'}


def test_severity_escalation_preserves_references(incident_app):
    from backend.tests.test_detection import baseline
    detector = incident_app.extensions['detection']; baseline(detector)
    for n in range(1, 4): detector.process(packet(n, n, source='live', mac='02:00:00:00:00:03'))
    incident_app.extensions['incidents'].drain()
    rows = incident_app.extensions['incidents'].page()['items']
    assert len(rows) == 1 and rows[0]['severity'] == 'High' and len(rows[0]['alertIds']) == 2


def test_complete_lifecycle_and_containment_report(incident_app):
    row = evidence(incident_app)
    row = change(incident_app, row, status='Investigating', assignedTo='Analyst A').json
    denied = change(incident_app, row, status='Contained'); assert denied.status_code == 400
    denied = change(incident_app, row, status='Contained', containmentConfirmed=True); assert denied.status_code == 400
    row = change(incident_app, row, status='Contained', containmentConfirmed=True, externalAction='Administrator reports approved external review and containment.').json
    assert row['status'] == 'Contained' and row['containment'] == 'administrator_report_only'
    assert change(incident_app, row, status='Resolved').status_code == 400
    row = change(incident_app, row, status='Resolved', resolutionNotes='Documented legitimate replacement; review complete.').json
    row = change(incident_app, row, status='Closed').json
    assert row['status'] == 'Closed'
    assert change(incident_app, row, resolutionNotes='').status_code == 400
    reopened = change(incident_app, row, status='Investigating').json
    assert reopened['status'] == 'Investigating'
    audit = incident_app.extensions['incidents'].audit(row['id'])
    assert audit['total'] == 6
    containment = next(a for a in audit['items'] if a['newStatus'] == 'Contained')
    assert containment['actor'] == 'investigator' and containment['details']['containmentConfirmed'] is True
    assert containment['details']['verification'] == 'administrator_report_not_verified_by_netguard'


def test_resolved_incidents_not_silently_reopened(incident_app):
    row = evidence(incident_app)
    assert change(incident_app, row, status='Resolved', resolutionNotes='Reviewed').status_code == 200
    incident_app.extensions['detection'].process(packet(3, 60))
    incident_app.extensions['incidents'].drain()
    rows = incident_app.extensions['incidents'].page()['items']
    assert len(rows) == 2 and {r['status'] for r in rows} == {'Open', 'Resolved'}


@pytest.mark.parametrize('fields,code', [
    ({'status': 'Closed'}, 409), ({'status': 'Bad'}, 400), ({'version': True, 'assignedTo': 'a'}, 400),
    ({'status': 'Investigating', 'reason': ''}, 400), ({'status': 'Investigating', 'actor': 'forged'}, 400),
    ({'assignedTo': 'x'*121}, 400), ({'resolutionNotes': 'x'*2001}, 400),
    ({'status': 'Investigating', 'containmentConfirmed': True}, 400),
    ({'status': 'Contained', 'containmentConfirmed': True, 'externalAction': 'claimed'}, 409),
])
def test_mutation_validation(incident_app, fields, code):
    row = evidence(incident_app)
    assert change(incident_app, row, **fields).status_code == code


def test_authorization_and_export_permission(incident_app):
    row = evidence(incident_app); client = incident_app.test_client(); path = '/api/incidents/' + row['id']
    assert client.patch(path, json={'status': 'Investigating', 'version': 1, 'reason': 'test'}).status_code == 401
    assert client.post(path + '/actions', json={}).status_code == 401
    assert client.get(path + '/export').status_code == 401
    assert client.patch(path, headers={**auth(incident_app), 'Origin': 'https://untrusted.invalid'}, json={}).status_code == 403
    assert incident_app.extensions['incidents'].audit(row['id'])['total'] == 1


def action_body(row):
    return {'version': row['version'], 'reason': 'Review record', 'actionId': 'dhcp_leases', 'confirmed': True,
            'description': 'Reviewed approved DHCP lease records for replacement.', 'performedAt': '2026-01-01T00:00:00Z'}


def test_external_checklist_action_does_not_contain_incident(incident_app):
    row = evidence(incident_app)
    response = incident_app.test_client().post('/api/incidents/' + row['id'] + '/actions', headers=auth(incident_app), json=action_body(row))
    assert response.status_code == 200 and response.json['status'] == 'Open'
    entry = incident_app.extensions['incidents'].audit(row['id'])['items'][0]
    assert entry['action'] == 'external_action' and entry['details']['source'] == 'offline'
    assert entry['details']['actionId'] == 'dhcp_leases' and entry['details']['confirmed'] is True
    detail = incident_app.extensions['incidents'].detail(row['id'])
    assert detail['completedActions'][0]['actionId'] == 'dhcp_leases'
    assert detail['completedActions'][0]['actor'] == 'investigator'


@pytest.mark.parametrize('override', [{'confirmed': False}, {'confirmed': 'true'}, {'description': ''}, {'actionId': 'run_command'}, {'performedAt': '2999-01-01T00:00:00Z'}, {'performedAt': '2026-01-01'}, {'performedAt': 'bad'}])
def test_external_action_validation(incident_app, override):
    row = evidence(incident_app)
    response = incident_app.test_client().post('/api/incidents/' + row['id'] + '/actions', headers=auth(incident_app), json={**action_body(row), **override})
    assert response.status_code == 400


def test_concurrent_updates_only_one_commits(incident_app):
    row = evidence(incident_app); service = incident_app.extensions['incidents']
    def update(_):
        try: service.change(row['id'], {'version': row['version'], 'reason': 'Concurrent', 'status': 'Investigating'}, 'investigator'); return 200
        except APIError as error: return error.status
    with ThreadPoolExecutor(max_workers=8) as pool: codes = list(pool.map(update, range(8)))
    assert codes.count(200) == 1 and codes.count(409) == 7
    assert service.audit(row['id'])['total'] == 2


def test_atomic_audit_rollback_no_event(incident_app, monkeypatch):
    row = evidence(incident_app); service = incident_app.extensions['incidents']; original = service.database.transaction
    socket = incident_app.extensions['socketio'].test_client(incident_app)
    @contextmanager
    def rollback(*args, **kwargs):
        with original(*args, **kwargs) as session:
            yield session
            raise RuntimeError('controlled commit failure')
    monkeypatch.setattr(service.database, 'transaction', rollback)
    with pytest.raises(RuntimeError): service.change(row['id'], {'version': row['version'], 'status': 'Investigating', 'reason': 'test'}, 'investigator')
    monkeypatch.setattr(service.database, 'transaction', original)
    assert service.detail(row['id'])['status'] == 'Open' and service.audit(row['id'])['total'] == 1
    assert socket.get_received() == []; socket.disconnect()


def test_correlation_failure_retains_alert_and_recovers(incident_app, monkeypatch):
    service = incident_app.extensions['incidents']; original = service.reconcile
    def fail(): raise RuntimeError('controlled incident database failure')
    monkeypatch.setattr(service, 'reconcile', fail)
    incident_app.extensions['detection'].process(packet()); incident_app.extensions['detection'].process(packet(2, 1, mac='02:00:00:00:00:03'))
    service.drain(); assert service.failure_count >= 1
    assert incident_app.extensions['alerts'].page()['total'] == 1
    monkeypatch.setattr(service, 'reconcile', original)
    assert service.page()['total'] == 1


def test_defense_guidance_and_explicit_gateway_status(incident_app):
    from backend.tests.test_detection import baseline
    baseline(incident_app.extensions['detection'])
    incident_app.extensions['incidents'].gateway_ids = ('gateway', 'missing')
    summary = incident_app.test_client().get('/api/defense/summary').json
    assert summary['advisoryOnly'] is True
    assert [x['state'] for x in summary['gatewayBaselines']] == ['verified', 'missing']
    assert {r['id'] for r in summary['recommendations']} == {'gateway_baseline', 'dhcp_leases', 'equipment', 'switch_review', 'escalate', 'document_action'}
    assert summary['storage']['limitBytes'] <= 1073741824


def test_json_csv_export_scoped_and_formula_safe(incident_app):
    row = evidence(incident_app); unrelated = evidence(incident_app, session='unrelated')
    row = change(incident_app, row, assignedTo='=HYPERLINK("malicious")', resolutionNotes='Private admin token: ' + incident_app.config['ADMIN_TOKEN']).json
    client = incident_app.test_client(); path = '/api/incidents/' + row['id'] + '/export'
    result = client.get(path, headers=auth(incident_app))
    assert result.status_code == 200
    data = result.json
    assert data['incident']['id'] == row['id'] and len(data['incident']['alerts']) == 1
    assert unrelated['id'] not in result.text and incident_app.config['ADMIN_TOKEN'] not in result.text
    assert '[REDACTED]' in result.text
    csv_response = client.get(path + '?format=csv', headers=auth(incident_app))
    entries = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert any(x['field'] == 'assignedTo' and x['value'].startswith("'=HYPERLINK") for x in entries)
    assert csv_response.headers['Content-Disposition'].endswith('.csv"')
    assert client.get(path + '?format=html', headers=auth(incident_app)).status_code == 400
    incident_app.config['INCIDENT_EXPORT_MAX_BYTES'] = 1
    assert client.get(path, headers=auth(incident_app)).status_code == 413


def test_persistence_safe_upgrade_and_restart(tmp_path):
    url = f'sqlite:///{tmp_path / "incident.sqlite"}'
    app = create_app({'TESTING': True, 'DATABASE_URL': url}); row = evidence(app)
    service = app.extensions['incidents']; service.change(row['id'], {'version': row['version'], 'status': 'Investigating', 'reason': 'Reviewed'}, 'admin')
    service.close()
    reopened = IncidentService(Database(url), lambda *_: None)
    assert reopened.detail(row['id'])['status'] == 'Investigating' and reopened.audit(row['id'])['total'] == 2
    # Model a Phase 6 database, preserving its original alert and finding rows.
    IncidentAudit.__table__.drop(app.extensions['database'].engine)
    IncidentAlert.__table__.drop(app.extensions['database'].engine)
    InvestigationIncident.__table__.drop(app.extensions['database'].engine)
    upgraded = IncidentService(Database(url), lambda *_: None)
    item = upgraded.page()['items'][0]
    assert item['alertIds'] == row['alertIds'] and item['findingIds'] == row['findingIds']


def test_capacity_backlog_is_honest_no_evidence_deleted(incident_app):
    service = incident_app.extensions['incidents']; service.limits = IncidentLimits(max_incidents=1)
    evidence(incident_app); evidence(incident_app, session='second')
    summary = service.summary()
    assert summary['pendingAlerts'] == 1 and summary['capacityMessage']
    assert incident_app.extensions['alerts'].page()['total'] == 2
    service.limits = IncidentLimits(max_incidents=2)
    assert service.page()['total'] == 2


def test_audit_capacity_does_not_update_status(incident_app):
    row = evidence(incident_app); incident_app.extensions['incidents'].limits = IncidentLimits(audit_per_incident=1)
    assert change(incident_app, row, status='Investigating').status_code == 503
    assert incident_app.extensions['incidents'].detail(row['id'])['status'] == 'Open'


@pytest.mark.parametrize('query', ['status=bad', 'source=bad', 'severity=Critical', 'q='+'x'*121, 'limit=0', 'status=Open&status=Open', 'bad=1'])
def test_query_validation(incident_app, query):
    assert incident_app.test_client().get('/api/incidents?' + query).status_code == 400


def test_filters_pagination_and_unknown_id(incident_app):
    evidence(incident_app)
    client = incident_app.test_client()
    assert client.get('/api/incidents?source=offline&status=Open&q=192.0.2.1').json['total'] == 1
    assert client.get('/api/incidents?source=live').json['total'] == 0
    assert client.get('/api/incidents?q=02:00:00:00:00:01').json['total'] == 1
    assert client.get('/api/incidents?offset=1&limit=1').json['items'] == []
    assert client.get('/api/incidents/missing').status_code == 404


def test_socket_delivery_reconnect_and_pcap_flow(incident_app):
    client = incident_app.test_client(); socket = incident_app.extensions['socketio'].test_client(incident_app)
    fixture = Path('backend/tests/fixtures/detection-conflict.pcap').read_bytes()
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(fixture), 'offline.pcap')})
    assert response.status_code in (200, 202)
    deadline = time.monotonic() + 3
    while incident_app.extensions['monitor'].status()['state'] != 'completed' and time.monotonic() < deadline: time.sleep(.01)
    incident_app.extensions['detection'].drain(); incident_app.extensions['incidents'].drain()
    events = socket.get_received(); created = next(e for e in events if e['name'] == 'incident_created')['args'][0]
    assert created['version'] == 1
    row = created['incident']; assert row['source'] == 'offline'
    assert len(row['alertIds']) == len(row['findingIds']) == 1
    assert change(incident_app, row, status='Investigating').status_code == 200
    assert any(e['name'] == 'incident_updated' for e in socket.get_received())
    socket.disconnect(); evidence(incident_app, session='missed')
    socket = incident_app.extensions['socketio'].test_client(incident_app)
    assert socket.get_received() == []
    assert client.get('/api/incidents').json['total'] == 2
    socket.disconnect()


def test_sqlite_storage_budget_prevents_growth_without_deletion(tmp_path):
    database = Database(f'sqlite:///{tmp_path / "budget.sqlite"}', max_bytes=1048576)
    with database.transaction(write=True) as session: session.execute(text('CREATE TABLE quota_test (data BLOB)'))
    with pytest.raises(APIError):
        with database.transaction(write=True) as session: session.execute(text('INSERT INTO quota_test VALUES (zeroblob(2097152))'))
    with database.transaction() as session: assert session.scalar(text('SELECT count(*) FROM quota_test')) == 0
    assert database.storage_status()['limitBytes'] == 1048576


def test_concurrent_initial_creation_from_backlog(incident_app):
    service = incident_app.extensions['incidents']; service.close()
    detector = incident_app.extensions['detection']
    detector.process(packet()); detector.process(packet(2, 1, mac='02:00:00:00:00:03'))
    with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(lambda _: service.reconcile(), range(16)))
    assert service.page()['total'] == 1
    with incident_app.extensions['database'].transaction() as session:
        assert session.scalar(select(func.count()).select_from(IncidentAlert)) == 1


def test_different_ip_claims_do_not_merge(incident_app):
    evidence(incident_app)
    detector = incident_app.extensions['detection']
    detector.process(packet(3, 2, ip='192.0.2.9'))
    detector.process(packet(4, 3, ip='192.0.2.9', mac='02:00:00:00:00:03'))
    incident_app.extensions['incidents'].drain()
    assert incident_app.extensions['incidents'].page()['total'] == 2


def test_reduced_window_never_merges_an_overlong_existing_span(incident_app):
    evidence(incident_app)
    detector = incident_app.extensions['detection']; service = incident_app.extensions['incidents']
    detector.process(packet(3, 60)); detector.process(packet(4, 61, mac='02:00:00:00:00:03')); service.drain()
    assert service.page()['total'] == 1
    service.limits = IncidentLimits(window_seconds=1)
    detector.process(packet(5, 120)); service.drain()
    assert service.page()['total'] == 2


def test_incident_failure_does_not_interrupt_running_capture(monkeypatch):
    from threading import Event
    from scapy.all import ARP, Ether
    sent = Event()
    class Engine:
        def run(self, interface, stop, ready, receive):
            ready()
            for n, mac in enumerate(('02:00:00:00:00:01', '02:00:00:00:00:03')):
                p = Ether(src=mac) / ARP(psrc='192.0.2.1', hwsrc=mac, pdst='192.0.2.2'); p.time = 1700000000 + n; receive(p)
            sent.set(); stop.wait(3)
    app = create_app({'TESTING': True, 'CAPTURE_ENGINE_FACTORY': Engine})
    def fail(): raise RuntimeError('controlled incident failure')
    monkeypatch.setattr(app.extensions['incidents'], 'reconcile', fail)
    try:
        app.extensions['monitor'].start('en0'); assert sent.wait(2)
        app.extensions['detection'].drain(); app.extensions['incidents'].drain()
        assert app.extensions['monitor'].status()['state'] == 'running'
        assert app.extensions['alerts'].page()['total'] == 1
        assert app.extensions['incidents'].failure_count >= 1
    finally:
        app.extensions['monitor'].stop(); app.extensions['detection'].close(); app.extensions['incidents'].close()


def test_database_unavailable_response_is_explicit(incident_app, monkeypatch):
    from sqlalchemy.exc import OperationalError
    def fail(): raise OperationalError('read', {}, Exception('unavailable'))
    monkeypatch.setattr(incident_app.extensions['database'], 'initialize', fail)
    response = incident_app.test_client().get('/api/defense/summary')
    assert response.status_code == 503 and response.json['error']['code'] == 'database_unavailable'


def test_smaller_quota_preserves_preexisting_database(tmp_path):
    path = tmp_path / 'preexisting.sqlite'; database = Database(f'sqlite:///{path}', max_bytes=4194304)
    with database.transaction(write=True) as session:
        session.execute(text('CREATE TABLE existing_data (payload BLOB)'))
        session.execute(text('INSERT INTO existing_data VALUES (zeroblob(2097152))'))
    database.engine.dispose()
    reopened = Database(f'sqlite:///{path}', max_bytes=1048576)
    with reopened.transaction() as session: assert session.scalar(text('SELECT length(payload) FROM existing_data')) == 2097152
    assert reopened.storage_status()['usedBytes'] > 1048576
    assert reopened.storage_status()['limitBytes'] >= reopened.storage_status()['usedBytes']


@pytest.mark.parametrize('config', [{'window_seconds': 0}, {'max_incidents': True}, {'links_per_incident': 501}, {'audit_per_incident': 1001}, {'unknown': 5}])
def test_invalid_incident_limits(config):
    with pytest.raises((ValueError, TypeError)): IncidentLimits(**config)
