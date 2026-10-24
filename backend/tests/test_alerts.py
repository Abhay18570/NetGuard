"""Genuine persisted findings from synthetic ARP evidence; no traffic transmission."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import secrets
import pytest
from sqlalchemy import select, func
from backend.app import create_app
from backend.database.models import SecurityAlert, AlertAudit, DetectionFinding
from backend.database.store import Database
from backend.services.alerts import AlertService
from backend.tests.test_detection import packet


@pytest.fixture
def alert_app():
    app = create_app({'TESTING': True, 'ADMIN_TOKEN': secrets.token_urlsafe(32), 'ADMIN_ACTOR': 'test-admin'})
    yield app
    app.extensions['monitor'].stop(); app.extensions['detection'].close()


def create_finding(app, source='offline', session='test'):
    detector = app.extensions['detection']
    detector.process(packet(source=source, session=session))
    findings = detector.process(packet(2, 1, mac='02:00:00:00:00:03', source=source, session=session))
    app.extensions['incidents'].drain()
    return findings[0]


def auth(app): return {'Authorization': 'Bearer ' + app.config['ADMIN_TOKEN']}


def test_empty_alerts_and_summary(alert_app):
    client = alert_app.test_client()
    assert client.get('/api/security-alerts').json['total'] == 0
    assert client.get('/api/security-alerts/summary').json['counts']['live']['New'] == 0
    assert client.get('/api/incidents').json['total'] == 0


def test_alert_created_only_from_persisted_finding(alert_app):
    finding = create_finding(alert_app)
    item = alert_app.test_client().get('/api/security-alerts').json['items'][0]
    assert item['findingId'] == finding['id']
    assert item['severity'] == finding['severity']
    assert item['confidence'] == finding['confidence']
    assert item['packetIds'] == finding['packetIds']
    assert item['status'] == 'New' and item['version'] == 1
    assert item['classification'] == 'suspicious_observation'
    assert alert_app.test_client().get(item['evidenceRef']).json == finding
    assert alert_app.test_client().post('/api/security-alerts', json={}).status_code == 405


def test_reprocessed_finding_no_duplicate_alert(alert_app):
    create_finding(alert_app)
    alert_app.extensions['detection'].process(packet(2, 1, mac='02:00:00:00:00:03'))
    for _ in range(3): alert_app.extensions['alerts'].reconcile()
    assert alert_app.extensions['alerts'].page()['total'] == 1


def test_live_replay_isolation(alert_app):
    create_finding(alert_app, 'live', 'live'); create_finding(alert_app, 'offline', 'offline')
    client = alert_app.test_client()
    assert client.get('/api/security-alerts?source=live').json['total'] == 1
    assert client.get('/api/security-alerts?source=offline').json['total'] == 1
    counts = client.get('/api/security-alerts/summary').json['counts']
    assert counts['live']['New'] == counts['offline']['New'] == 1


@pytest.mark.parametrize('new_status', ['Acknowledged', 'Investigating', 'Resolved'])
def test_authorized_status_and_atomic_audit(alert_app, new_status):
    create_finding(alert_app); client = alert_app.test_client(); alert = client.get('/api/security-alerts').json['items'][0]
    result = client.patch('/api/security-alerts/' + alert['id'], headers=auth(alert_app), json={'status': new_status, 'version': 1, 'reason': 'Reviewed controlled evidence'})
    assert result.status_code == 200
    assert result.json['status'] == new_status and result.json['version'] == 2
    history = client.get(f"/api/security-alerts/{alert['id']}/audit").json
    assert history['total'] == 1
    assert history['items'][0]['actor'] == 'test-admin'
    assert history['items'][0]['previousStatus'] == 'New'
    assert history['items'][0]['newStatus'] == new_status
    assert client.get('/api/security-alerts/summary').json['counts']['offline']['New'] == 0
    assert client.get('/api/alerts').json['items'][0]['status'] == 'Unreviewed'


@pytest.mark.parametrize('header', [{}, {'Authorization': 'Bearer wrong'}])
def test_unauthorized_updates(alert_app, header):
    create_finding(alert_app); item = alert_app.extensions['alerts'].page()['items'][0]
    assert alert_app.test_client().patch('/api/security-alerts/' + item['id'], headers=header, json={'status': 'Resolved', 'version': 1, 'reason': 'test'}).status_code == 401
    assert alert_app.extensions['alerts'].detail(item['id'])['status'] == 'New'
    assert alert_app.extensions['alerts'].audit(item['id'])['total'] == 0


@pytest.mark.parametrize('body', [
    {'status': 'Resolved', 'version': 1}, {'status': 'Resolved', 'version': True, 'reason': 'x'},
    {'status': 'Bogus', 'version': 1, 'reason': 'x'}, {'status': 'Resolved', 'version': 1, 'reason': ' '},
    {'status': 'Resolved', 'version': 1, 'reason': 'x'*501}, {'status': 'Resolved', 'version': 1, 'reason': 'x', 'actor': 'forged'},
])
def test_invalid_updates(alert_app, body):
    create_finding(alert_app); item = alert_app.extensions['alerts'].page()['items'][0]
    assert alert_app.test_client().patch('/api/security-alerts/' + item['id'], headers=auth(alert_app), json=body).status_code == 400


def test_stale_version_and_transition_rules(alert_app):
    create_finding(alert_app); service = alert_app.extensions['alerts']; item = service.page()['items'][0]; client = alert_app.test_client(); path = '/api/security-alerts/' + item['id']
    service.change(item['id'], {'status': 'Resolved', 'version': 1, 'reason': 'reviewed'}, 'test-admin')
    assert client.patch(path, headers=auth(alert_app), json={'status': 'Investigating', 'version': 1, 'reason': 'stale'}).status_code == 409
    assert client.patch(path, headers=auth(alert_app), json={'status': 'New', 'version': 2, 'reason': 'invalid'}).status_code == 409
    assert client.patch(path, headers=auth(alert_app), json={'status': 'Investigating', 'version': 2, 'reason': 'reopen'}).status_code == 200


@pytest.mark.parametrize('query', ['status=bad', 'source=bad', 'severity=Critical', 'q='+'x'*121, 'offset=-1', 'status=New&status=New', 'unknown=x'])
def test_alert_filter_validation(alert_app, query):
    assert alert_app.test_client().get('/api/security-alerts?' + query).status_code == 400


def test_filter_search_and_pagination(alert_app):
    create_finding(alert_app)
    client = alert_app.test_client()
    assert client.get('/api/security-alerts?status=New&severity=Medium&q=192.0.2.1').json['total'] == 1
    assert client.get('/api/security-alerts?status=Resolved').json['total'] == 0
    assert client.get('/api/security-alerts?offset=1&limit=1').json['items'] == []


def test_stream_contract_and_reconnect_recovery(alert_app):
    io = alert_app.extensions['socketio']; socket = io.test_client(alert_app)
    create_finding(alert_app)
    event = next(e for e in socket.get_received() if e['name'] == 'alert_created')
    assert event['args'][0]['version'] == 1
    item = event['args'][0]['alert']
    alert_app.extensions['alerts'].change(item['id'], {'status': 'Acknowledged', 'version': 1, 'reason': 'review'}, 'test-admin')
    assert next(e for e in socket.get_received() if e['name'] == 'alert_updated')['args'][0]['alert']['version'] == 2
    socket.disconnect(); create_finding(alert_app, session='missed')
    socket = io.test_client(alert_app)
    assert socket.get_received() == []
    assert alert_app.test_client().get('/api/security-alerts').json['total'] == 2
    socket.disconnect()


def test_persistence_and_phase5_backfill(tmp_path):
    url = f'sqlite:///{tmp_path / "alerts.sqlite"}'
    app = create_app({'TESTING': True, 'DATABASE_URL': url}); finding = create_finding(app)
    service = app.extensions['alerts']; item = service.page()['items'][0]
    service.change(item['id'], {'status': 'Investigating', 'version': 1, 'reason': 'investigate'}, 'test-admin')
    second = AlertService(Database(url), lambda *_: None)
    assert second.detail(item['id'])['status'] == 'Investigating'
    assert second.audit(item['id'])['total'] == 1
    # Existing Phase 5 evidence lacking alert rows is recovered without modifying evidence.
    with app.extensions['database'].transaction(write=True) as session:
        original = session.get(DetectionFinding, finding['id'])
        copied = dict(original.payload); copied['id'] = 'pre-phase6'
        session.add(DetectionFinding(id='pre-phase6', timestamp=original.timestamp, source=original.source, scope=original.scope, rule_id=original.rule_id, severity=original.severity, payload=copied))
    second.reconcile(); second.reconcile()
    assert second.page()['total'] == 2
    assert second.detail(item['id'])['status'] == 'Investigating'


def test_concurrent_reconciliation_and_updates(alert_app):
    create_finding(alert_app); service = alert_app.extensions['alerts']; item = service.page()['items'][0]
    with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(lambda _: service.reconcile(), range(20)))
    assert service.page()['total'] == 1
    def change(_):
        try: service.change(item['id'], {'status': 'Acknowledged', 'version': 1, 'reason': 'concurrent'}, 'test-admin'); return 200
        except Exception as error: return error.status
    with ThreadPoolExecutor(max_workers=8) as pool: results = list(pool.map(change, range(8)))
    assert results.count(200) == 1 and results.count(409) == 7
    assert service.audit(item['id'])['total'] == 1


def test_database_failure_rollback_and_no_event(alert_app, monkeypatch):
    create_finding(alert_app); service = alert_app.extensions['alerts']; item = service.page()['items'][0]
    socket = alert_app.extensions['socketio'].test_client(alert_app)
    original = service.database.transaction
    @contextmanager
    def rollback(*args, **kwargs):
        with original(*args, **kwargs) as session:
            yield session
            raise RuntimeError('controlled commit failure')
    monkeypatch.setattr(service.database, 'transaction', rollback)
    with pytest.raises(RuntimeError): service.change(item['id'], {'status': 'Resolved', 'version': 1, 'reason': 'test'}, 'test-admin')
    monkeypatch.setattr(service.database, 'transaction', original)
    assert service.detail(item['id'])['status'] == 'New'
    assert service.audit(item['id'])['total'] == 0
    assert socket.get_received() == []
    socket.disconnect()


def test_missing_resource_and_origin_rejection(alert_app):
    client = alert_app.test_client()
    assert client.get('/api/security-alerts/missing').status_code == 404
    assert client.get('/api/findings/missing').status_code == 404
    assert client.patch('/api/security-alerts/missing', headers={**auth(alert_app), 'Origin': 'https://untrusted.invalid'}, json={}).status_code == 403


def test_alert_foreign_key_requires_finding(alert_app):
    from backend.errors import APIError
    with pytest.raises(APIError):
        with alert_app.extensions['database'].transaction(write=True) as session:
            session.add(SecurityAlert(id='fake', finding_id='absent', status='New', version=1, created_at='now', updated_at='now'))
    with alert_app.extensions['database'].transaction() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAlert)) == 0


@pytest.mark.parametrize('severity', ['Low', 'Medium', 'High'])
def test_actual_rule_severity_mapping(alert_app, severity):
    detector = alert_app.extensions['detection']
    if severity == 'Medium': create_finding(alert_app)
    elif severity == 'Low':
        detector.process(packet())
        for n in range(2, 7): detector.process(packet(n, n + 4, operation='Reply'))
    else:
        from backend.tests.test_detection import baseline
        baseline(detector)
        for n in range(1, 4): detector.process(packet(n, n, source='live', mac='02:00:00:00:00:03'))
    items = alert_app.extensions['alerts'].page(severity=severity)['items']
    assert items and all(item['severity'] == severity for item in items)
    with alert_app.extensions['database'].transaction() as session:
        for item in items: assert session.get(DetectionFinding, item['findingId']).severity == severity


def test_alert_creation_rolls_back_with_finding_failure(alert_app, monkeypatch):
    from backend.detection import service as detection_module
    detector = alert_app.extensions['detection']; detector.process(packet())
    def fail(*_): raise RuntimeError('controlled alert persistence failure')
    monkeypatch.setattr(detection_module, 'ensure_alert', fail)
    detector.enqueue(packet(2, 1, mac='02:00:00:00:00:03')); detector.drain()
    assert detector.status()['failedPackets'] == 1
    with alert_app.extensions['database'].transaction() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAlert)) == 0
        assert session.scalar(select(func.count()).select_from(DetectionFinding)) == 0


def test_database_unavailable_json_error(alert_app, monkeypatch):
    from sqlalchemy.exc import OperationalError
    def failure(): raise OperationalError('test', {}, Exception('unavailable'))
    monkeypatch.setattr(alert_app.extensions['database'], 'initialize', failure)
    response = alert_app.test_client().get('/api/security-alerts')
    assert response.status_code == 503 and response.json['error']['code'] == 'database_unavailable'


def test_pre_phase6_schema_upgrade_preserves_findings(tmp_path):
    url = f'sqlite:///{tmp_path / "upgrade.sqlite"}'
    app = create_app({'TESTING': True, 'DATABASE_URL': url}); finding = create_finding(app)
    database = app.extensions['database']
    from backend.database.models import IncidentAudit, IncidentAlert, InvestigationIncident
    IncidentAudit.__table__.drop(database.engine); IncidentAlert.__table__.drop(database.engine); InvestigationIncident.__table__.drop(database.engine)
    AlertAudit.__table__.drop(database.engine); SecurityAlert.__table__.drop(database.engine)
    upgraded = Database(url); service = AlertService(upgraded, lambda *_: None)
    assert service.page()['items'][0]['findingId'] == finding['id']
    with upgraded.transaction() as session: assert session.get(DetectionFinding, finding['id']).payload == finding
