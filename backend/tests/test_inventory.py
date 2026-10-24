from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
import time
import pytest
from sqlalchemy import event, inspect, select
from sqlalchemy.exc import OperationalError
from backend.app import create_app
from backend.database.models import ObservationReceipt, TrustAudit
from backend.discovery.validation import normalize_mac
from backend.errors import APIError

TOKEN = 'test-admin-token-not-a-real-secret-123456789'
HEADERS = {'Authorization': 'Bearer ' + TOKEN}


def packet(index=1, **overrides):
    return {'id': f'session-a:{index}', 'sessionId': 'session-a', 'source': 'live', 'interface': 'en0',
            'senderIp': '192.0.2.1', 'senderMac': '02:AA:00:00:00:01',
            'targetIp': '192.0.2.2', 'targetMac': '00:00:00:00:00:00',
            'timestamp': '2023-11-14T22:13:20+00:00', **overrides}


@pytest.fixture
def inventory_app(monkeypatch):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [(1, 'en0'), (2, 'en1')])
    app = create_app({'TESTING': True, 'ADMIN_TOKEN': TOKEN, 'ADMIN_ACTOR': 'test-admin', 'REPLAY_INTERVAL': 0.001})
    yield app
    app.extensions['monitor'].stop()
    app.extensions['database'].engine.dispose()


def create(client, **fields):
    return client.post('/api/trusted-mappings', json={
        'ip': '192.0.2.1', 'mac': '02-aa-00-00-00-01', 'interface': 'en0',
        'reason': 'Compared with approved inventory', **fields}, headers=HEADERS)


def verify(client, mapping):
    return client.post(f"/api/trusted-mappings/{mapping['id']}/verify", json={'version': mapping['version'], 'reason': 'Verified with administrator'}, headers=HEADERS)


def test_sender_only_and_duplicate_delivery(inventory_app):
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    service.observe(packet()); service.observe(packet())
    items = client.get('/api/devices').json['items']
    assert len(items) == 1 and items[0]['observationCount'] == 1
    assert items[0]['ip'] == '192.0.2.1' and items[0]['mac'] == '02:aa:00:00:00:01'
    assert not items[0]['trusted'] and items[0]['hostname'] == ''
    assert client.get('/api/trusted-mappings').json['items'] == []
    service.observe(packet(2))
    assert client.get('/api/devices').json['items'][0]['observationCount'] == 2


@pytest.mark.parametrize('value', ['02-AA-00-00-00-01', '02:aa:00:00:00:01', '02aa.0000.0001', '02AA00000001'])
def test_mac_normalization(value):
    assert normalize_mac(value) == '02:aa:00:00:00:01'


@pytest.mark.parametrize('field,value', [('senderIp', '0.0.0.0'), ('senderIp', '255.255.255.255'), ('senderIp', '224.0.0.1'), ('senderIp', '::1'), ('senderIp', 'bad'), ('senderIp', 123), ('senderMac', 'ff:ff:ff:ff:ff:ff'), ('senderMac', '00:00:00:00:00:00'), ('senderMac', '01:00:5e:00:00:01'), ('senderMac', 'invalid'), ('senderMac', None), ('timestamp', 'invalid'), ('timestamp', '2023-01-01T00:00:00')])
def test_invalid_claims_do_not_create_devices(inventory_app, field, value):
    service = inventory_app.extensions['inventory']
    assert service.observe(packet(**{field: value})) is None
    assert service.devices(100, 0)['total'] == 0


def test_time_bounds_and_multiple_mac_claims(inventory_app):
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    service.observe(packet())
    service.observe(packet(2, timestamp='2023-11-14T22:13:19Z'))
    service.observe(packet(3, timestamp='2023-11-14T22:13:25Z'))
    service.observe(packet(4, senderMac='02:00:00:00:00:02'))
    rows = client.get('/api/devices').json['items']
    assert len(rows) == 2
    same = next(row for row in rows if row['mac'] == '02:aa:00:00:00:01')
    assert same['observationCount'] == 3
    assert same['firstSeen'] == '2023-11-14T22:13:19.000000+00:00'
    assert same['lastSeen'] == '2023-11-14T22:13:25.000000+00:00'
    evidence = client.get('/api/mapping-conflicts').json['items'][0]
    assert evidence['classification'] == 'unclassified'
    assert evidence['reasons'] == ['multiple_observed_macs']
    assert len(evidence['observedMappings']) == 2
    assert client.get('/api/alerts').json['items'] == []


def test_create_verify_update_revoke_and_audit(inventory_app):
    client = inventory_app.test_client(); inventory_app.extensions['inventory'].observe(packet())
    response = create(client); assert response.status_code == 201
    mapping = response.json
    assert mapping['state'] == 'pending' and mapping['source'] == 'live'
    assert not client.get('/api/devices').json['items'][0]['trusted']
    verified = verify(client, mapping).json
    assert verified['state'] == 'verified' and verified['version'] == 2
    assert client.get('/api/devices').json['items'][0]['trusted']
    url = '/api/trusted-mappings/' + mapping['id']
    assert client.get(url).json == verified
    changed = client.patch(url, json={'mac': '02:00:00:00:00:02', 'version': 2, 'reason': 'Hardware replaced'}, headers=HEADERS)
    assert changed.status_code == 200 and changed.json['state'] == 'pending'
    assert changed.json['verifiedAt'] is None
    assert not client.get('/api/devices').json['items'][0]['trusted']
    revoked = client.delete(url, json={'version': 3, 'reason': 'No longer approved'}, headers=HEADERS)
    assert revoked.status_code == 200 and revoked.json['state'] == 'revoked'
    history = client.get(url + '/audit').json['items']
    assert [row['action'] for row in history] == ['revoke', 'update', 'verify', 'create']
    assert all(row['actor'] == 'test-admin' and row['reason'] and row['timestamp'] for row in history)
    assert history[-1]['before'] is None
    assert history[0]['before']['state'] == 'pending' and history[0]['after']['state'] == 'revoked'
    assert client.get(url + '/audit?limit=1&offset=1').json['total'] == 4


def test_revoke_idempotent_and_reactivation_explicit(inventory_app):
    client = inventory_app.test_client(); mapping = verify(client, create(client).json).json
    url = '/api/trusted-mappings/' + mapping['id']
    revoked = client.delete(url, json={'version': 2, 'reason': 'Retired'}, headers=HEADERS).json
    assert client.delete(url, json={'version': 3, 'reason': 'Retired'}, headers=HEADERS).json == revoked
    assert verify(client, revoked).status_code == 409
    updated = client.patch(url, json={'version': 3, 'label': 'Reapproved', 'reason': 'Reviewed again'}, headers=HEADERS).json
    assert updated['state'] == 'pending'
    assert verify(client, updated).json['state'] == 'verified'
    assert client.get(url + '/audit').json['total'] == 5


def test_uniqueness_and_optimistic_concurrency(inventory_app):
    client = inventory_app.test_client(); mapping = create(client).json
    assert create(client, mac='02AA00000001').status_code == 409
    assert create(client, mac='02:00:00:00:00:02').status_code == 201
    assert create(client, interface='en1').status_code == 201
    verified = verify(client, mapping)
    assert verified.status_code == 200
    assert verify(client, mapping).status_code == 409
    url = '/api/trusted-mappings/' + mapping['id']
    assert client.patch(url, json={'version': 1, 'label': 'stale', 'reason': 'bad'}, headers=HEADERS).status_code == 409
    assert client.get(url + '/audit').json['total'] == 2


@pytest.mark.parametrize('fields', [{'ip': 'bad'}, {'ip': '0.0.0.0'}, {'mac': 'ff:ff:ff:ff:ff:ff'}, {'interface': 'missing'}, {'reason': ''}, {'label': 3}, {'label': 'x'*121}, {'source': 'offline'}, {'trusted': True}, {'actor': 'someone-else'}, {'observationId': 'replay-record'}])
def test_invalid_trust_body(inventory_app, fields):
    client = inventory_app.test_client()
    assert create(client, **fields).status_code == 400
    assert client.get('/api/trusted-mappings').json['total'] == 0


@pytest.mark.parametrize('headers', [{}, {'Authorization': 'Bearer incorrect'}, {'Authorization': TOKEN}])
def test_admin_authentication(inventory_app, headers):
    client = inventory_app.test_client()
    response = client.post('/api/trusted-mappings', json={}, headers=headers)
    assert response.status_code == 401
    assert TOKEN not in response.text


def test_admin_not_configured_and_foreign_origin(inventory_app):
    client = inventory_app.test_client()
    response = client.post('/api/trusted-mappings', json={}, headers={**HEADERS, 'Origin': 'https://example.com'})
    assert response.status_code == 403
    inventory_app.config['ADMIN_TOKEN'] = ''
    assert create(client).status_code == 503


def test_missing_mapping_invalid_version_and_queries(inventory_app):
    client = inventory_app.test_client()
    assert client.get('/api/trusted-mappings/missing').status_code == 404
    assert client.get('/api/trusted-mappings/missing/audit').status_code == 404
    mapping = create(client).json; url = '/api/trusted-mappings/' + mapping['id']
    for version in (0, True, '1', None):
        assert client.post(url + '/verify', json={'version': version, 'reason': 'test'}, headers=HEADERS).status_code == 400
    for path in ('trusted-mappings', 'mapping-conflicts', 'devices'):
        for query in ('limit=0', 'limit=501', 'offset=-1', 'unknown=1', 'limit=1&limit=2'):
            assert client.get('/api/' + path + '?' + query).status_code == 400


def test_replay_and_interface_isolation(inventory_app):
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    trusted = verify(client, create(client).json).json
    service.observe(packet())
    service.observe(packet(2, interface='en1', senderMac='02:00:00:00:00:02'))
    service.observe(packet(3, source='offline', interface=None, sessionId='replay-a'))
    service.observe(packet(4, source='offline', interface=None, sessionId='replay-b', senderMac='02:00:00:00:00:02'))
    rows = client.get('/api/devices').json['items']
    assert len(rows) == 4 and sum(row['trusted'] for row in rows) == 1
    assert all(not row['trusted'] for row in rows if row['source'] == 'offline')
    assert client.get('/api/mapping-conflicts').json['items'] == []
    assert client.get('/api/trusted-mappings/' + trusted['id']).json == trusted
    assert client.get('/api/trusted-mappings/' + trusted['id'] + '/audit').json['total'] == 2


def test_trust_conflict_evidence_and_revoke(inventory_app):
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    mapping = verify(client, create(client, mac='02:00:00:00:00:02').json).json
    service.observe(packet())
    evidence = client.get('/api/mapping-conflicts').json['items'][0]
    assert evidence['reasons'] == ['differs_from_verified_mapping']
    assert evidence['trustedMappings'][0]['id'] == mapping['id']
    client.delete('/api/trusted-mappings/' + mapping['id'], json={'version': 2, 'reason': 'Retired'}, headers=HEADERS)
    assert client.get('/api/mapping-conflicts').json['items'] == []


def test_multiple_verified_macs_do_not_make_false_mismatch(inventory_app):
    client = inventory_app.test_client(); service = inventory_app.extensions['inventory']
    verify(client, create(client).json); verify(client, create(client, mac='02:00:00:00:00:02').json)
    service.observe(packet())
    assert client.get('/api/mapping-conflicts').json['total'] == 0


def test_concurrent_observations_and_id_reuse(inventory_app):
    service = inventory_app.extensions['inventory']
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: service.observe(packet(index)), list(range(50)) * 2))
    assert service.devices(100, 0)['items'][0]['observationCount'] == 50
    with pytest.raises(APIError) as error:
        service.observe(packet(1, senderMac='02:00:00:00:00:02'))
    assert error.value.code == 'observation_id_conflict'


def test_persistence_and_schema_constraints(tmp_path, monkeypatch):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [(1, 'en0')])
    settings = {'TESTING': True, 'DATABASE_URL': 'sqlite:///' + str(tmp_path / 'inventory.db'), 'ADMIN_TOKEN': TOKEN}
    first = create_app(settings)
    first.extensions['inventory'].observe(packet())
    mapping = verify(first.test_client(), create(first.test_client()).json).json
    first.extensions['database'].engine.dispose()
    second = create_app(settings)
    try:
        second.extensions['inventory'].observe(packet())
        assert second.test_client().get('/api/devices').json['items'][0]['observationCount'] == 1
        assert second.test_client().get('/api/trusted-mappings/' + mapping['id']).json['state'] == 'verified'
        assert second.test_client().get('/api/trusted-mappings/' + mapping['id'] + '/audit').json['total'] == 2
        schema = inspect(second.extensions['database'].engine)
        assert any(item['name'] == 'uq_observed_scope_pair' for item in schema.get_unique_constraints('observed_mappings'))
        assert any(item['name'] == 'ix_observed_scope_ip' for item in schema.get_indexes('observed_mappings'))
    finally:
        second.extensions['database'].engine.dispose()


def test_database_failure_does_not_claim_discovery_or_stop_capture(inventory_app, monkeypatch):
    service = inventory_app.extensions['inventory']; database = inventory_app.extensions['database']
    socket = inventory_app.extensions['socketio'].test_client(inventory_app)
    def fail(*_): raise OperationalError('SELECT', {}, RuntimeError('secret path'))
    monkeypatch.setattr(database, 'initialize', fail)
    service.ingest(packet())
    events = socket.get_received()
    assert [item['name'] for item in events] == ['discovery_status']
    assert events[0]['args'][0]['status']['failedObservations'] == 1
    assert 'secret' not in str(events)
    response = inventory_app.test_client().get('/api/devices')
    assert response.status_code == 503 and response.json['error']['code'] == 'database_unavailable'
    socket.disconnect()


def test_audit_failure_rolls_back_trust(inventory_app):
    database = inventory_app.extensions['database']; client = inventory_app.test_client()
    def fail_audit(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO trust_audit'):
            raise OperationalError(statement, {}, RuntimeError('audit store failed'))
    event.listen(database.engine, 'before_cursor_execute', fail_audit)
    try:
        assert create(client).status_code == 503
    finally:
        event.remove(database.engine, 'before_cursor_execute', fail_audit)
    assert client.get('/api/trusted-mappings').json['total'] == 0
    with database.transaction() as session:
        assert session.scalars(select(TrustAudit)).all() == []


def test_device_and_trust_websocket_events(inventory_app):
    socket = inventory_app.extensions['socketio'].test_client(inventory_app)
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    service.observe(packet()); service.observe(packet()); service.observe(packet(2))
    mapping = create(client).json; verify(client, mapping)
    events = socket.get_received()
    assert [event['name'] for event in events] == ['device_discovered', 'device_updated', 'trusted_mapping_updated', 'trusted_mapping_updated']
    assert events[0]['args'][0]['version'] == 1
    assert events[1]['args'][0]['device']['observationCount'] == 2
    assert events[-1]['args'][0]['mapping']['state'] == 'verified'
    assert TOKEN not in str(events)
    socket.disconnect()


def test_controlled_pcap_inventory(inventory_app):
    client = inventory_app.test_client()
    fixture = Path(__file__).parent / 'fixtures' / 'offline-arp.pcap'
    socket = inventory_app.extensions['socketio'].test_client(inventory_app)
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(fixture.read_bytes()), 'fixture.pcap')})
    assert response.status_code == 200
    deadline = time.monotonic() + 2
    while client.get('/api/monitor/status').json['state'] != 'completed':
        assert time.monotonic() < deadline
        time.sleep(0.005)
    devices = client.get('/api/devices').json['items']
    assert len(devices) == 2
    assert {row['ip'] for row in devices} == {'192.0.2.1', '192.0.2.2'}
    assert all(row['source'] == 'offline' and row['interface'] is None and not row['trusted'] for row in devices)
    assert all(row['observationCount'] == 1 for row in devices)
    assert client.get('/api/trusted-mappings').json['total'] == 0
    assert len([event for event in socket.get_received() if event['name'] == 'device_discovered']) == 2
    socket.disconnect()


def test_source_search_trust_and_state_filters(inventory_app):
    service = inventory_app.extensions['inventory']; client = inventory_app.test_client()
    mapping = verify(client, create(client).json).json
    service.observe(packet())
    service.observe(packet(2, source='offline', interface=None, sessionId='replay'))
    assert client.get('/api/devices?source=live').json['total'] == 1
    assert client.get('/api/devices?source=offline').json['items'][0]['source'] == 'offline'
    assert client.get('/api/devices?trusted=true').json['total'] == 1
    assert client.get('/api/devices?source=offline&trusted=true').json['total'] == 0
    assert client.get('/api/devices?q=02:AA').json['total'] == 2
    assert client.get('/api/devices?q=%25').json['total'] == 0
    assert client.get('/api/trusted-mappings?state=verified').json['items'][0]['id'] == mapping['id']
    assert client.get('/api/trusted-mappings?state=pending').json['total'] == 0
    for query in ('source=demo', 'trusted=1', 'q=' + 'a'*121):
        assert client.get('/api/devices?' + query).status_code == 400
    assert client.get('/api/trusted-mappings?state=bad').status_code == 400


def test_readonly_observations_and_mutation_cors(inventory_app):
    client = inventory_app.test_client()
    assert client.post('/api/devices', json=packet(), headers=HEADERS).status_code == 405
    mapping = create(client).json
    url = '/api/trusted-mappings/' + mapping['id']
    for method in ('patch', 'delete'):
        assert getattr(client, method)(url, json={'version': 1, 'reason': 'test'}, headers={**HEADERS, 'Origin': 'https://example.com'}).status_code == 403
        assert getattr(client, method)(url, json={'version': 1, 'reason': 'test'}).status_code == 401
    response = client.options(url, headers={'Origin': 'http://127.0.0.1:5173', 'Access-Control-Request-Method': 'PATCH', 'Access-Control-Request-Headers': 'Authorization, Content-Type'})
    assert 'PATCH' in response.headers['Access-Control-Allow-Methods']
    assert 'Authorization' in response.headers['Access-Control-Allow-Headers']


def test_observation_receipt_failure_rolls_back_counts(inventory_app):
    service = inventory_app.extensions['inventory']; database = inventory_app.extensions['database']
    service.observe(packet())
    def fail_receipt(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO observation_receipts'):
            raise OperationalError(statement, {}, RuntimeError('receipt store failed'))
    event.listen(database.engine, 'before_cursor_execute', fail_receipt)
    try:
        with pytest.raises(APIError): service.observe(packet(2))
    finally:
        event.remove(database.engine, 'before_cursor_execute', fail_receipt)
    assert service.devices(100, 0)['items'][0]['observationCount'] == 1
    with database.transaction() as session:
        assert len(session.scalars(select(ObservationReceipt)).all()) == 1


def test_file_database_concurrent_connections(tmp_path):
    settings = {'TESTING': True, 'DATABASE_URL': 'sqlite:///' + str(tmp_path / 'concurrent.sqlite3')}
    apps = [create_app(settings), create_app(settings)]
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda index: apps[index % 2].extensions['inventory'].observe(packet(index)), list(range(60)) * 2))
        assert apps[0].extensions['inventory'].devices(100, 0)['items'][0]['observationCount'] == 60
    finally:
        for app in apps: app.extensions['database'].engine.dispose()


def test_failed_database_does_not_abort_replay(inventory_app, monkeypatch):
    def fail(*_): raise OperationalError('SELECT', {}, RuntimeError('database offline'))
    monkeypatch.setattr(inventory_app.extensions['database'], 'initialize', fail)
    client = inventory_app.test_client()
    fixture = Path(__file__).parent / 'fixtures' / 'offline-arp.pcap'
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(fixture.read_bytes()), 'test.pcap')})
    assert response.status_code == 200
    deadline = time.monotonic() + 2
    while client.get('/api/monitor/status').json['state'] != 'completed':
        assert time.monotonic() < deadline
        time.sleep(0.005)
    assert client.get('/api/packets').json['total'] == 2
    status = inventory_app.extensions['inventory'].status(check=False)
    assert status['state'] == 'degraded' and status['failedObservations'] == 2


def test_unavailable_database_startup_returns_json(tmp_path):
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite:///' + str(tmp_path / 'missing-folder' / 'db.sqlite3')})
    try:
        client = app.test_client()
        assert client.get('/api/health').status_code == 200
        response = client.get('/api/devices')
        assert response.status_code == 503 and response.json['error']['code'] == 'database_unavailable'
    finally:
        app.extensions['database'].engine.dispose()


def test_offline_conflict_has_no_live_trust_comparison(inventory_app):
    client = inventory_app.test_client(); service = inventory_app.extensions['inventory']
    verified = verify(client, create(client).json).json
    service.observe(packet(1, source='offline', interface=None, sessionId='replay-conflict'))
    service.observe(packet(2, source='offline', interface=None, sessionId='replay-conflict', senderMac='02:00:00:00:00:02'))
    evidence = client.get('/api/mapping-conflicts').json['items']
    assert len(evidence) == 1 and evidence[0]['source'] == 'offline'
    assert evidence[0]['classification'] == 'unclassified'
    assert evidence[0]['reasons'] == ['multiple_observed_macs']
    assert evidence[0]['trustedMappings'] == []
    assert client.get('/api/trusted-mappings/' + verified['id']).json == verified


def test_database_failure_recovery_keeps_incompleteness_visible(inventory_app, monkeypatch):
    service = inventory_app.extensions['inventory']; database = inventory_app.extensions['database']
    initialize = database.initialize
    def fail(): raise OperationalError('SELECT', {}, RuntimeError('temporarily unavailable'))
    monkeypatch.setattr(database, 'initialize', fail)
    service.ingest(packet())
    monkeypatch.setattr(database, 'initialize', initialize)
    service.ingest(packet(2))
    assert service.devices(100, 0)['items'][0]['observationCount'] == 1
    assert service.status()['state'] == 'degraded'
    assert service.status()['failedObservations'] == 1
    # Explicit redelivery after recovery is accepted exactly once.
    service.observe(packet()); service.observe(packet())
    assert service.devices(100, 0)['items'][0]['observationCount'] == 2


def test_reconnect_snapshot_and_duplicate_packet_do_not_double_count(inventory_app):
    socketio = inventory_app.extensions['socketio']; service = inventory_app.extensions['inventory']
    socket = socketio.test_client(inventory_app)
    service.observe(packet())
    assert socket.get_received()[0]['name'] == 'device_discovered'
    socket.disconnect()
    service.observe(packet(2))
    socket = socketio.test_client(inventory_app)
    assert socket.get_received() == []
    assert inventory_app.test_client().get('/api/devices').json['items'][0]['observationCount'] == 2
    service.observe(packet(2))
    assert socket.get_received() == []
    service.observe(packet(3))
    event = socket.get_received()[0]
    assert event['name'] == 'device_updated' and event['args'][0]['device']['observationCount'] == 3
    socket.disconnect()
