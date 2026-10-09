import pytest
from backend.app import create_app
from backend.discovery.interfaces import discover_interfaces

COLLECTIONS = ('devices', 'packets', 'alerts', 'incidents')


def assert_error(response, status, code):
    assert response.status_code == status
    assert response.content_type == 'application/json'
    assert set(response.json) == {'error'}
    assert response.json['error']['code'] == code
    assert isinstance(response.json['error']['message'], str)
    assert response.json['error']['message']


def test_health(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json == {'status': 'ok', 'service': 'netguard', 'phase': 7}
    assert response.headers['Cache-Control'] == 'no-store'


def test_monitor_initial_status(client):
    response = client.get('/api/monitor/status')
    assert response.status_code == 200
    assert response.json == {
        'state': 'not_started', 'captureAvailable': True, 'interface': None,
        'startedAt': None, 'reason': 'Select a local interface to start passive ARP capture.',
        'mode': None, 'sessionId': None, 'error': None, 'revision': 0, 'bufferCapacity': 1000,
    }


@pytest.mark.parametrize('resource', COLLECTIONS)
def test_empty_collections(client, resource):
    response = client.get(f'/api/{resource}')
    assert response.status_code == 200
    assert response.json == {'items': [], 'total': 0, 'limit': 100, 'offset': 0}
    response = client.get(f'/api/{resource}?limit=20&offset=10')
    assert response.json == {'items': [], 'total': 0, 'limit': 20, 'offset': 10}


@pytest.mark.parametrize('resource', COLLECTIONS)
@pytest.mark.parametrize('query', ['limit=0', 'limit=501', 'limit=-1', 'limit=1.5',
                                   'offset=-1', 'offset=1000001', 'limit=no',
                                   'limit=1&limit=2', 'unknown=1', 'offset=',
                                   'offset=99999999999999999999999'])
def test_collection_validation(client, resource, query):
    assert_error(client.get(f'/api/{resource}?{query}'), 400, 'invalid_query')


def test_interfaces_read_only(client, monkeypatch):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex',
                        lambda: [(2, 'en0'), (1, 'lo0')])
    response = client.get('/api/interfaces')
    assert response.status_code == 200
    assert response.json == {'items': [{'index': 1, 'name': 'lo0'}, {'index': 2, 'name': 'en0'}], 'total': 2}


def test_no_interfaces(client, monkeypatch):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [])
    assert client.get('/api/interfaces').json == {'items': [], 'total': 0}


def test_interface_discovery_failure(client, monkeypatch):
    def fail():
        raise OSError('private OS detail')
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', fail)
    response = client.get('/api/interfaces')
    assert_error(response, 503, 'interface_discovery_failed')
    assert 'private' not in response.text


def test_real_interface_enumeration_shape():
    for interface in discover_interfaces():
        assert isinstance(interface['index'], int)
        assert isinstance(interface['name'], str)


@pytest.mark.parametrize('body', [{}, {'interface': 'en0'}])
def test_start_requires_interface_and_dependencies(client, monkeypatch, body):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [(2, 'en0')])
    response = client.post('/api/monitor/start', json=body)
    assert_error(response, 501 if body else 400, 'capture_unavailable' if body else 'invalid_interface')
    status = client.get('/api/monitor/status').json
    assert status['state'] == ('error' if body else 'not_started')
    assert status['startedAt'] is None
    for resource in COLLECTIONS:
        assert client.get(f'/api/{resource}').json['items'] == []


@pytest.mark.parametrize('interface', [None, '', ' ', 1, True, [], {}, 'x' * 129, 'missing'])
def test_invalid_interface(client, monkeypatch, interface):
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [])
    assert_error(client.post('/api/monitor/start', json={'interface': interface}), 400, 'invalid_interface')


def test_stop_idempotent(client):
    before = client.get('/api/monitor/status').json
    for _ in range(2):
        response = client.post('/api/monitor/stop', json={})
        assert response.status_code == 200
        assert response.json == before


@pytest.mark.parametrize('endpoint', ['start', 'stop'])
@pytest.mark.parametrize('body', [[], 'bad', 5, {'unknown': 'field'}])
def test_invalid_bodies(client, endpoint, body):
    assert_error(client.post(f'/api/monitor/{endpoint}', json=body), 400, 'invalid_body')


@pytest.mark.parametrize('endpoint', ['start', 'stop'])
def test_json_errors(client, endpoint):
    path = f'/api/monitor/{endpoint}'
    assert_error(client.post(path, data='null', content_type='application/json'), 400, 'invalid_body')
    assert_error(client.post(path, data='{', content_type='application/json'), 400, 'bad_request')
    assert_error(client.post(path, data='{}', content_type='text/plain'), 415, 'unsupported_media_type')
    assert_error(client.post(path, data='x' * 17000, content_type='application/json'), 413, 'request_entity_too_large')
    assert_error(client.post(path + '?unexpected=1', json={}), 400, 'invalid_query')


@pytest.mark.parametrize('path', ['health', 'monitor/status', 'interfaces'])
def test_unknown_query(client, path):
    assert_error(client.get(f'/api/{path}?unknown=1'), 400, 'invalid_query')


def test_http_errors(client):
    assert_error(client.get('/api/missing'), 404, 'not_found')
    response = client.post('/api/health')
    assert_error(response, 405, 'method_not_allowed')
    assert 'GET' in response.headers['Allow']


def test_unexpected_error_is_sanitized(app, client, monkeypatch):
    def fail():
        raise RuntimeError('secret detail')
    monkeypatch.setattr(app.extensions['monitor'], 'status', fail)
    response = client.get('/api/monitor/status')
    assert_error(response, 500, 'internal_error')
    assert 'secret' not in response.text


@pytest.mark.parametrize('origin', ['http://localhost:5173', 'http://127.0.0.1:5173'])
def test_allowed_cors(client, origin):
    response = client.get('/api/health', headers={'Origin': origin})
    assert response.headers['Access-Control-Allow-Origin'] == origin
    response = client.options('/api/monitor/start', headers={
        'Origin': origin, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type',
    })
    assert response.status_code == 200
    assert 'POST' in response.headers['Access-Control-Allow-Methods']
    assert response.headers.get('Access-Control-Allow-Credentials') is None


@pytest.mark.parametrize('origin', ['https://example.com', 'http://localhost:9999', 'null'])
def test_disallowed_cors(client, origin):
    response = client.get('/api/health', headers={'Origin': origin})
    assert response.headers.get('Access-Control-Allow-Origin') is None


def test_socketio_no_fabricated_events(app):
    socketio = app.extensions['socketio']
    client = socketio.test_client(app)
    assert client.is_connected()
    assert client.get_received() == []
    client.emit('start_monitoring', {})
    assert client.get_received() == []
    assert app.extensions['monitor'].status()['state'] == 'not_started'
    client.disconnect()


def test_socketio_rejects_foreign_origin(client):
    response = client.get('/socket.io/?EIO=4&transport=polling', headers={'Origin': 'https://example.com'})
    assert response.status_code == 400


def test_factory_isolation(app):
    other = create_app({'TESTING': True})
    assert app.extensions['monitor'] is not other.extensions['monitor']
    assert app.extensions['socketio'] is not other.extensions['socketio']
