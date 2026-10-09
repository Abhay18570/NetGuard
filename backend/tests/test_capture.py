from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
from threading import Event, Thread
import struct
import time
import pytest
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP
from backend.app import create_app
from backend.capture.engine import ScapyCapture
from backend.capture.packets import PacketBuffer, parse_arp
from backend.capture.pcap import read_pcap
from backend.errors import APIError
from backend.services.monitor import MonitorService

FIXTURE = Path(__file__).parent / 'fixtures' / 'offline-arp.pcap'


def arp(operation=1):
    packet = Ether(src='02:00:00:00:00:01', dst='ff:ff:ff:ff:ff:ff') / ARP(
        op=operation, psrc='192.0.2.1', pdst='192.0.2.2',
        hwsrc='02:00:00:00:00:01', hwdst='00:00:00:00:00:00')
    packet.time = 1700000000.125
    return packet


def until(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        if time.monotonic() >= deadline:
            pytest.fail('Worker did not reach expected state')
        time.sleep(0.005)


class ControlledCapture:
    def __init__(self):
        self.opened = Event()
        self.fail = Event()
        self.receive = None
        self.interface = None

    def run(self, interface, stop, ready, receive):
        self.interface, self.receive = interface, receive
        ready()
        self.opened.set()
        while not stop.wait(0.005):
            if self.fail.is_set():
                raise OSError('private capture failure')


@pytest.fixture
def live_app(monkeypatch):
    capture = ControlledCapture()
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [(1, 'en0')])
    app = create_app({'TESTING': True, 'CAPTURE_ENGINE_FACTORY': lambda: capture,
                      'REPLAY_INTERVAL': 0.002, 'PACKET_BUFFER_CAPACITY': 3})
    yield app, capture
    app.extensions['monitor'].stop()


@pytest.mark.parametrize('operation,expected', [(1, 'Request'), (2, 'Reply')])
def test_parse_arp(operation, expected):
    packet = parse_arp(arp(operation), 'en0', 'live')
    assert packet == {'timestamp': '2023-11-14T22:13:20.125000+00:00',
                      'interface': 'en0', 'source': 'live', 'operation': expected,
                      'senderIp': '192.0.2.1', 'targetIp': '192.0.2.2',
                      'senderMac': '02:00:00:00:00:01', 'targetMac': '00:00:00:00:00:00',
                      'status': 'Not analyzed'}


@pytest.mark.parametrize('packet', [None, Ether() / IP(), arp(3), Ether(b'\x00' * 14)])
def test_non_arp_and_unsupported_ignored(packet):
    assert parse_arp(packet, 'en0', 'live') is None


@pytest.mark.parametrize('timestamp', [-1, float('nan'), float('inf'), 1e100])
def test_bad_timestamp_ignored(timestamp):
    packet = arp(); packet.time = timestamp
    assert parse_arp(packet, 'en0', 'live') is None


def test_invalid_arp_address_ignored():
    packet = arp(); packet[ARP].hwsrc = 'invalid'
    assert parse_arp(packet, 'en0', 'live') is None


def test_bounded_thread_safe_buffer():
    buffer = PacketBuffer(30)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: buffer.append({'id': str(index)}), range(500)))
    page = buffer.page(10, 5)
    assert page['total'] == 30 and len(page['items']) == 10
    assert len({item['id'] for item in buffer.page()['items']}) == 30
    page['items'][0]['id'] = 'mutated'
    assert all(item['id'] != 'mutated' for item in buffer.page()['items'])
    buffer.clear()
    assert buffer.page()['total'] == 0


def test_buffer_order():
    buffer = PacketBuffer(2)
    for index in range(3):
        buffer.append({'id': str(index)})
    assert [row['id'] for row in buffer.page()['items']] == ['2', '1']
    assert buffer.page(1, 1)['items'] == [{'id': '1'}]


def test_live_start_stop_packets_and_socket_contract(live_app):
    app, capture = live_app
    client = app.test_client()
    socket = app.extensions['socketio'].test_client(app)
    response = client.post('/api/monitor/start', json={'interface': 'en0'})
    assert response.status_code == 200
    status = response.json
    assert status['state'] == 'running' and status['mode'] == 'live'
    assert status['interface'] == capture.interface == 'en0'
    assert status['startedAt'] and status['sessionId']
    for operation in [1, 2, 1, 2]:
        capture.receive(arp(operation))
    response = client.get('/api/packets?limit=2&offset=1')
    assert response.json['total'] == 3
    assert [packet['sequence'] for packet in response.json['items']] == [3, 2]
    messages = socket.get_received()
    states = [event['args'][0]['status']['state'] for event in messages if event['name'] == 'monitor_status']
    assert states == ['starting', 'running']
    packet_events = [event['args'][0] for event in messages if event['name'] == 'arp_packet']
    assert len(packet_events) == 4
    for index, event in enumerate(packet_events, 1):
        assert set(event) == {'version', 'packet'} and event['version'] == 1
        assert event['packet']['source'] == 'live'
        assert event['packet']['sessionId'] == status['sessionId']
        assert event['packet']['sequence'] == index
        assert event['packet']['status'] == 'Not analyzed'
    assert client.post('/api/monitor/stop', json={}).json['state'] == 'stopped'
    assert client.post('/api/monitor/stop', json={}).json['state'] == 'stopped'
    capture.receive(arp())
    assert client.get('/api/packets').json['total'] == 3
    assert client.get('/api/devices').json['total'] == 1
    assert client.get('/api/devices').json['items'][0]['observationCount'] == 4
    for resource in ('alerts', 'incidents'):
        assert client.get('/api/' + resource).json['items'] == []
    socket.disconnect()


def test_one_session_and_new_session_clears_buffer(live_app):
    app, capture = live_app
    client = app.test_client()
    first = client.post('/api/monitor/start', json={'interface': 'en0'}).json
    capture.receive(arp())
    assert client.post('/api/monitor/start', json={'interface': 'en0'}).status_code == 409
    replay = client.post('/api/monitor/replay', data={'file': (BytesIO(FIXTURE.read_bytes()), 'test.pcap')})
    assert replay.status_code == 409
    assert client.get('/api/packets').json['total'] == 1
    client.post('/api/monitor/stop', json={})
    second = client.post('/api/monitor/start', json={'interface': 'en0'}).json
    assert second['sessionId'] != first['sessionId']
    assert client.get('/api/packets').json['items'] == []


def test_unexpected_failure_transitions_and_emits(live_app):
    app, capture = live_app
    socket = app.extensions['socketio'].test_client(app)
    client = app.test_client()
    client.post('/api/monitor/start', json={'interface': 'en0'})
    capture.fail.set()
    until(lambda: client.get('/api/monitor/status').json['state'] == 'error')
    status = client.get('/api/monitor/status').json
    assert status['error']['code'] == 'capture_failed'
    assert 'private' not in status['reason']
    assert any(event['name'] == 'monitor_status' and event['args'][0]['status']['state'] == 'error'
               for event in socket.get_received())
    socket.disconnect()


@pytest.mark.parametrize('error,code,http', [
    (PermissionError('denied'), 'capture_permission_denied', 403),
    (RuntimeError('Permission denied: could not open /dev/bpf0'), 'capture_permission_denied', 403),
    (ImportError('missing'), 'capture_unavailable', 501),
    (OSError('unexpected'), 'capture_failed', 503),
])
def test_open_failure_never_active(monkeypatch, error, code, http):
    class FailedCapture:
        def run(self, *_):
            raise error
    monkeypatch.setattr('backend.discovery.interfaces.socket.if_nameindex', lambda: [(1, 'en0')])
    app = create_app({'TESTING': True, 'CAPTURE_ENGINE_FACTORY': FailedCapture})
    client = app.test_client()
    socket = app.extensions['socketio'].test_client(app)
    response = client.post('/api/monitor/start', json={'interface': 'en0'})
    assert response.status_code == http and response.json['error']['code'] == code
    status = client.get('/api/monitor/status').json
    assert status['state'] == 'error' and status['startedAt'] is None
    assert all(event['args'][0]['status']['state'] != 'running' for event in socket.get_received())
    socket.disconnect()


def test_slow_open_stop_and_single_owner():
    release = Event()
    class SlowCapture:
        def run(self, interface, stop, ready, receive):
            release.wait(2)
            ready()
            stop.wait(2)
    monitor = MonitorService(engine_factory=SlowCapture, start_timeout=0.005, stop_timeout=0.005)
    try:
        assert monitor.start('en0')['state'] == 'starting'
        assert monitor.stop()['state'] == 'stopping'
        with pytest.raises(APIError) as error:
            monitor.start('en0')
        assert error.value.status == 409
        release.set()
        until(lambda: monitor.status()['state'] == 'stopped')
        assert monitor.status()['startedAt'] is None
    finally:
        release.set(); monitor.stop()


def test_competing_starts():
    capture = ControlledCapture()
    monitor = MonitorService(engine_factory=lambda: capture)
    def start():
        try:
            return monitor.start('en0')['state']
        except APIError as error:
            return error.code
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: start(), range(4)))
        assert outcomes.count('running') == 1
        assert outcomes.count('monitor_busy') == 3
    finally:
        monitor.stop()


def test_engine_opens_only_selected_interface_without_promisc(monkeypatch):
    from scapy.all import conf
    stop = Event(); ready = Event(); observed = []; parameters = []
    class Socket:
        closed = False
        def select(self, sockets, timeout):
            assert sockets == [self] and timeout == 0.2
            return sockets
        def recv(self):
            return arp()
        def close(self):
            self.closed = True
    socket = Socket()
    def open_socket(**kwargs):
        parameters.append(kwargs)
        return socket
    monkeypatch.setattr(conf, 'L2listen', open_socket)
    def receive(packet):
        observed.append(packet)
        stop.set()
    ScapyCapture().run('en0', stop, ready.set, receive)
    assert parameters == [{'iface': 'en0', 'filter': 'arp', 'promisc': False, 'monitor': False}]
    assert ready.is_set() and len(observed) == 1 and socket.closed


def test_engine_closes_on_receive_failure(monkeypatch):
    from scapy.all import conf
    closed = Event()
    class Socket:
        def select(self, *_): return [self]
        def recv(self): raise OSError('disconnected')
        def close(self): closed.set()
    monkeypatch.setattr(conf, 'L2listen', lambda **_: Socket())
    with pytest.raises(OSError):
        ScapyCapture().run('en0', Event(), lambda: None, lambda _: None)
    assert closed.is_set()


def test_missing_dependency_capability(monkeypatch):
    monkeypatch.setattr('backend.capture.engine.find_spec', lambda _: None)
    assert MonitorService().status()['captureAvailable'] is False


def test_valid_pcap_and_replay_contract(live_app):
    app, _ = live_app
    parsed = read_pcap(FIXTURE.read_bytes())
    assert [packet['operation'] for packet in parsed] == ['Request', 'Reply']
    assert all(packet['source'] == 'offline' and packet['interface'] is None for packet in parsed)
    socket = app.extensions['socketio'].test_client(app)
    client = app.test_client()
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(FIXTURE.read_bytes()), 'example.pcap')})
    assert response.status_code == 200
    until(lambda: client.get('/api/monitor/status').json['state'] == 'completed')
    status = client.get('/api/monitor/status').json
    assert status['mode'] == 'offline' and status['interface'] is None
    packets = client.get('/api/packets').json['items']
    assert len(packets) == 2 and all(row['source'] == 'offline' for row in packets)
    assert packets[-1]['timestamp'] == '2023-11-14T22:13:20.123456+00:00'
    messages = socket.get_received()
    assert len([event for event in messages if event['name'] == 'arp_packet']) == 2
    assert messages[-1]['args'][0]['status']['state'] == 'completed'
    socket.disconnect()


@pytest.mark.parametrize('data', [b'', b'not pcap', b'\x0a\x0d\x0d\x0a' + b'\x00' * 40,
                                 FIXTURE.read_bytes()[:-1], FIXTURE.read_bytes() + b'bad',
                                 (FIXTURE.parent / 'truncated.pcap').read_bytes()])
def test_bad_pcaps_rejected_without_session(live_app, data):
    app, _ = live_app; client = app.test_client()
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(data), 'test.pcap')})
    assert response.status_code == 400
    assert response.json['error']['code'] == 'invalid_pcap'
    assert client.get('/api/monitor/status').json['state'] == 'not_started'
    assert client.get('/api/packets').json['items'] == []


@pytest.mark.parametrize('offset,replacement', [(20, struct.pack('<I', 999)),
                                               (32, struct.pack('<I', 99999)),
                                               (28, struct.pack('<I', 1000000))])
def test_pcap_header_validation(offset, replacement):
    data = bytearray(FIXTURE.read_bytes()); data[offset:offset + 4] = replacement
    with pytest.raises(APIError): read_pcap(bytes(data))


def test_pcap_size_and_record_limits(live_app):
    app, _ = live_app; client = app.test_client()
    app.config['PCAP_MAX_BYTES'] = 50
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(FIXTURE.read_bytes()), 'test.pcap')})
    assert response.status_code == 413
    with pytest.raises(APIError) as error:
        read_pcap(FIXTURE.read_bytes(), max_records=1)
    assert error.value.code == 'pcap_too_many_records'


def test_replay_payload_limit(live_app):
    app, _ = live_app; app.config['PCAP_MAX_BYTES'] = 10
    response = app.test_client().post('/api/monitor/replay', data={'file': (BytesIO(b'x' * 70000), 'test.pcap')})
    assert response.status_code == 413 and response.is_json


def test_pcap_with_no_arp():
    with pytest.raises(APIError) as error:
        read_pcap(FIXTURE.read_bytes()[:24])
    assert error.value.status == 422 and error.value.code == 'no_arp_packets'


@pytest.mark.parametrize('data,content_type', [({}, None), ({'file': (BytesIO(b'bad'), 'test.txt')}, None),
                                              ({'extra': 'x'}, None), ('{}', 'application/json')])
def test_invalid_upload(live_app, data, content_type):
    app, _ = live_app
    response = app.test_client().post('/api/monitor/replay', data=data, content_type=content_type)
    assert response.status_code in (400, 415) and response.is_json


def test_replay_can_be_stopped():
    monitor = MonitorService(replay_interval=1)
    try:
        monitor.replay(read_pcap(FIXTURE.read_bytes()))
        assert monitor.stop()['state'] == 'stopped'
        assert monitor.buffer.page()['items'] == []
    finally:
        monitor.stop()


def test_foreign_origin_cannot_start_or_import(live_app):
    app, _ = live_app
    response = app.test_client().post('/api/monitor/start', json={'interface': 'en0'}, headers={'Origin': 'https://example.com'})
    assert response.status_code == 403 and response.json['error']['code'] == 'origin_not_allowed'
    response = app.test_client().post('/api/monitor/replay', data={'file': (BytesIO(FIXTURE.read_bytes()), 'test.pcap')}, headers={'Origin': 'null'})
    assert response.status_code == 403
    assert app.extensions['monitor'].status()['state'] == 'not_started'


def test_allowed_origin_can_start(live_app):
    app, _ = live_app
    response = app.test_client().post('/api/monitor/start', json={'interface': 'en0'}, headers={'Origin': 'http://127.0.0.1:5173'})
    assert response.status_code == 200


def test_socket_read_error_returning_none_is_failure(monkeypatch):
    from scapy.all import conf
    closed = Event()
    class Socket:
        def select(self, *_): return [self]
        def recv(self): return None
        def close(self): closed.set()
    monkeypatch.setattr(conf, 'L2listen', lambda **_: Socket())
    monitor = MonitorService()
    try:
        try:
            monitor.start('en0')
        except APIError:
            pass
        until(lambda: monitor.status()['state'] == 'error')
        assert closed.is_set()
    finally:
        monitor.stop()


def test_capture_return_without_stop_is_failure():
    class ReturnsEarly:
        def run(self, interface, stop, ready, receive):
            ready()
    monitor = MonitorService(engine_factory=ReturnsEarly)
    try:
        try: monitor.start('en0')
        except APIError: pass
        until(lambda: monitor.status()['state'] == 'error')
        assert monitor.status()['error']['code'] == 'capture_failed'
    finally: monitor.stop()


@pytest.mark.parametrize('endian,precision,magic', [('<', 1000000000, b'\x4d\x3c\xb2\xa1'),
                                                  ('>', 1000000, b'\xa1\xb2\xc3\xd4'),
                                                  ('>', 1000000000, b'\xa1\xb2\x3c\x4d')])
def test_pcap_endian_and_precision(endian, precision, magic):
    raw = bytes(arp())
    data = magic + struct.pack(endian + 'HHiIII', 2, 4, 0, 0, 65535, 1)
    data += struct.pack(endian + 'IIII', 1700000000, precision // 2, len(raw), len(raw)) + raw
    parsed = read_pcap(data)
    assert parsed[0]['timestamp'] == '2023-11-14T22:13:20.500000+00:00'


def test_corrupt_import_does_not_replace_session_buffer(live_app):
    app, capture = live_app; client = app.test_client()
    client.post('/api/monitor/start', json={'interface': 'en0'})
    capture.receive(arp())
    client.post('/api/monitor/stop', json={})
    before = client.get('/api/packets').json
    response = client.post('/api/monitor/replay', data={'file': (BytesIO(b'broken'), 'bad.pcap')})
    assert response.status_code == 400
    assert client.get('/api/packets').json == before


def test_upload_unknown_fields_and_duplicates(live_app):
    from werkzeug.datastructures import MultiDict
    client = live_app[0].test_client()
    for data in [MultiDict([('file', (BytesIO(FIXTURE.read_bytes()), 'a.pcap')), ('file', (BytesIO(FIXTURE.read_bytes()), 'b.pcap'))]),
                 {'file': (BytesIO(FIXTURE.read_bytes()), 'a.pcap'), 'extra': 'no'}]:
        assert client.post('/api/monitor/replay', data=data).status_code == 400
    assert client.post('/api/monitor/replay?unknown=1', data={'file': (BytesIO(FIXTURE.read_bytes()), 'a.pcap')}).status_code == 400


def test_idle_engine_stop_does_not_need_an_arp_packet(monkeypatch):
    from scapy.all import conf
    closed = Event(); opened = Event(); stop = Event()
    class Socket:
        def select(self, *_):
            stop.wait(0.01)
            return []
        def close(self): closed.set()
    monkeypatch.setattr(conf, 'L2listen', lambda **_: Socket())
    worker = Thread(target=ScapyCapture().run, args=('en0', stop, opened.set, lambda _: None))
    worker.start()
    assert opened.wait(1)
    stop.set(); worker.join(1)
    assert not worker.is_alive() and closed.is_set()
