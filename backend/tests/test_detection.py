"""Synthetic evidence only: no test opens a capture socket or transmits packets."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
import time
import pytest
from scapy.all import ARP, Ether, wrpcap
from sqlalchemy import select
from backend.app import create_app
from backend.database.models import TrustedMapping, ObservedMapping
from backend.database.store import Database
from backend.detection.service import DetectionService
from backend.detection.rules import Thresholds


def packet(n=1, seconds=0, mac='02:00:00:00:00:01', ip='192.0.2.1', operation='Request', source='offline', session='test', **extra):
    return dict(id=f'{session}:{n}', sessionId=session, sequence=n,
                timestamp=datetime.fromtimestamp(1700000000 + seconds, timezone.utc).isoformat(),
                source=source, interface='en0' if source == 'live' else None,
                senderIp=ip, senderMac=mac, targetIp='192.0.2.2', targetMac='02:00:00:00:00:02',
                operation=operation, status='Not analyzed', **extra)


@pytest.fixture
def service():
    events = []
    service = DetectionService(Database('sqlite://'), lambda *args: events.append(args))
    service.events = events
    yield service
    service.close()


def rules(findings):
    return {x['ruleId'] for x in findings}


def baseline(service, state='verified', mac='02:00:00:00:00:01'):
    with service.database.transaction(write=True) as db:
        db.add(TrustedMapping(id='gateway', ip='192.0.2.1', mac=mac, interface='en0', label='explicit gateway',
                              state=state, created_at='2026-01-01', updated_at='2026-01-01', version=1))
    service.gateway_ids = frozenset({'gateway'})


def test_normal_request_and_reply(service):
    request = packet(); request['targetIp'] = '192.0.2.2'
    service.process(request)
    reply = packet(2, 1, ip='192.0.2.2', mac='02:00:00:00:00:02', operation='Reply')
    reply.update(targetIp=request['senderIp'], targetMac=request['senderMac'])
    assert service.process(reply) == []
    assert service.findings()['total'] == 0


def test_conflict_evidence_and_cooldown(service):
    service.process(packet())
    findings = service.process(packet(2, 1, mac='02:00:00:00:00:03'))
    assert rules(findings) == {'ARP_CLAIM_CONFLICT'}
    item = findings[0]
    assert item['packetIds'] == ['test:1', 'test:2']
    assert item['expectedMac'] == '02:00:00:00:00:01'
    assert item['classification'] == 'suspicious_observation'
    assert item['status'] == 'Unreviewed'
    assert service.process(packet(3, 2, mac='02:00:00:00:00:03')) == []
    assert service.events[0] == ('detection_finding', {'version': 1, 'finding': item})


def test_old_claim_is_not_dhcp_conflict(service):
    service.process(packet())
    assert service.process(packet(2, 61, mac='02:00:00:00:00:03')) == []


def test_verified_replacement(service):
    baseline(service, mac='02:00:00:00:00:03')
    service.process(packet(source='live'))
    assert service.process(packet(2, 1, source='live', mac='02:00:00:00:00:03')) == []


@pytest.mark.parametrize('state,configured,source,expected', [
    ('verified', True, 'live', True), ('pending', True, 'live', False),
    ('revoked', True, 'live', False), ('verified', False, 'live', False),
    ('verified', True, 'offline', False),
])
def test_gateway_requires_explicit_verified_live_baseline(service, state, configured, source, expected):
    baseline(service, state)
    if not configured:
        service.gateway_ids = frozenset()
    findings = service.process(packet(mac='02:00:00:00:00:03', source=source))
    assert ('ARP_GATEWAY_MISMATCH' in rules(findings)) is expected


def test_gateway_repeated_evidence_raises_confidence(service):
    baseline(service)
    first = service.process(packet(source='live', mac='02:00:00:00:00:03'))[0]
    service.process(packet(2, 1, source='live', mac='02:00:00:00:00:03'))
    last = service.process(packet(3, 2, source='live', mac='02:00:00:00:00:03'))[0]
    assert (first['severity'], last['severity'], last['confidence']) == ('Medium', 'High', 'High')


def test_burst_threshold(service):
    for n in range(29):
        assert service.process(packet(n, n / 10, operation='Reply')) == []
    assert 'ARP_REPLY_BURST' in rules(service.process(packet(29, 2.9, operation='Reply')))


def test_unsolicited_warmup_and_missing_evidence(service):
    service.process(packet())
    findings = []
    for n in range(2, 7):
        findings += service.process(packet(n, n + 4, operation='Reply'))
    finding = next(x for x in findings if x['ruleId'] == 'ARP_UNCORRELATED_REPLY')
    assert finding['severity'] == 'Low'
    assert finding['details']['requestEvidence'] == 'not_observed'
    assert 'may have been missed' in finding['reason']


def test_correlated_replies_not_unsolicited(service):
    for n in range(10):
        request = packet(n * 2, n * 2, ip='192.0.2.2', mac='02:00:00:00:00:02')
        request['targetIp'] = '192.0.2.1'
        service.process(request)
        assert service.process(packet(n * 2 + 1, n * 2 + 1, operation='Reply')) == []


def test_gratuitous_context_not_automatically_suspicious(service):
    for n in range(10):
        p = packet(n, n + 10, operation='Reply'); p['targetIp'] = p['senderIp']
        assert service.process(p) == []


def test_duplicate_delivery_idempotent_and_collision_rejected(service):
    service.process(packet())
    p = packet(2, 1, mac='02:00:00:00:00:03')
    service.process(p)
    assert service.process(p) == []
    p['senderMac'] = '02:00:00:00:00:04'
    with pytest.raises(ValueError):
        service.process(p)
    assert service.findings()['total'] == 1


def test_replay_sessions_and_live_are_isolated(service):
    service.process(packet())
    assert service.process(packet(2, 1, mac='02:00:00:00:00:03', session='other')) == []
    assert service.process(packet(3, 2, mac='02:00:00:00:00:03', source='live')) == []


def test_persistence_and_receipts_after_restart(tmp_path):
    url = f'sqlite:///{tmp_path / "test.sqlite"}'
    service = DetectionService(Database(url), lambda *_: None)
    service.process(packet()); p = packet(2, 1, mac='02:00:00:00:00:03'); service.process(p)
    service.close()
    second = DetectionService(Database(url), lambda *_: None)
    assert second.findings()['total'] == 1
    assert second.process(p) == []
    second.close()


def test_concurrent_duplicate_events(service):
    service.process(packet())
    p = packet(2, 1, mac='02:00:00:00:00:03')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(service.process, [p] * 30))
    assert service.findings()['total'] == 1


def test_bounded_history_and_out_of_order(service):
    service.config = Thresholds(history_capacity=30)
    for n in range(100):
        service.process(packet(n, n))
    assert len(next(iter(service.histories.values()))) <= 30
    assert service.process(packet(101, 1, mac='02:00:00:00:00:03')) == []
    assert service.status()['latePackets'] == 1


def test_async_failure_does_not_escape(service, monkeypatch):
    def fail(_):
        raise RuntimeError('controlled database failure')
    monkeypatch.setattr(service, 'process', fail)
    service.enqueue(packet()); service.drain()
    assert service.status()['failedPackets'] == 1
    assert service.status()['state'] == 'degraded'


def test_queue_overflow_is_explicit(service):
    service.queue = __import__('queue').Queue(1)
    service.worker = object()  # Hold processing to deterministically exercise the bound.
    service.enqueue(packet()); service.enqueue(packet(2))
    assert service.status()['droppedPackets'] == 1
    service.queue.get_nowait(); service.queue.task_done()


@pytest.mark.parametrize('config', [{'burst_count': 0}, {'cooldown': True}, {'queue_capacity': -1}, {'history_capacity': 2}, {'unknown': 1}])
def test_invalid_thresholds(config):
    with pytest.raises((ValueError, TypeError)):
        Thresholds(**config)


@pytest.mark.parametrize('query', ['source=bogus', 'severity=Critical', 'limit=0', 'q=' + 'x'*121, 'source=live&source=offline', 'bad=1'])
def test_finding_api_validation(client, query):
    assert client.get('/api/alerts?' + query).status_code == 400


def test_empty_read_only_api(client):
    assert client.get('/api/alerts').json['total'] == 0
    assert client.get('/api/detection/status').json['state'] == 'ready'
    assert client.post('/api/alerts', json={}).status_code == 405
    assert client.post('/api/detection/status', json={}).status_code == 405


def test_controlled_pcap_pipeline_and_reconnect(tmp_path):
    path = tmp_path / 'conflict.pcap'
    packets = []
    for n, mac in enumerate(['02:00:00:00:00:01', '02:00:00:00:00:03']):
        p = Ether(src=mac) / ARP(op=1, psrc='192.0.2.1', hwsrc=mac, pdst='192.0.2.2')
        p.time = 1700000000 + n; packets.append(p)
    wrpcap(str(path), packets)
    app = create_app({'TESTING': True, 'REPLAY_INTERVAL': 0})
    client = app.test_client(); socket = app.extensions['socketio'].test_client(app)
    try:
        response = client.post('/api/monitor/replay', data={'file': (BytesIO(path.read_bytes()), 'test.pcap')})
        assert response.status_code in (200, 202)
        deadline = time.monotonic() + 3
        while app.extensions['monitor'].status()['state'] not in ('completed', 'error') and time.monotonic() < deadline:
            time.sleep(.01)
        app.extensions['detection'].drain()
        app.extensions['incidents'].drain()
        assert app.extensions['monitor'].status()['state'] == 'completed'
        findings = client.get('/api/alerts?source=offline').json
        assert findings['total'] == 1
        assert findings['items'][0]['source'] == 'offline'
        assert any(e['name'] == 'detection_finding' for e in socket.get_received())
        socket.disconnect()
        recovered = app.extensions['socketio'].test_client(app)
        assert recovered.get_received() == []  # No invented events on reconnect; REST restores history.
        assert client.get('/api/alerts').json == findings
        assert client.get('/api/alerts?source=live').json['total'] == 0
        assert client.get('/api/incidents').json['total'] == 1
        assert client.get('/api/devices').json['total'] == 2
        recovered.disconnect()
    finally:
        app.extensions['monitor'].stop(); app.extensions['detection'].close()


def test_additive_schema_preserves_phase4_data(tmp_path):
    url = f'sqlite:///{tmp_path / "old.sqlite"}'
    database = Database(url)
    with database.transaction(write=True) as db:
        db.add(ObservedMapping(id='original', ip='192.0.2.1', mac='02:00:00:00:00:01', source='offline', scope='old', interface=None,
                               first_seen='2026-01-01', last_seen='2026-01-01', observation_count=3, last_session_id='old'))
    # Model an existing Phase 4 database without the two new tables.
    from backend.database.models import DetectionFinding, DetectionReceipt
    DetectionFinding.__table__.drop(database.engine); DetectionReceipt.__table__.drop(database.engine)
    upgraded = Database(url)
    with upgraded.transaction() as db:
        assert db.get(ObservedMapping, 'original').observation_count == 3
        assert list(db.scalars(select(DetectionFinding))) == []


def test_database_failure_rolls_back_temporal_state(service, monkeypatch):
    from contextlib import contextmanager
    service.process(packet())
    original = service.database.transaction
    @contextmanager
    def unavailable(*args, **kwargs):
        raise RuntimeError('controlled persistence failure')
        yield
    monkeypatch.setattr(service.database, 'transaction', unavailable)
    service.enqueue(packet(2, 1, mac='02:00:00:00:00:03')); service.drain()
    assert len(next(iter(service.histories.values()))) == 1
    monkeypatch.setattr(service.database, 'transaction', original)
    assert service.findings()['total'] == 0
    assert len(service.process(packet(2, 1, mac='02:00:00:00:00:03'))) == 1


def test_revoked_gateway_no_longer_used(service):
    baseline(service)
    with service.database.transaction(write=True) as db:
        db.get(TrustedMapping, 'gateway').state = 'revoked'
    assert service.process(packet(source='live', mac='02:00:00:00:00:03')) == []


def test_concurrent_unique_claims_have_one_cooldown_finding(service):
    service.process(packet())
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(service.process, [packet(n, 1, mac='02:00:00:00:00:03') for n in range(2, 42)]))
    assert service.findings()['total'] == 1


def test_arp_probe_ignored_without_failure(service):
    assert service.process(packet(ip='0.0.0.0')) == []
    assert service.status()['state'] == 'ready'


def test_non_arp_packet_is_not_processed_as_an_arp_claim(service):
    tcp_packet = {'id': 'test:tcp:1', 'sessionId': 'test', 'source': 'offline',
                  'interface': None, 'protocol': 'TCP', 'operation': 'Request'}
    assert service.process(tcp_packet) == []
    assert service.status()['state'] == 'ready'


def test_passive_capture_stays_running_when_detector_fails(monkeypatch):
    from threading import Event
    sent = Event()
    class Engine:
        def run(self, interface, stop, ready, receive):
            ready()
            receive(Ether(src='02:00:00:00:00:01') / ARP(psrc='192.0.2.1', hwsrc='02:00:00:00:00:01', pdst='192.0.2.2'))
            sent.set(); stop.wait(3)
    app = create_app({'TESTING': True, 'CAPTURE_ENGINE_FACTORY': Engine})
    detector = app.extensions['detection']; monitor = app.extensions['monitor']
    def failure(_):
        raise RuntimeError('controlled detector failure')
    monkeypatch.setattr(detector, 'process', failure)
    try:
        monitor.start('en0'); assert sent.wait(2); detector.drain()
        assert monitor.status()['state'] == 'running'
        assert monitor.buffer.page()['total'] == 1
        assert detector.status()['failedPackets'] == 1
    finally:
        monitor.stop(); detector.close()
