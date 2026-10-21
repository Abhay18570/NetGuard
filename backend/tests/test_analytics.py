from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from backend.app import create_app
from backend.database.models import AnalyticsObservation, ObservedMapping, TrustedMapping, AnalyticsBaselineAudit
from backend.analytics.pcap_analysis import analyze_capture


def packet(session='sess', sequence=1, source='offline', timestamp='2026-01-01T00:00:00+00:00', ip='10.0.0.1', mac='aa:bb:cc:dd:ee:01', operation='Request'):
    return {'id': f'{session}:{sequence}', 'sessionId': session, 'sequence': sequence, 'source': source,
            'interface': 'eth0' if source == 'live' else None, 'timestamp': timestamp, 'operation': operation,
            'senderIp': ip, 'senderMac': mac, 'targetIp': '10.0.0.2', 'targetMac': '00:00:00:00:00:00'}


def test_empty_dataset_and_filters():
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://'})
    client = app.test_client()
    assert client.get('/api/analytics/summary').json['totalPackets'] == 0
    assert client.get('/api/analytics/top').json['items'] == []
    assert client.get('/api/analytics/timeseries').json['items'] == []
    app.extensions['analytics'].close()


def test_duplicate_persistence_and_offline_replay_isolation():
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://'})
    analytics = app.extensions['analytics']
    analytics.enqueue(packet()); analytics.enqueue(packet()); assert analytics.drain()
    assert app.test_client().get('/api/analytics/summary?source=offline').json['totalPackets'] == 1
    with app.extensions['database'].transaction() as db:
        assert db.query(ObservedMapping).count() == 0
        assert db.query(TrustedMapping).count() == 0
    analytics.close()


def test_mapping_changes_and_window_boundaries():
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://'})
    analytics = app.extensions['analytics']
    analytics.enqueue(packet(sequence=1, timestamp='2026-01-01T00:00:59+00:00'))
    analytics.enqueue(packet(sequence=2, timestamp='2026-01-01T00:01:00+00:00', mac='aa:bb:cc:dd:ee:02', operation='Reply'))
    assert analytics.drain()
    summary = app.test_client().get('/api/analytics/summary').json
    assert summary['mappingChanges'] == 1 and summary['requests'] == summary['replies'] == 1
    series = app.test_client().get('/api/analytics/timeseries?window=minute').json['items']
    assert len(series) == 2
    anomalies = app.test_client().get('/api/analytics/anomalies').json['items']
    assert any(item['method'] == 'mapping_change' and item['source'] == 'offline' for item in anomalies)
    analytics.close()


def test_high_volume_bounded_worker_and_report():
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://', 'ANALYTICS_QUEUE_CAPACITY': 256})
    analytics = app.extensions['analytics']
    for seq in range(1, 201): analytics.enqueue(packet(sequence=seq, ip=f'10.0.{seq // 250}.{seq % 250 + 1}'))
    assert analytics.drain(10)
    client = app.test_client()
    assert client.get('/api/analytics/summary').json['totalPackets'] == 200
    assert 'limitations' in client.get('/api/analytics/report?format=json').json
    assert client.get('/api/analytics/report?format=csv').mimetype == 'text/csv'
    analytics.close()


def test_offline_pcap_metadata_extraction_is_payload_free():
    fixture = Path(__file__).parent / 'fixtures' / 'offline-arp.pcap'
    result = analyze_capture(fixture.read_bytes(), fixture.name)
    assert result['source'] == 'offline' and result['packetCount'] == 2
    assert result['arp'] == {'requests': 1, 'replies': 1}
    assert result['flowCount'] >= 1 and result['timeline']
    assert all('payload' not in key.lower() for key in result)


def test_pcapng_supported_and_upload_endpoint_validates(tmp_path):
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    from scapy.utils import PcapNgWriter
    output = tmp_path / 'sample.pcapng'; writer = PcapNgWriter(str(output))
    writer.write(Ether(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66')/IP(src='192.0.2.1', dst='198.51.100.2')/TCP(sport=1200,dport=443,flags='S'))
    writer.close()
    data = output.read_bytes()
    result = analyze_capture(data, 'test.pcapng')
    assert result['captureFormat'] == 'pcapng' and result['protocolCounts']['TCP'] == 1
    assert result['tcpFlags'] == {'S': 1}
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://'})
    response = app.test_client().post('/api/analytics/pcap/analyze', data={'file': (BytesIO(data), 'sample.pcapng')}, content_type='multipart/form-data')
    assert response.status_code == 200 and response.json['packetCount'] == 1
    bad = app.test_client().post('/api/analytics/pcap/analyze', data={'file': (BytesIO(data), 'sample.txt')}, content_type='multipart/form-data')
    assert bad.status_code == 400
    app.extensions['analytics'].close()


def test_session_comparison_is_descriptive():
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://'})
    analytics = app.extensions['analytics']
    analytics.session_status({'sessionId': 'left', 'mode': 'offline', 'state': 'completed'})
    analytics.session_status({'sessionId': 'right', 'mode': 'live', 'interface': 'eth0', 'state': 'completed'})
    analytics.enqueue(packet(session='left', sequence=1))
    analytics.enqueue(packet(session='right', sequence=1, source='live'))
    assert analytics.drain()
    result = app.test_client().get('/api/analytics/compare?leftSessionId=left&rightSessionId=right')
    assert result.status_code == 200
    assert result.json['comparisons']['totalPackets']['difference'] == 0
    assert 'No significance test' in result.json['interpretation']
    analytics.close()


def test_offline_analysis_rejects_malformed_oversized_and_slow_inputs():
    import pytest
    from backend.errors import APIError
    fixture = Path(__file__).parent / 'fixtures' / 'offline-arp.pcap'
    data = fixture.read_bytes()
    with pytest.raises(APIError): analyze_capture(b'not a capture', 'bad.pcap')
    with pytest.raises(APIError): analyze_capture(data, 'file.pcap', max_bytes=10)
    with pytest.raises(APIError): analyze_capture(data, 'file.pcap', max_records=1)
    with pytest.raises(APIError): analyze_capture(data, 'file.pcap', max_seconds=0)


def test_baseline_requires_admin_approval_and_audit_record():
    from secrets import token_urlsafe
    token = token_urlsafe(32)
    app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite://', 'ADMIN_TOKEN': token, 'ADMIN_ACTOR': 'analyst'})
    analytics = app.extensions['analytics']
    analytics.session_status({'sessionId': 'baseline', 'mode': 'offline', 'state': 'completed'})
    analytics.session_status({'sessionId': 'observed', 'mode': 'offline', 'state': 'completed'})
    for seq in range(1, 21):
        analytics.enqueue(packet(session='baseline', sequence=seq, timestamp=f'2026-01-01T00:00:{seq:02d}+00:00'))
    analytics.enqueue(packet(session='observed', sequence=1))
    assert analytics.drain()
    client = app.test_client()
    payload = {'sessionId': 'baseline', 'reason': 'Approved stable lab observation window'}
    assert client.post('/api/analytics/baselines', json=payload).status_code == 401
    created = client.post('/api/analytics/baselines', json=payload, headers={'Authorization': f'Bearer {token}'})
    assert created.status_code == 201 and created.json['sampleCount'] == 20
    comparison = client.get(f"/api/analytics/baselines/{created.json['id']}/compare?sessionId=observed")
    assert comparison.status_code == 200 and comparison.json['differences']['totalPackets']['difference'] == -19
    with app.extensions['database'].transaction() as db:
        assert db.query(AnalyticsBaselineAudit).count() == 1
    analytics.close()
