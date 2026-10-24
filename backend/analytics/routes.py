from datetime import datetime, timezone
import csv
import io
import json
from statistics import median
from flask import Blueprint, current_app, jsonify, request, Response
from sqlalchemy import select, func
from backend.analytics.pcap_analysis import analyze_capture
from backend.database.models import AnalyticsObservation, AnalyticsBaseline, AnalyticsSession
from backend.errors import APIError
from backend.validation import validate_query, pagination, json_object
from backend.trust_routes import administrator

analytics_api = Blueprint('analytics_api', __name__)


@analytics_api.post('/api/analytics/pcap/analyze')
def analyze_pcap_upload():
    validate_query(('windowSeconds',))
    if request.mimetype != 'multipart/form-data' or request.form or set(request.files) != {'file'} or len(request.files.getlist('file')) != 1:
        raise APIError('invalid_upload', 'Upload exactly one .pcap or .pcapng file in multipart field "file".', 415)
    raw_window = request.args.get('windowSeconds', '60')
    if not raw_window.isdigit() or len(raw_window) > 4:
        raise APIError('invalid_window', 'windowSeconds must be an integer.')
    uploaded = request.files['file']
    name = (uploaded.filename or '').replace('\\', '/').rsplit('/', 1)[-1][:200]
    limit = current_app.config['PCAP_MAX_BYTES']
    data = uploaded.stream.read(limit + 1)
    return jsonify(analyze_capture(data, name, limit, current_app.config['PCAP_MAX_RECORDS'],
                                   current_app.config.get('PCAP_ANALYSIS_MAX_SECONDS', 3), int(raw_window)))


@analytics_api.get('/api/analytics/compare')
def compare_sessions():
    validate_query(('leftSessionId', 'rightSessionId'))
    left, right = request.args.get('leftSessionId'), request.args.get('rightSessionId')
    if not left or not right or left == right or len(left) > 128 or len(right) > 128:
        raise APIError('invalid_query', 'Provide two different session IDs (maximum 128 characters).')
    service = current_app.extensions['analytics']
    a, b = service.summary(session_id=left), service.summary(session_id=right)
    if not a['sessions'] or not b['sessions']:
        raise APIError('session_not_found', 'Both selected analytics sessions must exist.', 404)
    metrics = ('totalPackets', 'uniqueIps', 'uniqueMacs', 'requests', 'replies', 'mappings', 'mappingChanges')
    comparisons = {}
    for name in metrics:
        av, bv = a[name], b[name]
        comparisons[name] = {'left': av, 'right': bv, 'difference': bv-av,
                             'relativeChange': round((bv-av)/av, 4) if av else None}
    return jsonify({'left': a['sessions'][0], 'right': b['sessions'][0], 'comparisons': comparisons,
                    'interpretation': 'Descriptive comparison only. Relative changes are undefined when the left value is zero. No significance test was performed; session duration, capture loss, and time-of-day differences may confound results.'})


def filters(extra=()):
    allowed = ('source', 'sessionId', 'interface', 'start', 'end', 'window') + tuple(extra)
    validate_query(allowed)
    source = request.args.get('source', 'all')
    if source not in ('all', 'live', 'offline'):
        raise APIError('invalid_query', 'source must be all, live, or offline.')
    result = {'source': source, 'session_id': request.args.get('sessionId'), 'interface': request.args.get('interface')}
    for name in ('start', 'end'):
        raw = request.args.get(name)
        if raw:
            try: result[name] = datetime.fromisoformat(raw.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat()
            except ValueError: raise APIError('invalid_query', f'{name} must be an ISO-8601 timestamp.')
    if result.get('start') and result.get('end') and result['start'] > result['end']:
        raise APIError('invalid_query', 'start must be earlier than end.')
    window = request.args.get('window', 'minute')
    if window not in ('minute', '5min', '15min'):
        raise APIError('invalid_query', 'window must be minute, 5min, or 15min.')
    result['window'] = window
    return result


def query(filters):
    q = select(AnalyticsObservation)
    for field, col in (('source', AnalyticsObservation.source), ('session_id', AnalyticsObservation.session_id), ('interface', AnalyticsObservation.interface), ('start', AnalyticsObservation.timestamp), ('end', AnalyticsObservation.timestamp)):
        value = filters.get(field)
        if field == 'source' and value == 'all':
            continue
        if value:
            q = q.where(col >= value if field == 'start' else col <= value if field == 'end' else col == value)
    return q


@analytics_api.get('/api/analytics/summary')
def summary():
    f = filters()
    data = current_app.extensions['analytics'].summary(f['source'], f['session_id'], f['interface'], f.get('start'), f.get('end'))
    return jsonify(data)


@analytics_api.get('/api/analytics/sessions')
def sessions():
    page = pagination(('source',))
    source = request.args.get('source', 'all')
    if source not in ('all', 'live', 'offline'): raise APIError('invalid_query', 'Invalid source.')
    data = current_app.extensions['analytics'].summary(source)
    items = data['sessions']
    return jsonify({'items': items[page['offset']:page['offset']+page['limit']], 'total': len(items), **page})


@analytics_api.get('/api/analytics/top')
def top():
    f = filters(('dimension', 'limit'))
    dimension = request.args.get('dimension', 'source_ip')
    limit = request.args.get('limit', '10')
    if dimension not in ('source_ip', 'destination_ip', 'mac', 'mapping') or not limit.isdigit() or not 1 <= int(limit) <= 10:
        raise APIError('invalid_query', 'Choose a supported dimension and limit from 1 to 10.')
    column = {'source_ip': AnalyticsObservation.sender_ip, 'destination_ip': AnalyticsObservation.target_ip, 'mac': AnalyticsObservation.sender_mac}[dimension] if dimension != 'mapping' else None
    with current_app.extensions['database'].transaction() as db:
        rows = db.scalars(query(f)).all()
    counts = {}
    for row in rows:
        key = f'{row.sender_ip} → {row.sender_mac}' if dimension == 'mapping' else getattr(row, column.key)
        counts[key] = counts.get(key, 0) + 1
    items = [{'key': k, 'count': v} for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:int(limit)]]
    return jsonify({'dimension': dimension, 'items': items, 'frequencyAloneIsNotMalicious': True})


@analytics_api.get('/api/analytics/timeseries')
def timeseries():
    f = filters()
    seconds = {'minute': 60, '5min': 300, '15min': 900}[f['window']]
    with current_app.extensions['database'].transaction() as db:
        rows = db.scalars(query(f)).all()
    buckets = {}
    for row in rows:
        try: stamp = datetime.fromisoformat(row.timestamp.replace('Z', '+00:00')).timestamp()
        except ValueError: continue
        start = int(stamp // seconds * seconds)
        bucket = buckets.setdefault(start, {'timestamp': datetime.fromtimestamp(start, timezone.utc).isoformat(), 'packets': 0, 'requests': 0, 'replies': 0})
        bucket['packets'] += 1; bucket['requests' if row.operation == 'Request' else 'replies'] += 1
    return jsonify({'window': f['window'], 'items': [buckets[k] for k in sorted(buckets)]})


@analytics_api.get('/api/analytics/anomalies')
def anomalies():
    # Deterministic heuristics are deliberately separated from security findings.
    f = filters(('threshold',))
    raw = request.args.get('threshold', '20')
    if not raw.isdigit() or not 2 <= int(raw) <= 10000: raise APIError('invalid_query', 'threshold must be from 2 to 10000.')
    threshold = int(raw)
    with current_app.extensions['database'].transaction() as db:
        rows = db.scalars(query(f)).all()
    counts, maps, buckets = {}, {}, {}
    for row in rows:
        count_key = (row.source, row.session_id, row.sender_ip)
        counts[count_key] = counts.get(count_key, 0) + 1
        maps.setdefault((row.source, row.session_id, row.sender_ip), {}).setdefault(row.sender_mac, []).append(row.timestamp)
        try: stamp = datetime.fromisoformat(row.timestamp.replace('Z', '+00:00')).timestamp()
        except ValueError: continue
        minute = int(stamp // 60 * 60)
        key = (row.source, row.session_id, minute)
        buckets[key] = buckets.get(key, 0) + 1
    items = [{'id': f'frequency:{capture_source}:{session_id}:{ip}', 'kind': 'statistical_anomaly', 'method': 'source_frequency', 'version': '1.0', 'score': count / threshold, 'severity': 'medium' if count < threshold*2 else 'high', 'window': {'start': f.get('start'), 'end': f.get('end')}, 'source': capture_source, 'sessionId': session_id, 'sourceIp': ip, 'observations': {'packetCount': count, 'threshold': threshold}, 'reason': f'{count} ARP observations from {ip} exceeded the configured frequency threshold of {threshold}; frequency alone does not establish malicious activity.'} for (capture_source, session_id, ip), count in counts.items() if count >= threshold]
    for (capture_source, session_id, ip), macs in maps.items():
        if len(macs) > 1:
            items.append({'id': f'mapping-change:{capture_source}:{session_id}:{ip}', 'kind': 'statistical_anomaly', 'method': 'mapping_change', 'version': '1.0', 'score': len(macs)-1, 'severity': 'medium', 'window': {'start': min(t for values in macs.values() for t in values), 'end': max(t for values in macs.values() for t in values)}, 'source': capture_source, 'sessionId': session_id, 'sourceIp': ip, 'observations': {'macs': sorted(macs), 'counts': {mac: len(values) for mac, values in macs.items()}}, 'reason': f'{ip} was observed with {len(macs)} sender MAC addresses in this capture session. Replacement, failover, or incomplete visibility may explain the change.'})
    for (capture_source, session_id, minute), count in buckets.items():
        prior = [value for (src, sid, ts), value in buckets.items() if src == capture_source and sid == session_id and minute-30*60 <= ts < minute]
        if len(prior) >= 5:
            baseline = median(prior)
            limit = max(5, 3 * baseline)
            if count > limit:
                items.append({'id': f'traffic-spike:{capture_source}:{session_id}:{minute}', 'kind': 'statistical_anomaly', 'method': 'rolling_window_spike', 'version': '1.0', 'score': round(count / max(1, limit), 3), 'severity': 'medium', 'window': {'start': datetime.fromtimestamp(minute, timezone.utc).isoformat(), 'end': datetime.fromtimestamp(minute+60, timezone.utc).isoformat()}, 'source': capture_source, 'sessionId': session_id, 'observations': {'packetCount': count, 'baselineMedian': baseline, 'threshold': limit, 'priorNonemptyWindows': len(prior)}, 'reason': f'{count} packets in this minute exceeded 3× the median of {len(prior)} nonempty prior minute windows (minimum threshold 5). This is a traffic spike, not proof of an attack.'})
    requests = sum(row.operation == 'Request' for row in rows); replies = sum(row.operation == 'Reply' for row in rows)
    if len(rows) >= 20 and (requests >= max(1, replies)*10 or replies >= max(1, requests)*10):
        items.append({'id': f'arp-ratio:{f["source"]}:{f.get("session_id") or "selected"}', 'kind': 'statistical_anomaly', 'method': 'arp_request_reply_ratio', 'version': '1.0', 'score': round(max(requests, replies) / max(1, min(requests, replies)), 3), 'severity': 'low', 'window': {'start': f.get('start'), 'end': f.get('end')}, 'source': f['source'], 'observations': {'requests': requests, 'replies': replies, 'minimumPackets': 20, 'ratioThreshold': 10}, 'reason': f'The selected data contains {requests} ARP requests and {replies} replies, an unusually imbalanced ratio by the configured 10:1 heuristic. Capture loss and network role can affect this ratio.'})
    return jsonify({'items': items, 'total': len(items), 'findingType': 'statistical_anomaly', 'existingRuleFindingsIncluded': False})


@analytics_api.get('/api/analytics/report')
def report():
    f = filters(('format',))
    fmt = request.args.get('format', 'json')
    if fmt not in ('json', 'csv'): raise APIError('invalid_query', 'format must be json or csv.')
    data = current_app.extensions['analytics'].summary(f['source'], f['session_id'], f['interface'], f.get('start'), f.get('end'))
    result = {'generatedAt': datetime.now(timezone.utc).isoformat(), 'captureSource': f['source'], 'sessionId': f['session_id'], 'interface': f['interface'], 'analysisPeriod': {'start': f.get('start'), 'end': f.get('end')}, 'method': 'observed ARP aggregates; frequency threshold heuristics v1.0', 'counts': data, 'limitations': ['ARP-only observations; capture can be incomplete.', 'High frequency is not proof of malicious activity.', 'No labelled evaluation dataset was available; precision, recall, F1, and false-positive rate were not calculated.', 'Isolation Forest is not enabled.']}
    if fmt == 'json': return jsonify(result)
    output = io.StringIO(); writer = csv.writer(output); writer.writerow(['field', 'value'])
    for key, value in result.items(): writer.writerow([key, json.dumps(value, separators=(',', ':'))])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename="netguard-analytics.csv"'})


@analytics_api.get('/api/analytics/baselines')
def baselines():
    page = pagination()
    with current_app.extensions['database'].transaction() as db:
        q = select(AnalyticsBaseline).order_by(AnalyticsBaseline.created_at.desc(), AnalyticsBaseline.id)
        total = db.scalar(select(func.count()).select_from(AnalyticsBaseline)) or 0
        rows = db.scalars(q.offset(page['offset']).limit(page['limit'])).all()
    return jsonify({'items': [{'id': x.id, 'sessionId': x.session_id, 'source': x.source, 'createdAt': x.created_at, 'createdBy': x.created_by, 'reason': x.reason, 'sampleCount': x.sample_count, 'features': x.features, 'methodVersion': x.method_version} for x in rows], 'total': total, **page})


@analytics_api.post('/api/analytics/baselines')
@administrator
def create_baseline():
    body = json_object(('sessionId', 'reason'))
    session_id, reason = body.get('sessionId'), body.get('reason')
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128 or not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
        raise APIError('invalid_baseline', 'sessionId is required and reason must contain 10 to 500 characters.')
    try:
        value = current_app.extensions['analytics'].create_baseline(session_id, reason.strip(), current_app.config['ADMIN_ACTOR'], current_app.config.get('ANALYTICS_BASELINE_MINIMUM', 20))
    except ValueError as error:
        raise APIError('baseline_unavailable', str(error), 409) from error
    return jsonify(value), 201


@analytics_api.get('/api/analytics/baselines/<baseline_id>/compare')
def compare_baseline(baseline_id):
    validate_query(('sessionId',))
    session_id = request.args.get('sessionId')
    if not session_id or len(session_id) > 128: raise APIError('invalid_query', 'Provide a target sessionId.')
    with current_app.extensions['database'].transaction() as db:
        baseline = db.get(AnalyticsBaseline, baseline_id)
        target = db.get(AnalyticsSession, session_id)
    if baseline is None or target is None: raise APIError('baseline_or_session_not_found', 'Baseline and target session must exist.', 404)
    actual = current_app.extensions['analytics'].summary(session_id=session_id)
    expected = baseline.features
    pairs = {'totalPackets': (baseline.sample_count, actual['totalPackets']), 'requests': (expected['requests'], actual['requests']), 'replies': (expected['replies'], actual['replies']), 'uniqueIps': (expected['uniqueIps'], actual['uniqueIps']), 'uniqueMacs': (expected['uniqueMacs'], actual['uniqueMacs']), 'mappings': (expected['distinctSenderIpMacMappings'], actual['mappings']), 'mappingChanges': (expected['senderMappingChanges'], actual['mappingChanges'])}
    delta = {key: {'baseline': a, 'observed': b, 'difference': b-a, 'relativeChange': round((b-a)/a, 4) if a else None} for key, (a, b) in pairs.items()}
    return jsonify({'baselineId': baseline.id, 'baselineSessionId': baseline.session_id, 'targetSessionId': session_id, 'baselineMethod': baseline.method_version, 'baselineFeatures': expected, 'observed': actual, 'differences': delta, 'interpretation': 'Descriptive comparison against an explicitly approved session baseline. Differences are not proof of malicious activity; capture duration, interface, time-of-day, and incomplete visibility can confound them.'})
