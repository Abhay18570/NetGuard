from datetime import datetime, timezone
from queue import Queue, Full, Empty
from threading import Thread
import logging
from uuid import uuid4
from statistics import median
from ipaddress import ip_address
from sqlalchemy import select, func, union, case, cast, Integer, literal
from backend.database.models import AnalyticsObservation, ProtocolAnalyticsObservation, AnalyticsSession, AnalyticsBaseline, AnalyticsBaselineAudit, DetectionFinding

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Bounded persistence worker. enqueue() never waits on SQLite or the capture thread."""
    def __init__(self, database, capacity=10000):
        self.db, self.queue = database, Queue(maxsize=capacity)
        self.dropped = 0
        self._closed = False
        self._worker = Thread(target=self._run, name='netguard-analytics', daemon=True)
        self._worker.start()

    def enqueue(self, packet):
        try:
            self.queue.put_nowait(dict(packet))
        except Full:
            self.dropped += 1

    def session_status(self, status):
        session_id = status.get('sessionId')
        if not session_id:
            return
        mode = status.get('mode')
        if mode not in ('live', 'offline'):
            return
        state = status.get('state', 'unknown')
        started = status.get('startedAt')
        ended = datetime.now(timezone.utc).isoformat() if state in ('stopped', 'completed', 'error') else None
        try:
            with self.db.transaction(write=True) as db:
                row = db.get(AnalyticsSession, session_id)
                if row is None:
                    db.add(AnalyticsSession(id=session_id, source=mode, interface=status.get('interface') if mode == 'live' else None, state=state, started_at=started, ended_at=ended))
                else:
                    row.state, row.started_at = state, started or row.started_at
                    row.ended_at = ended or row.ended_at
        except Exception:
            logger.exception('Could not persist analytics session')

    def _run(self):
        while True:
            item = self.queue.get()
            try:
                if item is None:
                    return
                source = item.get('source')
                if source not in ('live', 'offline') or (source == 'offline' and item.get('interface') is not None):
                    continue
                protocol = item.get('protocol', 'ARP')
                if protocol not in ('ARP', 'TCP', 'UDP', 'DNS'):
                    continue
                if protocol == 'ARP':
                    if not all(isinstance(item.get(key), str)
                               for key in ('senderIp', 'senderMac', 'targetIp', 'targetMac')):
                        logger.warning('Analytics skipped an ARP observation missing normalized address fields')
                        continue
                else:
                    if (not all(isinstance(item.get(key), str) and item[key] for key in
                                ('id', 'sessionId', 'timestamp', 'sourceIp', 'destinationIp'))
                            or len(item['sessionId']) > 128 or len(item['id']) > 256):
                        logger.warning('Analytics skipped a %s observation missing required fields', protocol)
                        continue
                    operations = {'TCP': ('Request', 'Reply', 'Packet'),
                                  'UDP': ('Packet',), 'DNS': ('Query', 'Response')}
                    if (item.get('operation') not in operations[protocol]
                            or (source == 'live' and (not isinstance(item.get('interface'), str)
                                or not item['interface'] or len(item['interface']) > 128))
                            or (source == 'offline' and item.get('interface') is not None)
                            or type(item.get('sequence')) is not int or item['sequence'] < 1):
                        logger.warning('Analytics skipped an invalid %s observation', protocol)
                        continue
                    try:
                        timestamp = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
                        source_ip = str(ip_address(item['sourceIp']))
                        destination_ip = str(ip_address(item['destinationIp']))
                        if timestamp.tzinfo is None:
                            raise ValueError('Observation timestamp requires a timezone')
                    except (AttributeError, TypeError, ValueError):
                        logger.warning('Analytics skipped a %s observation with invalid address or timestamp fields', protocol)
                        continue
                    ports = []
                    valid_ports = True
                    for name in ('sourcePort', 'destinationPort'):
                        value = item.get(name)
                        if value is not None and (type(value) is not int or not 0 <= value <= 65535):
                            valid_ports = False
                        ports.append(value)
                    byte_count = item.get('byteCount')
                    if byte_count is not None and (type(byte_count) is not int or byte_count < 0):
                        byte_count = None
                    if not valid_ports:
                        logger.warning('Analytics skipped a %s observation with an invalid port', protocol)
                        continue
                    flags = item.get('flags')
                    if not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
                        flags = None
                    optional_text = {}
                    for source_name, target_name, maximum in (
                            ('queryName', 'query_name', 255),
                            ('queryType', 'query_type', 32),
                            ('responseCode', 'response_code', 16),
                            ('transport', 'transport', 8)):
                        value = item.get(source_name)
                        optional_text[target_name] = value[:maximum] if isinstance(value, str) else None
                    with self.db.transaction(write=True) as db:
                        if db.get(ProtocolAnalyticsObservation, item['id']) is None:
                            db.add(ProtocolAnalyticsObservation(
                                packet_id=item['id'], session_id=item['sessionId'],
                                sequence=int(item.get('sequence', 0)), source=source,
                                interface=item.get('interface'), protocol=protocol,
                                timestamp=item['timestamp'], operation=item['operation'],
                                source_ip=source_ip, destination_ip=destination_ip,
                                source_port=ports[0], destination_port=ports[1],
                                flags=flags, byte_count=byte_count, **optional_text))
                    continue
                with self.db.transaction(write=True) as db:
                    if db.get(AnalyticsObservation, str(item.get('id', ''))) is None:
                        db.add(AnalyticsObservation(packet_id=item['id'], session_id=item['sessionId'], sequence=int(item['sequence']), source=source, interface=item.get('interface'), timestamp=item['timestamp'], operation=item['operation'], sender_ip=item['senderIp'], sender_mac=item['senderMac'], target_ip=item['targetIp'], target_mac=item['targetMac']))
            except Exception:
                logger.exception('Analytics observation was not persisted')
            finally:
                self.queue.task_done()

    def drain(self, timeout=5):
        # Queue.join has no timeout; polling keeps this helper useful in bounded tests.
        import time
        deadline = time.monotonic() + timeout
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(.005)
        return self.queue.unfinished_tasks == 0

    def summary(self, source='all', session_id=None, interface=None, start=None, end=None):
        with self.db.transaction() as db:
            q = select(AnalyticsObservation)
            if source != 'all': q = q.where(AnalyticsObservation.source == source)
            if session_id: q = q.where(AnalyticsObservation.session_id == session_id)
            if interface: q = q.where(AnalyticsObservation.interface == interface)
            if start: q = q.where(AnalyticsObservation.timestamp >= start)
            if end: q = q.where(AnalyticsObservation.timestamp <= end)
            total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
            base = q.subquery()
            requests, replies = db.execute(select(
                func.sum(case((base.c.operation == 'Request', 1), else_=0)),
                func.sum(case((base.c.operation == 'Reply', 1), else_=0))).select_from(base)).one() if total else (0, 0)
            sub = select(base.c.sender_ip, base.c.sender_mac).distinct().subquery()
            pairs = db.execute(select(sub.c.sender_ip, func.count(func.distinct(sub.c.sender_mac))).group_by(sub.c.sender_ip)).all()
            mappings = db.scalar(select(func.count()).select_from(sub)) or 0
            ips = union(select(base.c.sender_ip.label('ip')), select(base.c.target_ip.label('ip'))).subquery()
            unique_ips = db.scalar(select(func.count()).select_from(ips)) or 0
            macs = union(select(base.c.sender_mac.label('mac')), select(base.c.target_mac.label('mac'))).subquery()
            unique_macs = db.scalar(select(func.count()).select_from(macs)) or 0
            finding_rows = db.execute(select(DetectionFinding.severity, DetectionFinding.rule_id, func.count()).where(*([DetectionFinding.source == source] if source != 'all' else []), *([DetectionFinding.timestamp >= start] if start else []), *([DetectionFinding.timestamp <= end] if end else [])).group_by(DetectionFinding.severity, DetectionFinding.rule_id)).all()
            sessions = db.scalars(select(AnalyticsSession)).all()
        return {'totalPackets': total, 'uniqueIps': unique_ips, 'uniqueMacs': unique_macs, 'requests': requests or 0, 'replies': replies or 0,
                'requestReplyRatio': round(requests / replies, 3) if replies else None,
                'mappings': mappings, 'mappingChanges': sum(max(0, count-1) for _, count in pairs),
                'sessions': [{'sessionId': s.id, 'source': s.source, 'interface': s.interface, 'state': s.state, 'startedAt': s.started_at, 'endedAt': s.ended_at} for s in sessions if (source == 'all' or source == s.source) and (not session_id or s.id == session_id) and (not interface or s.interface == interface)],
                'findings': [{'severity': sev, 'method': method, 'count': count} for sev, method, count in finding_rows],
                'analyticsQueueDepth': self.queue.qsize(), 'analyticsDropped': self.dropped}

    def dashboard(self, filters, protocol='all'):
        selected = ('ARP', 'TCP', 'UDP', 'DNS') if protocol == 'all' else (protocol,)
        seconds = {'minute': 60, '5min': 300, '15min': 900}[filters['window']]

        def filtered(statement, model, include_protocol=False):
            for name, column in (
                    ('source', model.source), ('session_id', model.session_id),
                    ('interface', model.interface), ('start', model.timestamp),
                    ('end', model.timestamp)):
                value = filters.get(name)
                if name == 'source' and value == 'all':
                    continue
                if value:
                    statement = statement.where(
                        column >= value if name == 'start' else
                        column <= value if name == 'end' else column == value)
            if include_protocol:
                statement = statement.where(model.protocol.in_(selected))
            return statement

        with self.db.transaction() as db:
            arp_query = filtered(select(AnalyticsObservation), AnalyticsObservation)
            other_query = filtered(
                select(ProtocolAnalyticsObservation), ProtocolAnalyticsObservation,
                include_protocol=True)
            arp = arp_query.subquery()
            other = other_query.subquery()
            counts = {name: 0 for name in selected}
            counts['ARP'] = db.scalar(select(func.count()).select_from(arp)) or 0 if 'ARP' in selected else 0
            for name in ('TCP', 'UDP', 'DNS'):
                if name in selected:
                    counts[name] = db.scalar(select(func.count()).select_from(other).where(other.c.protocol == name)) or 0

            arp_metrics = {'packetCount': counts['ARP'], 'uniqueIps': 0, 'uniqueMacs': 0,
                           'mappings': 0, 'mappingChanges': 0, 'requests': 0, 'replies': 0,
                           'requestReplyRatio': None}
            if 'ARP' in selected and counts['ARP']:
                arp_metrics['requests'], arp_metrics['replies'] = db.execute(select(
                    func.sum(case((arp.c.operation == 'Request', 1), else_=0)),
                    func.sum(case((arp.c.operation == 'Reply', 1), else_=0))).select_from(arp)).one()
                arp_metrics['requests'] = arp_metrics['requests'] or 0
                arp_metrics['replies'] = arp_metrics['replies'] or 0
                arp_metrics['requestReplyRatio'] = (
                    round(arp_metrics['requests'] / arp_metrics['replies'], 3)
                    if arp_metrics['replies'] else None)
                arp_ips = union(select(arp.c.sender_ip.label('ip')), select(arp.c.target_ip.label('ip'))).subquery()
                arp_macs = union(select(arp.c.sender_mac.label('mac')), select(arp.c.target_mac.label('mac'))).subquery()
                pairs = db.execute(select(arp.c.sender_ip, arp.c.sender_mac).distinct()).all()
                macs_by_ip = {}
                for ip, mac in pairs:
                    macs_by_ip.setdefault(ip, set()).add(mac)
                arp_metrics.update({
                    'uniqueIps': db.scalar(select(func.count()).select_from(arp_ips)) or 0,
                    'uniqueMacs': db.scalar(select(func.count()).select_from(arp_macs)) or 0,
                    'mappings': len(pairs),
                    'mappingChanges': sum(max(0, len(macs) - 1) for macs in macs_by_ip.values()),
                })

            metrics = {'ARP': arp_metrics}
            for name in ('TCP', 'UDP'):
                if name not in selected:
                    continue
                rows = other_query.where(ProtocolAnalyticsObservation.protocol == name).subquery()
                ip_rows = union(select(rows.c.source_ip.label('ip')),
                                select(rows.c.destination_ip.label('ip'))).subquery()
                flow_rows = select(rows.c.source_ip, rows.c.source_port,
                                   rows.c.destination_ip, rows.c.destination_port).distinct().subquery()
                ports = db.execute(select(rows.c.destination_port, func.count())
                                   .where(rows.c.destination_port.is_not(None))
                                   .group_by(rows.c.destination_port)
                                   .order_by(func.count().desc(), rows.c.destination_port)
                                   .limit(10)).all()
                port_items = [{'key': str(port), 'count': count,
                               'service': _port_service(name, port)} for port, count in ports]
                metric = {
                    'packetCount': counts[name],
                    'uniqueIps': db.scalar(select(func.count()).select_from(ip_rows)) or 0,
                    'uniqueSourcePorts': db.scalar(select(func.count(func.distinct(rows.c.source_port)))) or 0,
                    'uniqueDestinationPorts': db.scalar(select(func.count(func.distinct(rows.c.destination_port)))) or 0,
                    'flowTuples': db.scalar(select(func.count()).select_from(flow_rows)) or 0,
                    'topDestinationPorts': port_items,
                }
                if name == 'TCP':
                    flag_counts = {}
                    for (packet_flags,) in db.execute(select(rows.c.flags).where(rows.c.flags.is_not(None))):
                        for flag in packet_flags or ():
                            flag_counts[flag] = flag_counts.get(flag, 0) + 1
                    metric['flags'] = dict(sorted(flag_counts.items()))
                    metric['synPackets'] = flag_counts.get('SYN', 0)
                    metric['synAckPackets'] = flag_counts.get('SYN-ACK', 0)
                    metric['resetPackets'] = flag_counts.get('RST', 0)
                metrics[name] = metric

            if 'DNS' in selected:
                dns = other_query.where(ProtocolAnalyticsObservation.protocol == 'DNS').subquery()

                def grouped(column):
                    return [{'key': key, 'count': count} for key, count in db.execute(
                        select(column, func.count()).where(column.is_not(None))
                        .group_by(column).order_by(func.count().desc(), column).limit(10))]

                queries = db.scalar(select(func.count()).select_from(dns).where(dns.c.operation == 'Query')) or 0
                responses = db.scalar(select(func.count()).select_from(dns).where(dns.c.operation == 'Response')) or 0
                codes = [{'key': key, 'count': count} for key, count in db.execute(
                    select(dns.c.response_code, func.count())
                    .where(dns.c.operation == 'Response', dns.c.response_code.is_not(None))
                    .group_by(dns.c.response_code)
                    .order_by(func.count().desc(), dns.c.response_code).limit(10))]
                failures = sum(item['count'] for item in codes if item['key'] not in ('0', 'NOERROR'))
                metrics['DNS'] = {
                    'packetCount': counts['DNS'], 'queries': queries, 'responses': responses,
                    'topDomains': grouped(dns.c.query_name),
                    'recordTypes': grouped(dns.c.query_type),
                    'responseCodes': codes, 'queryFailures': failures,
                }

            source_counts = {}
            if 'ARP' in selected:
                for ip, count in db.execute(select(arp.c.sender_ip, func.count()).group_by(arp.c.sender_ip)):
                    source_counts[ip] = source_counts.get(ip, 0) + count
            if any(name in selected for name in ('TCP', 'UDP', 'DNS')):
                for ip, count in db.execute(select(other.c.source_ip, func.count())
                                            .group_by(other.c.source_ip)):
                    source_counts[ip] = source_counts.get(ip, 0) + count
            top_sources = [{'key': ip, 'count': count} for ip, count in
                           sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:10]]

            port_counts = {}
            if any(name in selected for name in ('TCP', 'UDP', 'DNS')):
                for name, port, count in db.execute(select(
                        other.c.protocol, other.c.destination_port, func.count())
                        .where(other.c.destination_port.is_not(None))
                        .group_by(other.c.protocol, other.c.destination_port)
                        .order_by(func.count().desc(), other.c.protocol, other.c.destination_port)
                        .limit(30)):
                    key = f'{port}/{name}'
                    port_counts[key] = {'key': key, 'count': count, 'service': _port_service(name, port)}
            top_ports = sorted(port_counts.values(), key=lambda item: (-item['count'], item['key']))[:10]

            timeline = {}
            if 'ARP' in selected:
                arp_bucket = cast(cast(func.strftime('%s', AnalyticsObservation.timestamp), Integer)
                                  / seconds, Integer) * seconds
                arp_groups = select(arp_bucket.label('bucket'), AnalyticsObservation.operation,
                                    func.count()).select_from(AnalyticsObservation)
                arp_groups = filtered(arp_groups, AnalyticsObservation)
                for stamp, operation, count in db.execute(
                        arp_groups.group_by(arp_bucket, AnalyticsObservation.operation)):
                    if stamp is None:
                        continue
                    point = timeline.setdefault(int(stamp), {'timestamp': datetime.fromtimestamp(
                        int(stamp), timezone.utc).isoformat(), 'protocolCounts': {}, 'operationCounts': {}})
                    point['protocolCounts']['ARP'] = point['protocolCounts'].get('ARP', 0) + count
                    operations = point['operationCounts'].setdefault('ARP', {})
                    operations[operation] = operations.get(operation, 0) + count
            if any(name in selected for name in ('TCP', 'UDP', 'DNS')):
                bucket = cast(cast(func.strftime('%s', ProtocolAnalyticsObservation.timestamp), Integer) / seconds, Integer) * seconds
                protocol_groups = select(bucket.label('bucket'), ProtocolAnalyticsObservation.protocol,
                                         ProtocolAnalyticsObservation.operation, func.count()).select_from(ProtocolAnalyticsObservation)
                protocol_groups = filtered(protocol_groups, ProtocolAnalyticsObservation, include_protocol=True)
                for stamp, name, operation, count in db.execute(
                        protocol_groups.group_by(bucket, ProtocolAnalyticsObservation.protocol,
                                                 ProtocolAnalyticsObservation.operation)):
                    if stamp is None:
                        continue
                    point = timeline.setdefault(int(stamp), {'timestamp': datetime.fromtimestamp(
                        int(stamp), timezone.utc).isoformat(), 'protocolCounts': {}, 'operationCounts': {}})
                    point['protocolCounts'][name] = point['protocolCounts'].get(name, 0) + count
                    operations = point['operationCounts'].setdefault(name, {})
                    operations[operation] = operations.get(operation, 0) + count
            timeline_items = [timeline[key] for key in sorted(timeline)]

            finding_conditions = []
            if filters.get('source') != 'all':
                finding_conditions.append(DetectionFinding.source == filters['source'])
            if filters.get('start'):
                finding_conditions.append(DetectionFinding.timestamp >= filters['start'])
            if filters.get('end'):
                finding_conditions.append(DetectionFinding.timestamp <= filters['end'])
            if filters.get('session_id'):
                finding_conditions.append(
                    DetectionFinding.payload['sessionId'].as_string() == filters['session_id'])
            if filters.get('interface'):
                finding_conditions.append(
                    DetectionFinding.payload['interface'].as_string() == filters['interface'])
            finding_rows = db.execute(select(
                DetectionFinding.rule_id, DetectionFinding.severity, func.count())
                .where(*finding_conditions)
                .group_by(DetectionFinding.rule_id, DetectionFinding.severity)).all()
            finding_items = [{'protocol': 'ARP', 'method': method, 'severity': severity, 'count': count}
                             for method, severity, count in finding_rows] if 'ARP' in selected else []
            total = sum(counts.values())
            unique_ip_queries = []
            if 'ARP' in selected:
                unique_ip_queries.extend((select(arp.c.sender_ip.label('ip')), select(arp.c.target_ip.label('ip'))))
            if any(name in selected for name in ('TCP', 'UDP', 'DNS')):
                unique_ip_queries.extend((select(other.c.source_ip.label('ip')),
                                          select(other.c.destination_ip.label('ip'))))
            if unique_ip_queries:
                unique_ips_query = union(*unique_ip_queries).subquery()
                unique_ips = db.scalar(select(func.count()).select_from(unique_ips_query)) or 0
            else:
                unique_ips = 0

        return {
            'protocol': protocol, 'totalPackets': total, 'uniqueIps': unique_ips,
            'protocolCounts': [{'protocol': name, 'count': counts.get(name, 0)} for name in selected],
            'metrics': {name: metrics[name] for name in selected},
            'timeseries': timeline_items, 'topSources': top_sources, 'topDestinationPorts': top_ports,
            'findings': finding_items, 'findingsNote': (
                'Detection findings are currently generated by the ARP detection rules; no TCP, UDP, or DNS detection rules are configured.'
            ),
        }

    def create_baseline(self, session_id, reason, actor, minimum=20):
        if not self.drain(timeout=5):
            raise ValueError('Analytics observations are still processing; retry baseline creation.')
        with self.db.transaction(write=True) as db:
            capture = db.get(AnalyticsSession, session_id)
            if capture is None or capture.state not in ('completed', 'stopped'):
                raise ValueError('Choose a completed or stopped capture session for baseline approval.')
            q = select(AnalyticsObservation).where(AnalyticsObservation.session_id == session_id)
            count = db.scalar(select(func.count()).select_from(q.subquery())) or 0
            if count < minimum:
                raise ValueError(f'Baseline requires at least {minimum} observed packets; this session has {count}.')
            bucket_rows = db.execute(select(func.substr(AnalyticsObservation.timestamp, 1, 16), func.count()).where(AnalyticsObservation.session_id == session_id).group_by(func.substr(AnalyticsObservation.timestamp, 1, 16))).all()
            rates = [float(total) for _, total in bucket_rows]
            center = median(rates) if rates else 0.0
            mad = median([abs(value-center) for value in rates]) if rates else 0.0
            ordered = sorted(rates)
            p95 = ordered[min(len(ordered)-1, int((len(ordered)-1)*.95))] if ordered else 0
            sub = select(AnalyticsObservation.sender_ip, AnalyticsObservation.sender_mac).where(AnalyticsObservation.session_id == session_id).distinct().subquery()
            pairs = db.execute(select(sub.c.sender_ip, func.count()).group_by(sub.c.sender_ip)).all()
            mappings = db.scalar(select(func.count()).select_from(sub)) or 0
            requests, replies = db.execute(select(
                func.sum(case((AnalyticsObservation.operation == 'Request', 1), else_=0)),
                func.sum(case((AnalyticsObservation.operation == 'Reply', 1), else_=0))).where(AnalyticsObservation.session_id == session_id)).one()
            unique_ips = union(select(AnalyticsObservation.sender_ip.label('ip')).where(AnalyticsObservation.session_id == session_id), select(AnalyticsObservation.target_ip.label('ip')).where(AnalyticsObservation.session_id == session_id)).subquery()
            unique_macs = union(select(AnalyticsObservation.sender_mac.label('mac')).where(AnalyticsObservation.session_id == session_id), select(AnalyticsObservation.target_mac.label('mac')).where(AnalyticsObservation.session_id == session_id)).subquery()
            features = {'windowSeconds': 60, 'sampleCount': count, 'activeMinuteWindows': len(rates), 'packetsPerActiveMinute': {'median': center, 'mad': mad, 'p95': p95, 'max': max(rates, default=0)}, 'requests': requests or 0, 'replies': replies or 0, 'requestReplyRatio': round(requests/replies, 3) if replies else None, 'uniqueIps': db.scalar(select(func.count()).select_from(unique_ips)) or 0, 'uniqueMacs': db.scalar(select(func.count()).select_from(unique_macs)) or 0, 'distinctSenderIpMacMappings': mappings, 'senderMappingChanges': sum(max(0, n-1) for _, n in pairs)}
            baseline_id = str(uuid4()); now = datetime.now(timezone.utc).isoformat()
            db.add(AnalyticsBaseline(id=baseline_id, session_id=session_id, source=capture.source, created_at=now, created_by=actor, reason=reason, sample_count=count, features=features))
            db.flush()
            db.add(AnalyticsBaselineAudit(baseline_id=baseline_id, action='approved', actor=actor, reason=reason, timestamp=now))
        return {'id': baseline_id, 'sessionId': session_id, 'source': capture.source, 'createdAt': now, 'createdBy': actor, 'reason': reason, 'sampleCount': count, 'features': features, 'methodVersion': 'robust-session-baseline-1.0'}

    def close(self):
        if self._closed: return
        self._closed = True
        self.queue.put(None)
        self._worker.join(2)


def _port_service(protocol, port):
    if protocol == 'DNS' and port == 53:
        return 'DNS'
    if protocol == 'TCP':
        return {20: 'FTP data', 21: 'FTP control', 22: 'SSH', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
                3389: 'RDP'}.get(port, 'Other')
    if protocol == 'UDP':
        return {53: 'DNS', 67: 'DHCP server', 68: 'DHCP client',
                123: 'NTP', 161: 'SNMP', 443: 'QUIC'}.get(port, 'Other')
    return 'Other'
