"""Bounded asynchronous analysis. Persistence failures never change capture state."""
from collections import OrderedDict, deque
from datetime import datetime
from ipaddress import IPv4Address
from hashlib import sha256
import json
import logging
from queue import Queue, Full, Empty
from threading import RLock, Thread
from uuid import uuid4
from sqlalchemy import select, func, String
from backend.database.models import DetectionFinding, DetectionReceipt, TrustedMapping
from backend.discovery.validation import normalize_ip, normalize_mac, utc_timestamp
from backend.services.alerts import ensure_alert
from backend.detection.rules import Thresholds, evaluate, correlated, gratuitous

logger = logging.getLogger(__name__)


class DetectionService:
    def __init__(self, database, emit, thresholds=None, gateway_ids=()):
        self.database, self.emit = database, emit
        self.config = Thresholds(**(thresholds or {}))
        if not isinstance(gateway_ids, (list, tuple)) or any(not isinstance(x, str) or not x or len(x) > 36 for x in gateway_ids):
            raise ValueError('Gateway mapping IDs must be an explicit list of mapping IDs')
        self.gateway_ids = frozenset(gateway_ids)
        self.queue = Queue(self.config.queue_capacity)
        self.lock, self.worker_lock = RLock(), RLock()
        self.histories = OrderedDict()
        self.cooldowns = OrderedDict()
        self.failed = self.dropped = self.late = 0
        self.worker = None
        self.closed = False

    def enqueue(self, packet):
        with self.worker_lock:
            if self.closed:
                return
            try:
                self.queue.put_nowait(dict(packet))
            except Full:
                self.dropped += 1
                return
            if self.worker is None:
                self.worker = Thread(target=self._run, daemon=True, name='netguard-detection')
                self.worker.start()

    def _run(self):
        while True:
            try:
                packet = self.queue.get(timeout=.1)
            except Empty:
                with self.worker_lock:
                    if self.queue.empty():
                        self.worker = None
                        return
                continue
            try:
                self.process(packet)
            except Exception:
                self.failed += 1
                logger.exception('Detection failed; capture remains independent')
            finally:
                self.queue.task_done()

    def drain(self):
        self.queue.join()

    def close(self):
        with self.worker_lock:
            self.closed = True
        self.drain()

    def status(self):
        with self.database.transaction() as session:
            session.execute(select(1))
        return {'state': 'degraded' if self.failed or self.dropped or self.late else 'ready',
                'failedPackets': self.failed, 'droppedPackets': self.dropped, 'latePackets': self.late,
                'pendingPackets': self.queue.unfinished_tasks,
                'thresholds': vars(self.config), 'gatewayMappingIds': sorted(self.gateway_ids),
                'message': 'Analysis is incomplete; inspect failure, queue-drop, or out-of-order counts.' if self.failed or self.dropped or self.late else None}

    def process(self, packet):
        p = dict(packet)
        if p.get('protocol') not in (None, 'ARP'):
            return []
        if p.get('source') not in ('live', 'offline') or p.get('operation') not in ('Request', 'Reply'):
            raise ValueError('Invalid packet source or operation')
        for key in ('id', 'sessionId'):
            if not isinstance(p.get(key), str) or not p[key] or len(p[key]) > 256:
                raise ValueError('Invalid packet identity')
        if not all(isinstance(p.get(key), str) for key in ('senderIp', 'senderMac', 'targetIp', 'targetMac')):
            raise ValueError('ARP packet is missing normalized sender or target fields')
        if p['source'] == 'live' and (not isinstance(p.get('interface'), str) or not p['interface'] or len(p['interface']) > 128):
            raise ValueError('Invalid live interface')
        if p['source'] == 'offline' and p.get('interface') is not None:
            raise ValueError('Offline observations cannot name a live interface')
        # ARP probes have no sender claim; they are not suspicious findings.
        if p.get('senderIp') == '0.0.0.0':
            return []
        p['senderIp'], p['targetIp'] = normalize_ip(p['senderIp']), str(IPv4Address(p['targetIp']))
        p['senderMac'] = normalize_mac(p['senderMac'])
        p['targetMac'] = normalize_mac(p['targetMac'], unicast=False)
        p['timestamp'] = utc_timestamp(p['timestamp'])
        fingerprint = sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()
        p['_time'] = datetime.fromisoformat(p['timestamp']).timestamp()
        scope = f"{p['source']}:{p['interface'] or ''}:{p['sessionId']}"
        output = []
        alert_output = []
        with self.lock:
            history = list(self.histories.get(scope, ()))
            newest = history[-1]['_time'] if history else p['_time']
            late = p['_time'] < newest
            window = max(self.config.claim_window, self.config.burst_window + self.config.request_window)
            history = [x for x in history if p['_time'] - x['_time'] <= window]
            p['_uncorrelatedEligible'] = bool(history and not late and p['operation'] == 'Reply'
                and not gratuitous(p) and p['_time'] - history[0]['_time'] >= self.config.request_window
                and not correlated(p, history, self.config.request_window))
            cooldown_updates = []
            with self.database.transaction(write=True) as session:
                receipt = session.get(DetectionReceipt, p['id'])
                if receipt:
                    if receipt.fingerprint != fingerprint:
                        raise ValueError('Packet identity was reused for different evidence')
                    return []
                session.add(DetectionReceipt(packet_id=p['id'], fingerprint=fingerprint))
                baseline = list(session.scalars(select(TrustedMapping).where(
                    TrustedMapping.interface == p['interface'], TrustedMapping.ip == p['senderIp'],
                    TrustedMapping.state == 'verified'))) if p['source'] == 'live' else []
                candidates = [] if late else evaluate(p, history, baseline, self.config, self.gateway_ids)
                for rule, severity, confidence, related, reason, expected, details in candidates:
                    key = (scope, rule, p['senderIp'], p['senderMac'], severity)
                    if p['_time'] - self.cooldowns.get(key, float('-inf')) < self.config.cooldown:
                        continue
                    ids = list(dict.fromkeys([x['id'] for x in related] + [p['id']]))
                    evidence = {'id': str(uuid4()), 'timestamp': p['timestamp'], 'source': p['source'],
                                'interface': p['interface'], 'sessionId': p['sessionId'], 'scope': scope,
                                'ruleId': rule, 'sourceIp': p['senderIp'], 'observedMac': p['senderMac'],
                                'expectedMac': expected[0] if expected else '', 'expectedMacs': expected,
                                'packetIds': ids[-64:], 'relatedPacketCount': len(ids),
                                'reason': reason, 'severity': severity, 'confidence': confidence,
                                'status': 'Unreviewed', 'classification': 'suspicious_observation',
                                'details': details, 'corroboratingRules': [x[0] for x in candidates if x[0] != rule]}
                    session.add(DetectionFinding(id=evidence['id'], timestamp=p['timestamp'], source=p['source'],
                                                scope=scope, rule_id=rule, severity=severity, payload=evidence))
                    session.flush()
                    alert, created = ensure_alert(session, session.get(DetectionFinding, evidence['id']))
                    if created:
                        alert_output.append(alert)
                    output.append(evidence)
                    cooldown_updates.append((key, p['_time']))
            # Update temporal state only after commit. Failed transactions are never represented as analyzed.
            if late:
                self.late += 1
            else:
                history.append(p)
                self.histories[scope] = deque(history[-self.config.history_capacity:], maxlen=self.config.history_capacity)
                self.histories.move_to_end(scope)
                while len(self.histories) > 8:
                    self.histories.popitem(last=False)
            for key, timestamp in cooldown_updates:
                self.cooldowns[key] = timestamp
                self.cooldowns.move_to_end(key)
            while len(self.cooldowns) > self.config.history_capacity:
                self.cooldowns.popitem(last=False)
        for finding in output:
            self.emit('detection_finding', {'version': 1, 'finding': finding})
        for alert in alert_output:
            self.emit('alert_created', {'version': 1, 'alert': alert, 'recovered': False})
        return output

    def findings(self, limit=100, offset=0, source='all', severity='all', q=''):
        conditions = []
        if source != 'all':
            conditions.append(DetectionFinding.source == source)
        if severity != 'all':
            conditions.append(DetectionFinding.severity == severity)
        if q:
            conditions.append(DetectionFinding.payload.cast(String).contains(q, autoescape=True))
        with self.database.transaction() as session:
            total = session.scalar(select(func.count()).select_from(DetectionFinding).where(*conditions))
            rows = session.scalars(select(DetectionFinding).where(*conditions).order_by(
                DetectionFinding.timestamp.desc(), DetectionFinding.id.desc()).limit(limit).offset(offset))
            return {'items': [row.payload for row in rows], 'total': total, 'limit': limit, 'offset': offset}
