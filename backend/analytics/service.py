from datetime import datetime, timezone
from queue import Queue, Full, Empty
from threading import Thread
import logging
from uuid import uuid4
from statistics import median
from sqlalchemy import select, func, union, case
from backend.database.models import AnalyticsObservation, AnalyticsSession, AnalyticsBaseline, AnalyticsBaselineAudit, DetectionFinding

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
