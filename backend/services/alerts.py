"""Finding-backed alerts with atomic, authorized, optimistic lifecycle changes."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import select, func, String, or_
from backend.database.models import SecurityAlert, AlertAudit, DetectionFinding
from backend.discovery.validation import require_text
from backend.errors import APIError

STATES = ('New', 'Acknowledged', 'Investigating', 'Resolved')
TRANSITIONS = {'New': ('Acknowledged', 'Investigating', 'Resolved'),
               'Acknowledged': ('Investigating', 'Resolved'), 'Investigating': ('Resolved',),
               'Resolved': ('Investigating',)}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def serialize(alert, finding):
    return {**finding.payload, 'id': alert.id, 'findingId': finding.id,
            'evidenceRef': f'/api/findings/{finding.id}', 'status': alert.status,
            'version': alert.version, 'createdAt': alert.created_at, 'updatedAt': alert.updated_at}


def ensure_alert(session, finding):
    existing = session.scalar(select(SecurityAlert).where(SecurityAlert.finding_id == finding.id))
    if existing:
        return serialize(existing, finding), False
    timestamp = now()
    alert = SecurityAlert(id=str(uuid4()), finding_id=finding.id, status='New', version=1,
                          created_at=timestamp, updated_at=timestamp)
    session.add(alert)
    session.flush()
    return serialize(alert, finding), True


class AlertService:
    def __init__(self, database, emit):
        self.database, self.emit = database, emit

    def reconcile(self):
        # Bounded, idempotent recovery for genuine pre-Phase-6 findings, never synthetic records.
        events = []
        with self.database.transaction(write=True) as session:
            missing = list(session.scalars(select(DetectionFinding).where(~select(SecurityAlert.id).where(
                SecurityAlert.finding_id == DetectionFinding.id).exists()).order_by(DetectionFinding.timestamp).limit(100)))
            for finding in missing:
                value, created = ensure_alert(session, finding)
                if created:
                    events.append(value)
        for value in events:
            self.emit('alert_created', {'version': 1, 'alert': value, 'recovered': True})

    def page(self, limit=100, offset=0, source='all', severity='all', status='all', q=''):
        self.reconcile()
        conditions = []
        if source != 'all': conditions.append(DetectionFinding.source == source)
        if severity != 'all': conditions.append(DetectionFinding.severity == severity)
        if status != 'all': conditions.append(SecurityAlert.status == status)
        if q: conditions.append(or_(SecurityAlert.id.contains(q, autoescape=True), DetectionFinding.payload.cast(String).contains(q, autoescape=True)))
        with self.database.transaction() as session:
            query = select(SecurityAlert, DetectionFinding).join(DetectionFinding)
            total = session.scalar(select(func.count()).select_from(SecurityAlert).join(DetectionFinding).where(*conditions))
            rows = session.execute(query.where(*conditions).order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc()).limit(limit).offset(offset))
            return {'items': [serialize(a, f) for a, f in rows], 'total': total, 'limit': limit, 'offset': offset}

    def counts(self):
        self.reconcile()
        with self.database.transaction() as session:
            rows = session.execute(select(DetectionFinding.source, SecurityAlert.status, func.count()).select_from(SecurityAlert).join(DetectionFinding).group_by(DetectionFinding.source, SecurityAlert.status))
            counts = {source: {state: 0 for state in STATES} for source in ('live', 'offline')}
            for source, state, count in rows:
                counts[source][state] = count
            pending = session.scalar(select(func.count()).select_from(DetectionFinding).where(~select(SecurityAlert.id).where(SecurityAlert.finding_id == DetectionFinding.id).exists()))
            return {'counts': counts, 'pendingFindings': pending, 'delivery': 'best_effort_socket_rest_recovery'}

    def detail(self, alert_id):
        with self.database.transaction() as session:
            alert = session.get(SecurityAlert, alert_id)
            if not alert: raise APIError('alert_not_found', 'Alert not found.', 404)
            return serialize(alert, session.get(DetectionFinding, alert.finding_id))

    def change(self, alert_id, body, actor):
        state, version = body.get('status'), body.get('version')
        reason = require_text(body.get('reason'), 'reason')
        if state not in STATES or type(version) is not int or version < 1:
            raise APIError('invalid_body', 'Use a valid status and positive integer version.')
        with self.database.transaction(write=True) as session:
            alert = session.get(SecurityAlert, alert_id)
            if not alert: raise APIError('alert_not_found', 'Alert not found.', 404)
            if alert.version != version: raise APIError('stale_version', 'Alert changed. Refresh before updating.', 409)
            if state not in TRANSITIONS[alert.status]: raise APIError('invalid_transition', 'This alert status transition is not allowed.', 409)
            timestamp = now()
            session.add(AlertAudit(alert_id=alert.id, actor=actor, timestamp=timestamp,
                                   previous_status=alert.status, new_status=state, reason=reason))
            alert.status, alert.updated_at, alert.version = state, timestamp, alert.version + 1
            result = serialize(alert, session.get(DetectionFinding, alert.finding_id))
        self.emit('alert_updated', {'version': 1, 'alert': result})
        return result

    def audit(self, alert_id, limit=100, offset=0):
        self.detail(alert_id)
        with self.database.transaction() as session:
            condition = AlertAudit.alert_id == alert_id
            rows = session.scalars(select(AlertAudit).where(condition).order_by(AlertAudit.id.desc()).limit(limit).offset(offset))
            return {'items': [{'id': r.id, 'alertId': r.alert_id, 'actor': r.actor, 'timestamp': r.timestamp,
                               'previousStatus': r.previous_status, 'newStatus': r.new_status, 'reason': r.reason} for r in rows],
                    'total': session.scalar(select(func.count()).select_from(AlertAudit).where(condition)), 'limit': limit, 'offset': offset}
