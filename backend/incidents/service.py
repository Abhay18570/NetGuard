"""Bounded, idempotent correlation of persisted alerts plus audited investigation."""
from datetime import datetime, timedelta, timezone
from threading import RLock, Thread
from uuid import uuid4
import logging
from sqlalchemy import select, func, or_, String
from backend.database.models import InvestigationIncident as Incident, IncidentAlert, IncidentAudit, SecurityAlert, DetectionFinding, TrustedMapping
from backend.services.alerts import now, serialize as alert_json
from backend.discovery.validation import require_text, utc_timestamp
from backend.errors import APIError
from backend.incidents.policy import IncidentLimits, STATES, TRANSITIONS, SEVERITIES, RECOMMENDATIONS, correlation_key

logger = logging.getLogger(__name__)


def audit_json(row):
    return {'id': row.id, 'incidentId': row.incident_id, 'actor': row.actor, 'timestamp': row.timestamp,
            'action': row.action, 'reason': row.reason, 'previousStatus': row.previous_status,
            'newStatus': row.new_status, 'details': row.details}


class IncidentService:
    def __init__(self, database, emit, config=None, gateway_ids=()):
        self.database, self.emit = database, emit
        self.limits = IncidentLimits(**(config or {}))
        self.gateway_ids = tuple(gateway_ids)
        self.worker_lock = RLock()
        self.worker = None
        self.requested = False
        self.closed = False
        self.failure_count = 0
        self.capacity_message = None

    def enqueue(self):
        # A coalesced wakeup, not a per-alert payload queue. Durable backlog is queried from SQLite.
        with self.worker_lock:
            if self.closed: return
            self.requested = True
            if self.worker is None:
                self.worker = Thread(target=self._run, daemon=True, name='netguard-incidents')
                self.worker.start()

    def _run(self):
        while True:
            with self.worker_lock:
                if self.closed or not self.requested:
                    self.worker = None
                    return
                self.requested = False
            try:
                if self.reconcile() == 100:
                    with self.worker_lock: self.requested = True
            except Exception:
                self.failure_count += 1
                logger.exception('Incident correlation failed; alerts remain available for REST recovery')

    def drain(self):
        while True:
            with self.worker_lock:
                worker = self.worker
            if worker is None: return
            worker.join(timeout=5)
            if worker.is_alive(): raise TimeoutError('Incident worker did not finish within five seconds')

    def close(self):
        with self.worker_lock:
            self.closed = True
            worker = self.worker
        if worker: worker.join(timeout=5)

    @staticmethod
    def _get(session, incident_id):
        row = session.get(Incident, incident_id)
        if not row: raise APIError('incident_not_found', 'Incident not found.', 404)
        return row

    @staticmethod
    def _counts(session):
        return {name: session.scalar(select(func.count()).select_from(model)) for name, model in
                (('incidents', Incident), ('links', IncidentAlert), ('audit', IncidentAudit))}

    def _audit_room(self, session, row, counts=None):
        total = counts['audit'] if counts else session.scalar(select(func.count()).select_from(IncidentAudit))
        local = session.scalar(select(func.count()).select_from(IncidentAudit).where(IncidentAudit.incident_id == row.id))
        if total >= self.limits.max_audit or local >= self.limits.audit_per_incident:
            raise APIError('incident_capacity', 'Incident audit capacity reached. No data was deleted; export/review storage limits.', 503)

    def _json(self, session, row):
        references = session.execute(select(SecurityAlert.id, SecurityAlert.finding_id).join(IncidentAlert, IncidentAlert.alert_id == SecurityAlert.id).where(IncidentAlert.incident_id == row.id).order_by(SecurityAlert.id)).all()
        return {'id': row.id, 'title': row.title, 'description': row.description, 'severity': row.severity,
                'status': row.status, 'firstDetected': row.first_detected, 'lastDetected': row.last_detected,
                'createdAt': row.created_at, 'updatedAt': row.updated_at, 'assignedTo': row.assigned_to,
                'resolutionNotes': row.resolution_notes, 'version': row.version, 'source': row.source,
                'interface': row.interface, 'sessionId': row.session_id, 'scope': row.scope, 'ruleId': row.rule_id,
                'sourceIp': row.source_ip, 'observedMac': row.observed_mac, 'expectedMacs': row.expected_macs,
                'alertIds': [a for a, _ in references], 'findingIds': [f for _, f in references],
                'classification': 'suspicious_observation', 'containment': 'administrator_report_only',
                # Retain Phase 1 collection shape used by the shared workspace adapter.
                'timestamp': row.first_detected, 'expectedMac': row.expected_macs[0] if row.expected_macs else '', 'reason': row.description}

    def reconcile(self):
        events = []
        with self.database.transaction(write=True) as session:
            pairs = session.execute(select(SecurityAlert, DetectionFinding).join(DetectionFinding).where(
                ~select(IncidentAlert.alert_id).where(IncidentAlert.alert_id == SecurityAlert.id).exists())
                .order_by(DetectionFinding.timestamp, SecurityAlert.id).limit(100)).all()
            counts = self._counts(session)
            self.capacity_message = None
            for alert, finding in pairs:
                if counts['links'] >= self.limits.max_links or counts['audit'] >= self.limits.max_audit:
                    self.capacity_message = 'Incident link or audit limit reached; unlinked alerts remain persisted.'
                    break
                p = finding.payload
                timestamp = utc_timestamp(p['timestamp'])
                point = datetime.fromisoformat(timestamp)
                key = correlation_key(finding)
                low = (point - timedelta(seconds=self.limits.window_seconds)).isoformat(timespec='microseconds')
                high = (point + timedelta(seconds=self.limits.window_seconds)).isoformat(timespec='microseconds')
                candidates = session.scalars(select(Incident).where(Incident.correlation_key == key,
                    Incident.status.in_(('Open', 'Investigating')), Incident.first_detected >= low,
                    Incident.last_detected <= high).order_by(Incident.first_detected, Incident.id)).all()
                row = None
                for candidate in candidates:
                    first = min(datetime.fromisoformat(candidate.first_detected), point)
                    last = max(datetime.fromisoformat(candidate.last_detected), point)
                    if (last - first).total_seconds() > self.limits.window_seconds:
                        continue
                    links = session.scalar(select(func.count()).select_from(IncidentAlert).where(IncidentAlert.incident_id == candidate.id))
                    audits = session.scalar(select(func.count()).select_from(IncidentAudit).where(IncidentAudit.incident_id == candidate.id))
                    if links < self.limits.links_per_incident and audits < self.limits.audit_per_incident:
                        row = candidate
                        break
                created = row is None
                if created:
                    if counts['incidents'] >= self.limits.max_incidents:
                        self.capacity_message = 'Incident record limit reached; unlinked alerts remain persisted.'
                        break
                    row = Incident(id=str(uuid4()), correlation_key=key, title=f"{p['ruleId']} · {p['sourceIp']}",
                        description=p['reason'], severity=p['severity'], status='Open', source=p['source'], scope=p['scope'],
                        interface=p['interface'], session_id=p['sessionId'], rule_id=p['ruleId'], source_ip=p['sourceIp'],
                        observed_mac=p['observedMac'], expected_macs=p['expectedMacs'], first_detected=timestamp,
                        last_detected=timestamp, created_at=now(), updated_at=now(), assigned_to='', resolution_notes='', version=1)
                    session.add(row); session.flush(); counts['incidents'] += 1
                else:
                    row.first_detected = min(row.first_detected, timestamp)
                    row.last_detected = max(row.last_detected, timestamp)
                    row.severity = max((row.severity, p['severity']), key=SEVERITIES.get)
                    row.updated_at = now(); row.version += 1
                session.add(IncidentAlert(alert_id=alert.id, incident_id=row.id))
                session.add(IncidentAudit(incident_id=row.id, actor='system:correlation', timestamp=now(),
                    action='created' if created else 'alert_linked', reason='Correlated persisted suspicious evidence; not a confirmed attack.',
                    previous_status=None if created else row.status, new_status=row.status,
                    details={'alertId': alert.id, 'findingId': finding.id, 'windowSeconds': self.limits.window_seconds}))
                session.flush()
                counts['links'] += 1; counts['audit'] += 1
                events.append(('incident_created' if created else 'incident_updated', self._json(session, row)))
        for event, item in events:
            self.emit(event, {'version': 1, 'incident': item})
        return len(events)

    def page(self, limit=100, offset=0, source='all', severity='all', status='all', q=''):
        self.reconcile()
        conditions = []
        if source != 'all': conditions.append(Incident.source == source)
        if severity != 'all': conditions.append(Incident.severity == severity)
        if status != 'all': conditions.append(Incident.status == status)
        if q: conditions.append(or_(*(field.contains(q, autoescape=True) for field in
            (Incident.id, Incident.title, Incident.description, Incident.source_ip, Incident.observed_mac, Incident.expected_macs.cast(String), Incident.assigned_to, Incident.resolution_notes))))
        with self.database.transaction() as session:
            total = session.scalar(select(func.count()).select_from(Incident).where(*conditions))
            rows = session.scalars(select(Incident).where(*conditions).order_by(Incident.updated_at.desc(), Incident.id.desc()).limit(limit).offset(offset))
            return {'items': [self._json(session, row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    def _detail(self, session, row):
        value = self._json(session, row)
        pairs = session.execute(select(SecurityAlert, DetectionFinding).join(DetectionFinding).join(IncidentAlert, IncidentAlert.alert_id == SecurityAlert.id).where(IncidentAlert.incident_id == row.id).order_by(DetectionFinding.timestamp, SecurityAlert.id))
        value['alerts'] = [alert_json(a, f) for a, f in pairs]
        value['packetIds'] = list(dict.fromkeys(pid for alert in value['alerts'] for pid in alert['packetIds']))
        value['observedMappings'] = [{'ip': alert['sourceIp'], 'mac': alert['observedMac'], 'expectedMacs': alert['expectedMacs'], 'findingId': alert['findingId']} for alert in value['alerts']]
        latest_actions = {}
        actions = session.scalars(select(IncidentAudit).where(IncidentAudit.incident_id == row.id,
            IncidentAudit.action == 'external_action').order_by(IncidentAudit.id))
        for action in actions:
            latest_actions[action.details['actionId']] = {'actionId': action.details['actionId'], 'actor': action.actor,
                'performedAt': action.details['performedAt'], 'description': action.details['description'], 'timestamp': action.timestamp}
        value['completedActions'] = list(latest_actions.values())
        return value

    def detail(self, incident_id):
        with self.database.transaction() as session:
            return self._detail(session, self._get(session, incident_id))

    def audit(self, incident_id, limit=100, offset=0):
        with self.database.transaction() as session:
            self._get(session, incident_id)
            query = IncidentAudit.incident_id == incident_id
            rows = session.scalars(select(IncidentAudit).where(query).order_by(IncidentAudit.id.desc()).limit(limit).offset(offset))
            return {'items': [audit_json(row) for row in rows], 'total': session.scalar(select(func.count()).select_from(IncidentAudit).where(query)), 'limit': limit, 'offset': offset}

    def change(self, incident_id, body, actor, action=False):
        reason = require_text(body.get('reason'), 'reason')
        version = body.get('version')
        if type(version) is not int or version < 1: raise APIError('invalid_body', 'Supply a positive integer version.')
        with self.database.transaction(write=True) as session:
            row = self._get(session, incident_id)
            if row.version != version: raise APIError('stale_version', 'Incident changed. Refresh before updating.', 409)
            self._audit_room(session, row)
            previous = row.status
            details = {'source': row.source, 'sessionId': row.session_id, 'administrativeOnly': True}
            if action:
                action_id = body.get('actionId')
                if action_id not in [r['id'] for r in RECOMMENDATIONS] or body.get('confirmed') is not True:
                    raise APIError('invalid_action', 'Choose a checklist action and explicitly confirm that it was completed.')
                description = require_text(body.get('description'), 'description', 2000)
                try: performed = utc_timestamp(body.get('performedAt'))
                except (ValueError, TypeError): raise APIError('invalid_body', 'performedAt must be a timezone-aware ISO timestamp.')
                if datetime.fromisoformat(performed) > datetime.now(timezone.utc): raise APIError('invalid_body', 'An external action cannot be reported in the future.')
                details.update(actionId=action_id, description=description, performedAt=performed, confirmed=True)
                audit_action = 'external_action'
            else:
                if not any(k in body for k in ('status', 'assignedTo', 'resolutionNotes')): raise APIError('invalid_body', 'Supply a status, assignment, or resolution notes change.')
                if 'assignedTo' in body:
                    if not isinstance(body['assignedTo'], str) or len(body['assignedTo']) > 120: raise APIError('invalid_body', 'assignedTo must be text up to 120 characters.')
                    details['previousAssignee'] = row.assigned_to; row.assigned_to = body['assignedTo'].strip(); details['assignedTo'] = row.assigned_to
                if 'resolutionNotes' in body:
                    if not isinstance(body['resolutionNotes'], str) or len(body['resolutionNotes']) > 2000: raise APIError('invalid_body', 'resolutionNotes must be text up to 2000 characters.')
                    details['previousResolutionNotes'] = row.resolution_notes; row.resolution_notes = body['resolutionNotes'].strip(); details['resolutionNotes'] = row.resolution_notes
                if 'status' in body:
                    state = body['status']
                    if state not in STATES: raise APIError('invalid_body', 'Unknown incident status.')
                    if state not in TRANSITIONS[row.status]: raise APIError('invalid_transition', 'This incident transition is not allowed.', 409)
                    if state == 'Contained':
                        if body.get('containmentConfirmed') is not True: raise APIError('containment_confirmation_required', 'Explicit confirmation of a completed external containment action is required.')
                        details.update(containmentConfirmed=True, externalAction=require_text(body.get('externalAction'), 'externalAction', 2000), verification='administrator_report_not_verified_by_netguard')
                    elif 'containmentConfirmed' in body or 'externalAction' in body:
                        raise APIError('invalid_body', 'Containment fields are only accepted with a Contained transition.')
                    if state in ('Resolved', 'Closed') and not row.resolution_notes: raise APIError('resolution_notes_required', 'Resolution notes are required before resolving or closing.')
                    row.status = state
                elif 'containmentConfirmed' in body or 'externalAction' in body:
                    raise APIError('invalid_body', 'Containment fields require a Contained transition.')
                if row.status in ('Resolved', 'Closed') and not row.resolution_notes:
                    raise APIError('resolution_notes_required', 'Resolved and closed incidents must retain resolution notes.')
                audit_action = 'status_changed' if previous != row.status else 'metadata_updated'
            row.version += 1; row.updated_at = now()
            session.add(IncidentAudit(incident_id=row.id, actor=actor, timestamp=row.updated_at, action=audit_action,
                reason=reason, previous_status=previous, new_status=row.status, details=details))
            result = self._json(session, row)
        self.emit('incident_updated', {'version': 1, 'incident': result})
        return result

    def export(self, incident_id):
        with self.database.transaction() as session:
            row = self._get(session, incident_id)
            return {'schemaVersion': 1, 'exportedAt': now(), 'incident': self._detail(session, row),
                    'timeline': [audit_json(r) for r in session.scalars(select(IncidentAudit).where(IncidentAudit.incident_id == row.id).order_by(IncidentAudit.id))],
                    'notice': 'Suspicious evidence and administrator-reported external actions; no network actions performed by NetGuard.'}

    def summary(self):
        self.reconcile()
        with self.database.transaction() as session:
            counts = {source: {state: 0 for state in STATES} for source in ('live', 'offline')}
            for source, status, count in session.execute(select(Incident.source, Incident.status, func.count()).group_by(Incident.source, Incident.status)):
                counts[source][status] = count
            pending = session.scalar(select(func.count()).select_from(SecurityAlert).where(~select(IncidentAlert.alert_id).where(IncidentAlert.alert_id == SecurityAlert.id).exists()))
            gateways = []
            for mapping_id in self.gateway_ids:
                mapping = session.get(TrustedMapping, mapping_id)
                gateways.append({'mappingId': mapping_id, 'state': mapping.state if mapping else 'missing',
                    'ip': mapping.ip if mapping else None, 'mac': mapping.mac if mapping else None, 'interface': mapping.interface if mapping else None})
            usage = self._counts(session)
            verified = session.scalar(select(func.count()).select_from(TrustedMapping).where(TrustedMapping.state == 'verified'))
        return {'counts': counts, 'pendingAlerts': pending, 'capacityMessage': self.capacity_message,
                'failedAttempts': self.failure_count, 'limits': vars(self.limits), 'usage': usage,
                'gatewayBaselines': gateways, 'verifiedMappingCount': verified, 'recommendations': RECOMMENDATIONS,
                'advisoryOnly': True, 'storage': self.database.storage_status()}
