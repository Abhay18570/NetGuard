"""Passive sender observations and explicit, independently audited live trust."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import logging
from threading import RLock
from uuid import uuid4
from sqlalchemy import and_, case, distinct, func, or_, select, text
from backend.database.models import ObservedMapping, ObservationReceipt, TrustedMapping, TrustAudit
from backend.discovery.interfaces import discover_interfaces
from backend.discovery.validation import normalize_ip, normalize_mac, require_text, utc_timestamp
from backend.errors import APIError

logger = logging.getLogger(__name__)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def trusted_json(row):
    return {'id': row.id, 'ip': row.ip, 'mac': row.mac, 'interface': row.interface,
            'source': 'live', 'label': row.label, 'state': row.state,
            'createdAt': row.created_at, 'updatedAt': row.updated_at,
            'verifiedAt': row.verified_at, 'revokedAt': row.revoked_at, 'version': row.version}


def audit_json(row):
    return {'id': row.id, 'mappingId': row.mapping_id, 'action': row.action,
            'actor': row.actor, 'reason': row.reason, 'timestamp': row.timestamp,
            'before': row.before, 'after': row.after}


class InventoryService:
    def __init__(self, database, emit):
        self.db, self.emit = database, emit
        self.lock = RLock()
        self.failed_observations = 0
        self.last_error = None

    def _device(self, session, row):
        trusted = None
        if row.source == 'live':
            trusted = session.scalar(select(TrustedMapping).where(
                TrustedMapping.interface == row.interface, TrustedMapping.ip == row.ip,
                TrustedMapping.mac == row.mac, TrustedMapping.state == 'verified'))
        return {'id': row.id, 'ip': row.ip, 'mac': row.mac, 'hostname': '',
                'trusted': trusted is not None, 'trustedMappingId': trusted.id if trusted else None,
                'firstSeen': row.first_seen, 'lastSeen': row.last_seen,
                'observationCount': row.observation_count, 'interface': row.interface,
                'source': row.source, 'scope': row.scope, 'lastSessionId': row.last_session_id}

    def observe(self, packet):
        # Only the sender asserts ownership. Request targets, zero-IP probes,
        # multicast/broadcast/zero MACs and invalid addresses do not create devices.
        try:
            ip, mac = normalize_ip(packet['senderIp']), normalize_mac(packet['senderMac'])
            timestamp = utc_timestamp(packet['timestamp'])
            source, interface, session_id, packet_id = packet['source'], packet['interface'], packet['sessionId'], packet['id']
            if source not in ('live', 'offline') or not isinstance(session_id, str) or not 1 <= len(session_id) <= 128:
                return None
            if not isinstance(packet_id, str) or not 1 <= len(packet_id) <= 256:
                return None
            if source == 'live' and (not isinstance(interface, str) or not 1 <= len(interface) <= 128):
                return None
            if source == 'offline' and interface is not None:
                return None
        except (KeyError, TypeError, ValueError):
            return None
        scope = f'live:{interface}' if source == 'live' else f'offline:{session_id}'
        fingerprint = sha256(json.dumps([scope, ip, mac, timestamp], separators=(',', ':')).encode()).hexdigest()
        with self.lock:
            with self.db.transaction(write=True) as session:
                receipt = session.get(ObservationReceipt, packet_id)
                if receipt:
                    if receipt.fingerprint != fingerprint:
                        raise APIError('observation_id_conflict', 'Packet identity was reused with different observation data.', 409)
                    return None
                row = session.scalar(select(ObservedMapping).where(
                    ObservedMapping.source == source, ObservedMapping.scope == scope,
                    ObservedMapping.ip == ip, ObservedMapping.mac == mac))
                created = row is None
                if created:
                    row = ObservedMapping(id=str(uuid4()), ip=ip, mac=mac, source=source, scope=scope,
                                          interface=interface, first_seen=timestamp, last_seen=timestamp,
                                          observation_count=1, last_session_id=session_id)
                    session.add(row)
                    session.flush()
                else:
                    row.first_seen = min(row.first_seen, timestamp)
                    row.last_seen = max(row.last_seen, timestamp)
                    row.observation_count += 1
                    row.last_session_id = session_id
                session.add(ObservationReceipt(packet_id=packet_id, fingerprint=fingerprint, mapping_id=row.id))
                device = self._device(session, row)
            # Commit precedes publication; a failed write never emits a discovery.
            self.emit('device_discovered' if created else 'device_updated', {'version': 1, 'device': device})
            return device

    def ingest(self, packet):
        try:
            self.observe(packet)
        except Exception:
            logger.exception('Device observation could not be persisted')
            with self.lock:
                self.failed_observations += 1
                self.last_error = 'Some observations could not be persisted. Packet capture continues; inventory may be incomplete.'
                self.emit('discovery_status', {'version': 1, 'status': self.status(check=False)})

    def status(self, check=True):
        with self.lock:
            if check:
                with self.db.transaction() as session:
                    session.execute(text('SELECT 1'))
            return {'state': 'degraded' if self.failed_observations else 'ready',
                    'failedObservations': self.failed_observations, 'message': self.last_error}

    def devices(self, limit, offset, query='', source='all', trusted=False):
        o, t = ObservedMapping, TrustedMapping
        filters = []
        if source != 'all':
            filters.append(o.source == source)
        if query:
            filters.append(or_(o.ip.contains(query, autoescape=True), o.mac.contains(query.lower(), autoescape=True)))
        if trusted:
            filters.append(and_(o.source == 'live', select(t.id).where(t.interface == o.interface, t.ip == o.ip, t.mac == o.mac, t.state == 'verified').correlate(o).exists()))
        with self.db.transaction() as session:
            total = session.scalar(select(func.count()).select_from(o).where(*filters))
            rows = session.scalars(select(o).where(*filters).order_by(o.last_seen.desc(), o.id).offset(offset).limit(limit)).all()
            return {'items': [self._device(session, row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    def trusted(self, limit, offset, state='all'):
        filters = [] if state == 'all' else [TrustedMapping.state == state]
        with self.db.transaction() as session:
            total = session.scalar(select(func.count()).select_from(TrustedMapping).where(*filters))
            rows = session.scalars(select(TrustedMapping).where(*filters).order_by(TrustedMapping.updated_at.desc(), TrustedMapping.id).offset(offset).limit(limit)).all()
            return {'items': [trusted_json(row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    def _get(self, session, mapping_id):
        row = session.get(TrustedMapping, mapping_id)
        if row is None:
            raise APIError('mapping_not_found', 'Trusted mapping was not found.', 404)
        return row

    def get_trusted(self, mapping_id):
        with self.db.transaction() as session:
            return trusted_json(self._get(session, mapping_id))

    def audit(self, mapping_id, limit, offset):
        with self.db.transaction() as session:
            self._get(session, mapping_id)
            where = TrustAudit.mapping_id == mapping_id
            total = session.scalar(select(func.count()).select_from(TrustAudit).where(where))
            rows = session.scalars(select(TrustAudit).where(where).order_by(TrustAudit.id.desc()).offset(offset).limit(limit)).all()
            return {'items': [audit_json(row) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    def _fields(self, body, row=None):
        try:
            ip = normalize_ip(body.get('ip', row.ip if row else None))
            mac = normalize_mac(body.get('mac', row.mac if row else None))
        except ValueError as error:
            raise APIError('invalid_address', str(error)) from error
        interface = require_text(body.get('interface', row.interface if row else None), 'interface', 128)
        if row is None or 'interface' in body:
            if interface not in {item['name'] for item in discover_interfaces()}:
                raise APIError('invalid_interface', 'Choose a currently discovered local interface.')
        label = body.get('label', row.label if row else '')
        if not isinstance(label, str) or len(label) > 120:
            raise APIError('invalid_body', 'label must be text of at most 120 characters.')
        return ip, mac, interface, label.strip()

    def change_trust(self, action, body, actor, mapping_id=None):
        reason = require_text(body.get('reason'), 'reason')
        with self.lock:
            with self.db.transaction(write=True) as session:
                before = None
                timestamp = now()
                if action == 'create':
                    ip, mac, interface, label = self._fields(body)
                    row = TrustedMapping(id=str(uuid4()), ip=ip, mac=mac, interface=interface,
                                         label=label, state='pending', created_at=timestamp,
                                         updated_at=timestamp, version=1)
                    session.add(row)
                else:
                    row = self._get(session, mapping_id)
                    version = body.get('version')
                    if type(version) is not int or version < 1:
                        raise APIError('invalid_version', 'Supply the current positive integer version.')
                    if version != row.version:
                        raise APIError('stale_version', 'The mapping changed. Refresh it before making another change.', 409)
                    before = trusted_json(row)
                    if action == 'update':
                        if not any(field in body for field in ('ip', 'mac', 'interface', 'label')):
                            raise APIError('invalid_body', 'Supply at least one mapping field to update.')
                        ip, mac, interface, label = self._fields(body, row)
                        if (ip, mac, interface) != (row.ip, row.mac, row.interface) or row.state == 'revoked':
                            row.state, row.verified_at, row.revoked_at = 'pending', None, None
                        row.ip, row.mac, row.interface, row.label = ip, mac, interface, label
                    elif action == 'verify':
                        if row.state == 'revoked':
                            raise APIError('mapping_revoked', 'Update the revoked mapping before verifying it again.', 409)
                        if row.state == 'verified':
                            return trusted_json(row)
                        if row.interface not in {item['name'] for item in discover_interfaces()}:
                            raise APIError('invalid_interface', 'The mapping interface is not currently available.')
                        row.state, row.verified_at = 'verified', timestamp
                    elif action == 'revoke':
                        if row.state == 'revoked':
                            return trusted_json(row)
                        row.state, row.revoked_at = 'revoked', timestamp
                    row.version += 1
                    row.updated_at = timestamp
                session.flush()
                after = trusted_json(row)
                session.add(TrustAudit(mapping_id=row.id, action=action, actor=actor, reason=reason,
                                       timestamp=timestamp, before=before, after=after))
            self.emit('trusted_mapping_updated', {'version': 1, 'action': action, 'mapping': after})
            return after

    def conflicts(self, limit, offset):
        o, t = ObservedMapping, TrustedMapping
        any_trust = select(t.id).where(t.interface == o.interface, t.ip == o.ip, t.state == 'verified').correlate(o).exists()
        matching_trust = select(t.id).where(t.interface == o.interface, t.ip == o.ip, t.mac == o.mac, t.state == 'verified').correlate(o).exists()
        mismatch = and_(o.source == 'live', any_trust, ~matching_trust)
        groups = select(o.source, o.scope, o.interface, o.ip).group_by(o.source, o.scope, o.interface, o.ip).having(
            or_(func.count(distinct(o.mac)) > 1, func.max(case((mismatch, 1), else_=0)) == 1))
        with self.db.transaction() as session:
            total = session.scalar(select(func.count()).select_from(groups.subquery()))
            candidates = session.execute(groups.order_by(o.source, o.scope, o.ip).offset(offset).limit(limit)).all()
            items = []
            for source, scope, interface, ip in candidates:
                observations = session.scalars(select(o).where(o.source == source, o.scope == scope, o.ip == ip).order_by(o.mac)).all()
                trusted = session.scalars(select(t).where(t.interface == interface, t.ip == ip, t.state == 'verified').order_by(t.mac)).all() if source == 'live' else []
                reasons = []
                if len(observations) > 1:
                    reasons.append('multiple_observed_macs')
                if trusted and {row.mac for row in observations} - {row.mac for row in trusted}:
                    reasons.append('differs_from_verified_mapping')
                items.append({'ip': ip, 'source': source, 'scope': scope, 'interface': interface,
                              'classification': 'unclassified', 'reasons': reasons,
                              'observedMappings': [self._device(session, row) for row in observations],
                              'trustedMappings': [trusted_json(row) for row in trusted]})
            return {'items': items, 'total': total, 'limit': limit, 'offset': offset}
