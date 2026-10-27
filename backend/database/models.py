"""Observed claims, explicit trust, and immutable audit history are separate tables."""
from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ObservedMapping(Base):
    __tablename__ = 'observed_mappings'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ip: Mapped[str] = mapped_column(String(15))
    mac: Mapped[str] = mapped_column(String(17))
    source: Mapped[str] = mapped_column(String(8))
    scope: Mapped[str] = mapped_column(String(160))
    interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    last_session_id: Mapped[str] = mapped_column(String(128))
    __table_args__ = (
        UniqueConstraint('source', 'scope', 'ip', 'mac', name='uq_observed_scope_pair'),
        CheckConstraint("source IN ('live', 'offline')"),
        CheckConstraint("(source = 'live' AND interface IS NOT NULL) OR (source = 'offline' AND interface IS NULL)"),
        CheckConstraint('observation_count > 0'),
        Index('ix_observed_scope_ip', 'source', 'scope', 'ip'),
        Index('ix_observed_last_seen', 'last_seen', 'id'),
    )


class ObservationReceipt(Base):
    __tablename__ = 'observation_receipts'
    packet_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    mapping_id: Mapped[str] = mapped_column(ForeignKey('observed_mappings.id', ondelete='RESTRICT'), index=True)


class TrustedMapping(Base):
    __tablename__ = 'trusted_mappings'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ip: Mapped[str] = mapped_column(String(15))
    mac: Mapped[str] = mapped_column(String(17))
    interface: Mapped[str] = mapped_column(String(128))
    label: Mapped[str] = mapped_column(String(120), default='')
    state: Mapped[str] = mapped_column(String(12), default='pending')
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    verified_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (
        UniqueConstraint('interface', 'ip', 'mac', name='uq_trusted_interface_pair'),
        CheckConstraint("state IN ('pending', 'verified', 'revoked')"),
        CheckConstraint('version > 0'),
        Index('ix_trusted_interface_ip_state', 'interface', 'ip', 'state'),
    )


class TrustAudit(Base):
    __tablename__ = 'trust_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(ForeignKey('trusted_mappings.id', ondelete='RESTRICT'))
    action: Mapped[str] = mapped_column(String(12))
    actor: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(500))
    timestamp: Mapped[str] = mapped_column(String(40))
    before: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (Index('ix_audit_mapping_id', 'mapping_id', 'id'),)


class DetectionFinding(Base):
    __tablename__ = 'detection_findings'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    source: Mapped[str] = mapped_column(String(8))
    scope: Mapped[str] = mapped_column(String(300))
    rule_id: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(12))
    payload: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (
        CheckConstraint("source IN ('live', 'offline')"),
        Index('ix_finding_source_scope', 'source', 'scope'),
        Index('ix_finding_rule_severity', 'rule_id', 'severity'),
    )


class DetectionReceipt(Base):
    __tablename__ = 'detection_receipts'
    packet_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64))


class SecurityAlert(Base):
    __tablename__ = 'security_alerts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey('detection_findings.id', ondelete='RESTRICT'), unique=True)
    status: Mapped[str] = mapped_column(String(20), default='New')
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    updated_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (CheckConstraint("status IN ('New','Acknowledged','Investigating','Resolved')"),
                     CheckConstraint('version > 0'), Index('ix_alert_status_created', 'status', 'created_at'))


class AlertAudit(Base):
    __tablename__ = 'alert_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey('security_alerts.id', ondelete='RESTRICT'), index=True)
    actor: Mapped[str] = mapped_column(String(120))
    timestamp: Mapped[str] = mapped_column(String(40))
    previous_status: Mapped[str] = mapped_column(String(20))
    new_status: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(500))


class InvestigationIncident(Base):
    __tablename__ = 'investigation_incidents'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    correlation_key: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(String(1000))
    severity: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(20), default='Open')
    source: Mapped[str] = mapped_column(String(8))
    scope: Mapped[str] = mapped_column(String(300))
    interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str] = mapped_column(String(256))
    rule_id: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(15))
    observed_mac: Mapped[str] = mapped_column(String(17))
    expected_macs: Mapped[list] = mapped_column(JSON)
    first_detected: Mapped[str] = mapped_column(String(40))
    last_detected: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40), index=True)
    assigned_to: Mapped[str] = mapped_column(String(120), default='')
    resolution_notes: Mapped[str] = mapped_column(String(2000), default='')
    version: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (CheckConstraint("status IN ('Open','Investigating','Contained','Resolved','Closed')"),
                     CheckConstraint("source IN ('live','offline')"), CheckConstraint('version > 0'),
                     Index('ix_incident_source_status', 'source', 'status'))


class IncidentAlert(Base):
    __tablename__ = 'incident_alerts'
    alert_id: Mapped[str] = mapped_column(ForeignKey('security_alerts.id', ondelete='RESTRICT'), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey('investigation_incidents.id', ondelete='RESTRICT'), index=True)


class IncidentAudit(Base):
    __tablename__ = 'incident_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey('investigation_incidents.id', ondelete='RESTRICT'), index=True)
    actor: Mapped[str] = mapped_column(String(120))
    timestamp: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(500))
    previous_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    new_status: Mapped[str] = mapped_column(String(20))
    details: Mapped[dict] = mapped_column(JSON)


class AnalyticsObservation(Base):
    """Idempotent, passive ARP observations retained for aggregate analysis."""
    __tablename__ = 'analytics_observations'
    packet_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(8))
    interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timestamp: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(8))
    sender_ip: Mapped[str] = mapped_column(String(15))
    sender_mac: Mapped[str] = mapped_column(String(17))
    target_ip: Mapped[str] = mapped_column(String(15))
    target_mac: Mapped[str] = mapped_column(String(17))
    __table_args__ = (CheckConstraint("source IN ('live','offline')"),
                      CheckConstraint("operation IN ('Request','Reply')"),
                      CheckConstraint("(source = 'live' AND interface IS NOT NULL) OR (source = 'offline' AND interface IS NULL)"),
                      Index('ix_analytics_filter_time', 'source', 'session_id', 'timestamp'))


class ProtocolAnalyticsObservation(Base):
    """Metadata-only TCP, UDP, and DNS observations for protocol analytics."""
    __tablename__ = 'protocol_analytics_observations'
    packet_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(8))
    interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    protocol: Mapped[str] = mapped_column(String(3))
    timestamp: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(12))
    source_ip: Mapped[str] = mapped_column(String(45))
    destination_ip: Mapped[str] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    byte_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    query_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    query_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    response_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    transport: Mapped[str | None] = mapped_column(String(8), nullable=True)
    __table_args__ = (
        CheckConstraint("source IN ('live','offline')"),
        CheckConstraint("protocol IN ('TCP','UDP','DNS')"),
        CheckConstraint("(source = 'live' AND interface IS NOT NULL) OR (source = 'offline' AND interface IS NULL)"),
        CheckConstraint("operation IN ('Request','Reply','Packet','Query','Response')"),
        CheckConstraint('source_port IS NULL OR source_port BETWEEN 0 AND 65535'),
        CheckConstraint('destination_port IS NULL OR destination_port BETWEEN 0 AND 65535'),
        Index('ix_protocol_analytics_filter_time', 'protocol', 'source', 'session_id', 'timestamp'),
        Index('ix_protocol_analytics_destination_port', 'protocol', 'destination_port'),
    )


class AnalyticsSession(Base):
    __tablename__ = 'analytics_sessions'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(8))
    interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    ended_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class AnalyticsBaseline(Base):
    """Immutable analyst-approved robust feature snapshot for one completed session."""
    __tablename__ = 'analytics_baselines'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(8))
    created_at: Mapped[str] = mapped_column(String(40))
    created_by: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(500))
    sample_count: Mapped[int] = mapped_column(Integer)
    features: Mapped[dict] = mapped_column(JSON)
    method_version: Mapped[str] = mapped_column(String(32), default='robust-session-baseline-1.0')
    __table_args__ = (CheckConstraint("source IN ('live','offline')"), CheckConstraint('sample_count > 0'),
                      Index('ix_analytics_baseline_session', 'session_id', 'created_at'))


class AnalyticsBaselineAudit(Base):
    __tablename__ = 'analytics_baseline_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    baseline_id: Mapped[str] = mapped_column(ForeignKey('analytics_baselines.id', ondelete='RESTRICT'), index=True)
    action: Mapped[str] = mapped_column(String(20))
    actor: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(500))
    timestamp: Mapped[str] = mapped_column(String(40))
