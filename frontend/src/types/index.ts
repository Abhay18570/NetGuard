export interface Packet { id: string; sessionId: string; sequence: number; timestamp: string; interface: string | null; source: 'live' | 'offline'; senderIp: string; senderMac: string; targetIp: string; targetMac: string; operation: 'Request' | 'Reply'; status: 'Not analyzed' }
export interface Device { id: string; ip: string; mac: string; hostname: string; trusted: boolean; trustedMappingId: string | null; firstSeen: string; lastSeen: string; observationCount: number; interface: string | null; source: 'live' | 'offline'; scope: string; lastSessionId: string }
export interface Incident { id: string; timestamp: string; severity: 'Critical' | 'High' | 'Medium' | 'Low'; sourceIp: string; observedMac: string; expectedMac: string; reason: string; status: string }
export interface ActivityPoint { time: string; packets: number; suspicious: number }
export interface Snapshot { packets: Packet[]; devices: Device[]; deviceTotal: number; incidents: Incident[]; alerts: Incident[]; activity: ActivityPoint[] }
export interface Preferences { networkInterface: string; conflictThreshold: number; windowSeconds: number; refreshSeconds: number; notifications: boolean; autoRefresh: boolean }
export type ConnectionState = 'disconnected' | 'loading' | 'connected' | 'error'
export interface PacketEvent { version: 1; packet: Packet }
export interface StatusEvent { version: 1; status: MonitorStatus }
export interface NetworkInterface { index: number; name: string; networkName?: string; description?: string }
export type MonitorState = 'not_started' | 'starting' | 'running' | 'stopping' | 'stopped' | 'completed' | 'error'
export interface MonitorStatus { state: MonitorState; captureAvailable: boolean; interface: string | null; startedAt: string | null; reason: string; mode: 'live' | 'offline' | null; sessionId: string | null; error: { code: string; message: string } | null; revision: number; bufferCapacity: number }
export interface CollectionResponse<T> { items: T[]; total: number; limit: number; offset: number }
export interface WorkspaceResponse { data: Snapshot; monitor: MonitorStatus; interfaces: NetworkInterface[]; inventoryError: string }

export interface TrustedMapping { id: string; ip: string; mac: string; interface: string; source: 'live'; label: string; state: 'pending' | 'verified' | 'revoked'; createdAt: string; updatedAt: string; verifiedAt: string | null; revokedAt: string | null; version: number }
export interface TrustAudit { id: number; mappingId: string; action: string; actor: string; reason: string; timestamp: string; before: TrustedMapping | null; after: TrustedMapping }
export interface MappingEvidence { ip: string; source: 'live' | 'offline'; scope: string; interface: string | null; classification: 'unclassified'; reasons: string[]; observedMappings: Device[]; trustedMappings: TrustedMapping[] }
export interface DiscoveryStatus { state: 'ready' | 'degraded'; failedObservations: number; message: string | null }
