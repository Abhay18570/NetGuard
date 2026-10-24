import axios from 'axios'
import type { Device, Incident, MonitorStatus, NetworkInterface, Packet, PacketEvent, StatusEvent, Snapshot, WorkspaceResponse, TrustedMapping, TrustAudit, MappingEvidence, DiscoveryStatus, CollectionResponse } from '../types'
export const emptySnapshot: Snapshot = { packets: [], devices: [], deviceTotal: 0, incidents: [], alerts: [], activity: [] }
const client = axios.create({ baseURL: '/api', timeout: 8000 })
type RecordValue = Record<string, unknown>
function record(value: unknown): value is RecordValue { return !!value && typeof value === 'object' && !Array.isArray(value) }
function strings(value: RecordValue, keys: string[]) { return keys.every(key => typeof value[key] === 'string') }
function integer(value: unknown): value is number { return Number.isInteger(value) && Number(value) >= 0 }
export const isPacket = (value: unknown): value is Packet => record(value) && strings(value, ['id', 'sessionId', 'timestamp', 'senderIp', 'senderMac', 'targetIp', 'targetMac']) && integer(value.sequence) && value.sequence > 0 && ['Request', 'Reply', 'Packet', 'Query', 'Response'].includes(String(value.operation)) && ['live', 'offline'].includes(String(value.source)) && (value.source === 'offline' ? value.interface === null : typeof value.interface === 'string' && value.interface.length > 0) && value.status === 'Not analyzed'
export const isDevice = (value: unknown): value is Device => record(value) && strings(value, ['id', 'ip', 'mac', 'hostname', 'firstSeen', 'lastSeen', 'scope', 'lastSessionId']) && typeof value.trusted === 'boolean'
  && integer(value.observationCount) && value.observationCount > 0 && (value.trustedMappingId === null || typeof value.trustedMappingId === 'string')
  && (value.source === 'live' ? typeof value.interface === 'string' : value.source === 'offline' && value.interface === null && !value.trusted && value.trustedMappingId === null)
export const isTrustedMapping = (value: unknown): value is TrustedMapping => record(value) && strings(value, ['id', 'ip', 'mac', 'interface', 'label', 'createdAt', 'updatedAt']) && value.source === 'live'
  && ['pending', 'verified', 'revoked'].includes(String(value.state)) && integer(value.version) && value.version > 0
  && (value.verifiedAt === null || typeof value.verifiedAt === 'string') && (value.revokedAt === null || typeof value.revokedAt === 'string')
  && (value.state !== 'verified' || typeof value.verifiedAt === 'string') && (value.state !== 'revoked' || typeof value.revokedAt === 'string')
const isAudit = (value: unknown): value is TrustAudit => record(value) && integer(value.id) && strings(value, ['mappingId', 'action', 'actor', 'reason', 'timestamp']) && (value.before === null || isTrustedMapping(value.before)) && isTrustedMapping(value.after)
const isEvidence = (value: unknown): value is MappingEvidence => record(value) && strings(value, ['ip', 'scope']) && ['live', 'offline'].includes(String(value.source)) && (value.interface === null || typeof value.interface === 'string') && value.classification === 'unclassified' && Array.isArray(value.reasons) && value.reasons.every(reason => typeof reason === 'string') && Array.isArray(value.observedMappings) && value.observedMappings.every(isDevice) && Array.isArray(value.trustedMappings) && value.trustedMappings.every(isTrustedMapping)
export const isDiscoveryStatus = (value: unknown): value is DiscoveryStatus => record(value) && ['ready', 'degraded'].includes(String(value.state)) && integer(value.failedObservations) && (value.message === null || typeof value.message === 'string')
export const isDeviceEvent = (value: unknown): value is { version: 1; device: Device } => record(value) && value.version === 1 && isDevice(value.device)
export const isTrustEvent = (value: unknown): value is { version: 1; mapping: TrustedMapping; action: string } => record(value) && value.version === 1 && isTrustedMapping(value.mapping) && ['create', 'update', 'verify', 'revoke'].includes(String(value.action))
export const isDiscoveryEvent = (value: unknown): value is { version: 1; status: DiscoveryStatus } => record(value) && value.version === 1 && isDiscoveryStatus(value.status)
const isIncident = (value: unknown): value is Incident => record(value) && strings(value, ['id', 'timestamp', 'sourceIp', 'observedMac', 'expectedMac', 'reason', 'status']) && ['Critical', 'High', 'Medium', 'Low'].includes(String(value.severity))
const isInterface = (value: unknown): value is NetworkInterface => record(value) && integer(value.index) && typeof value.name === 'string' && value.name.length > 0 && (value.networkName === undefined || typeof value.networkName === 'string') && (value.description === undefined || typeof value.description === 'string')
function invalidContract(): never { throw new Error('The backend returned an unexpected response. Check API compatibility.') }
async function request(path: string, signal?: AbortSignal, body?: unknown, options?: { method: string; token: string }): Promise<unknown> {
  try { return (await client.request<unknown>({ url: path, method: options?.method ?? (body === undefined ? 'GET' : 'POST'), data: body, signal, headers: options ? { Authorization: `Bearer ${options.token}` } : undefined })).data }
  catch (error) {
    if (axios.isCancel(error)) throw error
    if (axios.isAxiosError(error)) {
      const body: unknown = error.response?.data
      if (record(body) && record(body.error) && typeof body.error.message === 'string') throw new Error(body.error.message)
      throw new Error(error.response ? `API request failed (HTTP ${error.response.status}).` : 'Cannot reach the NetGuard backend. Start Flask on 127.0.0.1:5001 and retry.')
    }
    throw error
  }
}
async function page<T>(path: string, validate: (value: unknown) => value is T, signal?: AbortSignal): Promise<CollectionResponse<T>> {
  const body = await request(path, signal)
  if (!record(body) || !Array.isArray(body.items) || !body.items.every(validate) || !integer(body.total) || !integer(body.limit) || !integer(body.offset)) invalidContract()
  return { items: body.items, total: body.total, limit: body.limit, offset: body.offset }
}
async function collection<T>(path: string, validate: (value: unknown) => value is T, signal?: AbortSignal): Promise<T[]> { return (await page(path, validate, signal)).items }
export function isMonitorStatus(value: unknown): value is MonitorStatus {
  return record(value) && ['not_started', 'starting', 'running', 'stopping', 'stopped', 'completed', 'error'].includes(String(value.state))
    && typeof value.captureAvailable === 'boolean' && typeof value.reason === 'string'
    && (value.interface === null || typeof value.interface === 'string') && (value.startedAt === null || typeof value.startedAt === 'string')
    && (value.sessionId === null || typeof value.sessionId === 'string') && (value.mode === null || value.mode === 'live' || value.mode === 'offline')
    && integer(value.revision) && integer(value.bufferCapacity) && value.bufferCapacity > 0
    && (!('protocols' in value) || Array.isArray(value.protocols) && value.protocols.every(item => ['ARP', 'TCP', 'UDP', 'DNS'].includes(String(item))))
    && (!('supportedProtocols' in value) || Array.isArray(value.supportedProtocols) && value.supportedProtocols.every(item => ['ARP', 'TCP', 'UDP', 'DNS'].includes(String(item))))
    && (value.state !== 'running' || (typeof value.startedAt === 'string' && typeof value.sessionId === 'string' && (value.mode === 'live' ? typeof value.interface === 'string' && value.interface.length > 0 : value.mode === 'offline' && value.interface === null)))
    && (value.error === null || (record(value.error) && strings(value.error, ['code', 'message'])))
}
export function isPacketEvent(value: unknown): value is PacketEvent { return record(value) && value.version === 1 && isPacket(value.packet) }
export function isStatusEvent(value: unknown): value is StatusEvent { return record(value) && value.version === 1 && isMonitorStatus(value.status) }
async function mutation(path: string, body: unknown): Promise<MonitorStatus> {
  const result = await request(path, undefined, body)
  if (!isMonitorStatus(result)) invalidContract()
  return result
}
export const api = {
  startMonitoring: (networkInterface: string, protocols: string[] = ['ARP']) => mutation('/monitor/start', { interface: networkInterface, protocols }),
  stopMonitoring: () => mutation('/monitor/stop', {}),
  replayPcap: (file: File) => { const body = new FormData(); body.append('file', file); return mutation('/monitor/replay', body) },
  async getHealth(signal?: AbortSignal) {
    const body = await request('/health', signal)
    if (!record(body) || body.status !== 'ok' || body.service !== 'netguard' || body.phase !== 7) invalidContract()
    return body
  },
  async getMonitorStatus(signal?: AbortSignal): Promise<MonitorStatus> {
    const body = await request('/monitor/status', signal)
    if (!isMonitorStatus(body)) invalidContract()
    return body
  },
  async getInterfaces(signal?: AbortSignal): Promise<NetworkInterface[]> {
    const body = await request('/interfaces', signal)
    if (!record(body) || !Array.isArray(body.items) || !body.items.every(isInterface) || !integer(body.total)) invalidContract()
    return body.items
  },
  getDevices: (signal?: AbortSignal) => collection('/devices?limit=500', isDevice, signal),
  getDevicePage: (query = '', source = 'all', trusted = false, offset = 0, signal?: AbortSignal) => page(`/devices?${new URLSearchParams({ q: query, source, trusted: String(trusted), limit: '25', offset: String(offset) })}`, isDevice, signal),
  getTrustedPage: (offset = 0, signal?: AbortSignal, state = 'all') => page(`/trusted-mappings?limit=25&offset=${offset}&state=${encodeURIComponent(state)}`, isTrustedMapping, signal),
  getAudit: (id: string, offset = 0, signal?: AbortSignal) => page(`/trusted-mappings/${encodeURIComponent(id)}/audit?limit=25&offset=${offset}`, isAudit, signal),
  getConflicts: (offset = 0, signal?: AbortSignal) => page(`/mapping-conflicts?limit=25&offset=${offset}`, isEvidence, signal),
  async changeTrust(action: 'create' | 'update' | 'verify' | 'revoke', id: string | null, body: Record<string, unknown>, token: string): Promise<TrustedMapping> {
    const path = '/trusted-mappings' + (id ? `/${encodeURIComponent(id)}` : '') + (action === 'verify' ? '/verify' : '')
    const result = await request(path, undefined, body, { method: action === 'update' ? 'PATCH' : action === 'revoke' ? 'DELETE' : 'POST', token })
    if (!isTrustedMapping(result)) invalidContract()
    return result
  },
  async getDiscoveryStatus(signal?: AbortSignal): Promise<DiscoveryStatus> { const result = await request('/discovery/status', signal); if (!isDiscoveryStatus(result)) invalidContract(); return result },
  getPackets: (signal?: AbortSignal) => collection('/packets?limit=500', isPacket, signal),
  getAlerts: (signal?: AbortSignal) => collection('/alerts', isIncident, signal),
  getIncidents: (signal?: AbortSignal) => collection('/incidents', isIncident, signal),
  async getWorkspace(signal?: AbortSignal): Promise<WorkspaceResponse> {
    const inventory = Promise.all([page('/devices?limit=500', isDevice, signal), api.getDiscoveryStatus(signal)])
      .then(([devices, status]) => ({ devices, error: status.message || '' }))
      .catch((cause: unknown) => ({ devices: { items: [] as Device[], total: 0 }, error: cause instanceof Error ? cause.message : 'Inventory unavailable.' }))
    // Dedicated detection views own error reporting; analysis failure must not disconnect capture controls.
    const [, monitor, interfaces, packets, alerts, incidents, observed] = await Promise.all([
      api.getHealth(signal), api.getMonitorStatus(signal), api.getInterfaces(signal),
      api.getPackets(signal), api.getAlerts(signal).catch(() => [] as Incident[]), api.getIncidents(signal).catch(() => [] as Incident[]), inventory,
    ])
    return { monitor, interfaces, inventoryError: observed.error, data: { devices: observed.devices.items, deviceTotal: observed.devices.total, packets, alerts, incidents, activity: [] } }
  },
}
