import axios from 'axios'
import { isAlert, type SecurityAlert } from './alerts.ts'
import type { CollectionResponse } from '../types'
export const incidentStates = ['Open', 'Investigating', 'Contained', 'Resolved', 'Closed'] as const
export type IncidentState = typeof incidentStates[number]
export const incidentTransitions: Record<IncidentState, IncidentState[]> = { Open: ['Investigating', 'Resolved'], Investigating: ['Contained', 'Resolved'], Contained: ['Investigating', 'Resolved'], Resolved: ['Investigating', 'Closed'], Closed: ['Investigating'] }
export interface Investigation {
  id: string; title: string; description: string; severity: 'Low' | 'Medium' | 'High'; status: IncidentState;
  firstDetected: string; lastDetected: string; createdAt: string; updatedAt: string; assignedTo: string; resolutionNotes: string;
  version: number; source: 'live' | 'offline'; interface: string | null; sessionId: string; scope: string; ruleId: string;
  sourceIp: string; observedMac: string; expectedMacs: string[]; alertIds: string[]; findingIds: string[];
  classification: 'suspicious_observation'; containment: 'administrator_report_only';
}
export interface InvestigationDetail extends Investigation { completedActions: { actionId: string; actor: string; performedAt: string; description: string; timestamp: string }[]; alerts: SecurityAlert[]; packetIds: string[]; observedMappings: { ip: string; mac: string; expectedMacs: string[]; findingId: string }[] }
export interface InvestigationAudit { id: number; incidentId: string; actor: string; timestamp: string; action: string; reason: string; previousStatus: IncidentState | null; newStatus: IncidentState; details: Record<string, unknown> }
export interface Recommendation { id: string; title: string; description: string }
export interface DefenseSummary { counts: Record<'live' | 'offline', Record<IncidentState, number>>; pendingAlerts: number; capacityMessage: string | null; failedAttempts: number; verifiedMappingCount: number; advisoryOnly: true; recommendations: Recommendation[]; gatewayBaselines: { mappingId: string; state: string; ip: string | null; mac: string | null; interface: string | null }[]; storage: { usedBytes: number; limitBytes: number; configuredBytes: number; atCapacity: boolean }; limits: Record<string, number>; usage: Record<string, number> }
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string')
const number = (v: unknown) => Number.isInteger(v) && Number(v) >= 0
export function isInvestigation(v: unknown): v is Investigation {
  return object(v) && ['id', 'title', 'description', 'firstDetected', 'lastDetected', 'createdAt', 'updatedAt', 'assignedTo', 'resolutionNotes', 'sessionId', 'scope', 'ruleId', 'sourceIp', 'observedMac'].every(k => typeof v[k] === 'string')
    && incidentStates.includes(v.status as IncidentState) && ['Low', 'Medium', 'High'].includes(String(v.severity)) && number(v.version) && Number(v.version) > 0
    && (v.source === 'live' ? typeof v.interface === 'string' && !!v.interface : v.source === 'offline' && v.interface === null)
    && strings(v.alertIds) && v.alertIds.length > 0 && strings(v.findingIds) && v.findingIds.length === v.alertIds.length && strings(v.expectedMacs)
    && v.classification === 'suspicious_observation' && v.containment === 'administrator_report_only'
}
export function isIncidentEvent(v: unknown): boolean { return object(v) && v.version === 1 && isInvestigation(v.incident) }
export function isInvestigationDetail(v: unknown): v is InvestigationDetail { return isInvestigation(v) && object(v) && Array.isArray(v.alerts) && v.alerts.every(isAlert) && strings(v.packetIds) && Array.isArray(v.completedActions) && v.completedActions.every(x => object(x) && ['actionId', 'actor', 'performedAt', 'description', 'timestamp'].every(k => typeof x[k] === 'string')) && Array.isArray(v.observedMappings) && v.observedMappings.every(x => object(x) && typeof x.ip === 'string' && typeof x.mac === 'string' && typeof x.findingId === 'string' && strings(x.expectedMacs)) }
export function isDefenseSummary(v: unknown): v is DefenseSummary { return object(v) && v.advisoryOnly === true && object(v.counts) && ['live', 'offline'].every(source => { const counts = (v.counts as Record<string, unknown>)[source]; return object(counts) && incidentStates.every(state => number(counts[state])) }) && number(v.pendingAlerts) && number(v.failedAttempts) && number(v.verifiedMappingCount) && (v.capacityMessage === null || typeof v.capacityMessage === 'string') && object(v.storage) && ['usedBytes', 'limitBytes', 'configuredBytes'].every(k => number((v.storage as Record<string, unknown>)[k])) && typeof v.storage.atCapacity === 'boolean' && object(v.limits) && Object.values(v.limits).every(number) && object(v.usage) && Object.values(v.usage).every(number) && Array.isArray(v.recommendations) && v.recommendations.every(x => object(x) && ['id', 'title', 'description'].every(k => typeof x[k] === 'string')) && Array.isArray(v.gatewayBaselines) && v.gatewayBaselines.every(x => object(x) && typeof x.mappingId === 'string' && ['missing', 'pending', 'verified', 'revoked'].includes(String(x.state)) && ['ip', 'mac', 'interface'].every(k => x[k] === null || typeof x[k] === 'string')) }
export const incidentQuery = (source = 'all', severity = 'all', status = 'all', q = '', offset = 0) => new URLSearchParams({ source, severity, status, q, offset: String(offset), limit: '25' }).toString()
export const incidentEmptyLabel = (loading: boolean, error: string) => loading ? 'Loading incidents…' : error ? 'Incident records unavailable' : 'No matching incidents'
export function validateIncidentChange(status: string, notes: string, confirmed: boolean, action: string) { if (status === 'Contained' && (!confirmed || !action.trim())) return 'Confirm and describe a completed external containment action. NetGuard does not perform or verify containment.'; if (['Resolved', 'Closed'].includes(status) && !notes.trim()) return 'Resolution notes are required.'; return '' }
async function request(path: string, signal?: AbortSignal, body?: unknown, token?: string, method = 'GET') {
  try { return (await axios.request<unknown>({ url: '/api' + path, method, data: body, signal, timeout: 8000, headers: token ? { Authorization: `Bearer ${token}` } : undefined })).data }
  catch (cause) { if (axios.isAxiosError(cause) && typeof cause.response?.data?.error?.message === 'string') throw new Error(cause.response.data.error.message); throw cause }
}
function page<T>(v: unknown, validate: (value: unknown) => value is T): CollectionResponse<T> { if (!object(v) || !Array.isArray(v.items) || !v.items.every(validate) || !['total', 'limit', 'offset'].every(k => number(v[k]))) throw new Error('Invalid incident response'); return v as unknown as CollectionResponse<T> }
export const incidentApi = {
  async list(source = 'all', severity = 'all', status = 'all', q = '', offset = 0, signal?: AbortSignal) { return page(await request('/incidents?' + incidentQuery(source, severity, status, q, offset), signal), isInvestigation) },
  async detail(id: string, signal?: AbortSignal) { const result = await request('/incidents/' + encodeURIComponent(id), signal); if (!isInvestigationDetail(result)) throw new Error('Invalid incident detail'); return result },
  async summary(signal?: AbortSignal) { const result = await request('/defense/summary', signal); if (!isDefenseSummary(result)) throw new Error('Invalid defense summary'); return result },
  async audit(id: string, offset = 0, signal?: AbortSignal) { return page(await request(`/incidents/${encodeURIComponent(id)}/audit?limit=25&offset=${offset}`, signal), (v): v is InvestigationAudit => object(v) && number(v.id) && ['incidentId', 'actor', 'timestamp', 'action', 'reason'].every(k => typeof v[k] === 'string') && (v.previousStatus === null || incidentStates.includes(v.previousStatus as IncidentState)) && incidentStates.includes(v.newStatus as IncidentState) && object(v.details)) },
  async change(id: string, body: Record<string, unknown>, token: string, action = false) { const result = await request(`/incidents/${encodeURIComponent(id)}${action ? '/actions' : ''}`, undefined, body, token, action ? 'POST' : 'PATCH'); if (!isInvestigation(result)) throw new Error('Invalid incident update'); return result },
  async export(id: string, format: 'json' | 'csv', token: string) { try { return (await axios.get<Blob>(`/api/incidents/${encodeURIComponent(id)}/export?format=${format}`, { headers: { Authorization: `Bearer ${token}` }, responseType: 'blob', timeout: 15000 })).data } catch (cause) { if (axios.isAxiosError(cause) && cause.response?.data instanceof Blob) { try { const body = JSON.parse(await cause.response.data.text()); if (body.error?.message) throw new Error(body.error.message) } catch (error) { if (error instanceof Error && !(error instanceof SyntaxError)) throw error } } throw cause } },
}
