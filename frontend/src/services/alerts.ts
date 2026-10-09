import axios from 'axios'
import { isFinding, type Finding } from './detection.ts'
import type { CollectionResponse } from '../types'
export const alertStates = ['New', 'Acknowledged', 'Investigating', 'Resolved'] as const
export type AlertState = typeof alertStates[number]
export const nextStatuses: Record<AlertState, AlertState[]> = { New: ['Acknowledged', 'Investigating', 'Resolved'], Acknowledged: ['Investigating', 'Resolved'], Investigating: ['Resolved'], Resolved: ['Investigating'] }
export interface SecurityAlert extends Omit<Finding, 'status'> { status: AlertState; findingId: string; evidenceRef: string; version: number; createdAt: string; updatedAt: string }
export interface AlertSummary { counts: Record<'live' | 'offline', Record<AlertState, number>>; pendingFindings: number; delivery: string }
export interface AlertAudit { id: number; alertId: string; actor: string; timestamp: string; previousStatus: AlertState; newStatus: AlertState; reason: string }
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
export function isAlert(v: unknown): v is SecurityAlert { return object(v) && isFinding({ ...v, status: 'Unreviewed' }) && alertStates.includes(v.status as AlertState) && ['findingId', 'evidenceRef', 'createdAt', 'updatedAt'].every(k => typeof v[k] === 'string') && Number.isInteger(v.version) && Number(v.version) > 0 }
export function isAlertEvent(v: unknown): v is { version: 1; alert: SecurityAlert; recovered?: boolean } { return object(v) && v.version === 1 && isAlert(v.alert) && (v.recovered === undefined || typeof v.recovered === 'boolean') }
export function isSummary(v: unknown): v is AlertSummary { return object(v) && object(v.counts) && ['live', 'offline'].every(source => object(v.counts) && object(v.counts[source]) && alertStates.every(state => { const counts = (v.counts as Record<string, Record<string, unknown>>)[source]; return Number.isInteger(counts[state]) && Number(counts[state]) >= 0 })) && Number.isInteger(v.pendingFindings) && Number(v.pendingFindings) >= 0 && v.delivery === 'best_effort_socket_rest_recovery' }
export function alertQuery(source = 'live', severity = 'all', status = 'all', q = '', offset = 0) { return new URLSearchParams({ source, severity, status, q, offset: String(offset), limit: '25' }).toString() }
export function alertEmptyLabel(loading: boolean, error: string) { return loading ? 'Loading alerts…' : error ? 'Alerts unavailable' : 'No matching alerts' }
async function request(path: string, signal?: AbortSignal, body?: unknown, token?: string): Promise<unknown> {
  try { return (await axios.request({ url: '/api' + path, method: body ? 'PATCH' : 'GET', data: body, signal, timeout: 8000, headers: token ? { Authorization: `Bearer ${token}` } : undefined })).data }
  catch (error) { if (axios.isAxiosError(error) && typeof error.response?.data?.error?.message === 'string') throw new Error(error.response.data.error.message); throw error }
}
function page<T>(value: unknown, validator: (v: unknown) => v is T): CollectionResponse<T> { if (!object(value) || !Array.isArray(value.items) || !value.items.every(validator) || !['total', 'limit', 'offset'].every(k => Number.isInteger(value[k]) && Number(value[k]) >= 0)) throw new Error('Invalid alert response'); return value as unknown as CollectionResponse<T> }
export const alertApi = {
  async list(source = 'live', severity = 'all', status = 'all', q = '', offset = 0, signal?: AbortSignal) { return page(await request('/security-alerts?' + alertQuery(source, severity, status, q, offset), signal), isAlert) },
  async summary(signal?: AbortSignal) { const value = await request('/security-alerts/summary', signal); if (!isSummary(value)) throw new Error('Invalid alert summary'); return value },
  async update(alert: SecurityAlert, status: AlertState, reason: string, token: string) { const value = await request('/security-alerts/' + encodeURIComponent(alert.id), undefined, { status, reason, version: alert.version }, token); if (!isAlert(value)) throw new Error('Invalid alert update'); return value },
  async audit(id: string, offset = 0, signal?: AbortSignal) { return page(await request(`/security-alerts/${encodeURIComponent(id)}/audit?limit=25&offset=${offset}`, signal), (v): v is AlertAudit => object(v) && Number.isInteger(v.id) && ['alertId', 'actor', 'timestamp', 'reason'].every(k => typeof v[k] === 'string') && alertStates.includes(v.previousStatus as AlertState) && alertStates.includes(v.newStatus as AlertState)) },
}
