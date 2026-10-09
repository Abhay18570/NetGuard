import axios from 'axios'
import type { Incident, CollectionResponse } from '../types'
export interface Finding extends Incident {
  source: 'live' | 'offline'; interface: string | null; sessionId: string; scope: string;
  ruleId: string; confidence: 'Low' | 'Medium' | 'High'; classification: 'suspicious_observation';
  expectedMacs: string[]; packetIds: string[]; relatedPacketCount: number;
  details: Record<string, unknown>; corroboratingRules: string[];
}
export interface DetectionStatus { state: 'ready' | 'degraded'; failedPackets: number; droppedPackets: number; latePackets: number; pendingPackets: number; message: string | null; thresholds: Record<string, number>; gatewayMappingIds: string[] }
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string')
export function isFinding(v: unknown): v is Finding {
  return object(v) && ['id', 'timestamp', 'sessionId', 'scope', 'sourceIp', 'observedMac', 'expectedMac', 'reason'].every(k => typeof v[k] === 'string')
    && ['ARP_CLAIM_CONFLICT', 'ARP_GATEWAY_MISMATCH', 'ARP_REPLY_BURST', 'ARP_UNCORRELATED_REPLY'].includes(String(v.ruleId))
    && ['Low', 'Medium', 'High'].includes(String(v.severity)) && ['Low', 'Medium', 'High'].includes(String(v.confidence))
    && v.classification === 'suspicious_observation' && v.status === 'Unreviewed'
    && (v.source === 'live' ? typeof v.interface === 'string' && !!v.interface : v.source === 'offline' && v.interface === null)
    && strings(v.packetIds) && v.packetIds.length > 0 && strings(v.expectedMacs) && strings(v.corroboratingRules) && object(v.details)
    && Number.isInteger(v.relatedPacketCount) && Number(v.relatedPacketCount) >= v.packetIds.length
}
export function isFindingEvent(v: unknown): boolean { return object(v) && v.version === 1 && isFinding(v.finding) }
export function isDetectionStatus(v: unknown): v is DetectionStatus {
  return object(v) && ['ready', 'degraded'].includes(String(v.state)) && ['failedPackets', 'droppedPackets', 'latePackets', 'pendingPackets'].every(k => Number.isInteger(v[k]) && Number(v[k]) >= 0)
    && (v.message === null || typeof v.message === 'string') && strings(v.gatewayMappingIds) && object(v.thresholds) && Object.values(v.thresholds).every(x => Number.isInteger(x) && Number(x) > 0)
}
export async function getFindings(source = 'all', severity = 'all', q = '', offset = 0, signal?: AbortSignal): Promise<CollectionResponse<Finding>> {
  const { data } = await axios.get<unknown>('/api/alerts', { params: { source, severity, q, offset, limit: 25 }, signal, timeout: 8000 })
  if (!object(data) || !Array.isArray(data.items) || !data.items.every(isFinding) || !['total', 'offset', 'limit'].every(k => Number.isInteger(data[k]) && Number(data[k]) >= 0)) throw new Error('Invalid detection response')
  return data as unknown as CollectionResponse<Finding>
}
export async function getDetectionStatus(signal?: AbortSignal): Promise<DetectionStatus> {
  const { data } = await axios.get<unknown>('/api/detection/status', { signal, timeout: 8000 }); if (!isDetectionStatus(data)) throw new Error('Invalid detection status'); return data
}
