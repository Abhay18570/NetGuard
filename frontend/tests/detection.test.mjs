import test from 'node:test'
import assert from 'node:assert/strict'
import { isFinding, isFindingEvent, isDetectionStatus } from '../src/services/detection.ts'
const finding = { id: 'f', timestamp: '2026-01-01', source: 'offline', interface: null, sessionId: 'replay', scope: 'offline::replay', ruleId: 'ARP_CLAIM_CONFLICT', sourceIp: '192.0.2.1', observedMac: '02:00:00:00:00:01', expectedMac: '02:00:00:00:00:02', expectedMacs: ['02:00:00:00:00:02'], packetIds: ['a', 'b'], relatedPacketCount: 2, reason: 'Observed conflicting claims', severity: 'Medium', confidence: 'Medium', status: 'Unreviewed', classification: 'suspicious_observation', details: {}, corroboratingRules: [] }
test('accepts explainable offline finding and versioned event', () => { assert.ok(isFinding(finding)); assert.ok(isFindingEvent({ version: 1, finding })) })
test('rejects replay presented as a local interface', () => assert.equal(isFinding({ ...finding, interface: 'en0' }), false))
test('rejects confirmed-attack classification and unsupported rule', () => { assert.equal(isFinding({ ...finding, classification: 'attack' }), false); assert.equal(isFinding({ ...finding, ruleId: 'unknown' }), false) })
test('rejects absent packet evidence and inconsistent evidence counts', () => { assert.equal(isFinding({ ...finding, packetIds: [] }), false); assert.equal(isFinding({ ...finding, relatedPacketCount: 1 }), false) })
test('rejects malformed events so reconnect refresh uses REST', () => { assert.equal(isFindingEvent({ version: 2, finding }), false); assert.equal(isFindingEvent({ version: 1, finding: {} }), false) })
test('validates degraded detection separately from capture lifecycle', () => { const status = { state: 'degraded', failedPackets: 1, droppedPackets: 0, latePackets: 0, pendingPackets: 2, message: 'Incomplete', thresholds: { cooldown: 60 }, gatewayMappingIds: [] }; assert.ok(isDetectionStatus(status)); assert.equal(isDetectionStatus({ ...status, failedPackets: -1 }), false) })
test('detection REST failure does not disconnect capture workspace', async () => {
  const { default: axios } = await import('axios'); const previous = axios.defaults.adapter
  const monitor = { state: 'not_started', captureAvailable: true, interface: null, startedAt: null, reason: 'Not started', mode: null, sessionId: null, error: null, revision: 0, bufferCapacity: 1000 }
  axios.defaults.adapter = async config => {
    if (config.url === '/alerts') throw new Error('Detection database unavailable')
    const data = config.url === '/health' ? { status: 'ok', service: 'netguard', phase: 7 } : config.url === '/monitor/status' ? monitor : config.url === '/interfaces' ? { items: [], total: 0 } : config.url === '/discovery/status' ? { state: 'ready', failedObservations: 0, message: null } : { items: [], total: 0, limit: 100, offset: 0 }
    return { data, status: 200, statusText: 'OK', headers: {}, config }
  }
  try { const { api } = await import('../src/services/api.ts?detection-failure'); assert.equal((await api.getWorkspace()).monitor.state, 'not_started') }
  finally { axios.defaults.adapter = previous }
})
