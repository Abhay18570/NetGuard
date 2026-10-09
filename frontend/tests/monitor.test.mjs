import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mergePackets, statusLabel } from '../src/services/monitorState.ts'
import { isPacketEvent, isStatusEvent } from '../src/services/api.ts'
const packet = (sequence, sessionId = 'session-a', source = 'live') => ({ id: `${sessionId}:${sequence}`, sessionId, sequence, timestamp: '2023-11-14T22:13:20+00:00', source, interface: source === 'live' ? 'en0' : null, operation: 'Request', senderIp: '192.0.2.1', senderMac: '02:00:00:00:00:01', targetIp: '192.0.2.2', targetMac: '00:00:00:00:00:00', status: 'Not analyzed' })
const status = { state: 'running', mode: 'live', captureAvailable: true, interface: 'en0', startedAt: '2023-11-14T22:13:20+00:00', reason: 'Passive capture', sessionId: 'session-a', error: null, revision: 2, bufferCapacity: 1000 }
test('REST recovery and stream events deduplicate and preserve sequence order', () => {
  assert.deepEqual(mergePackets([packet(3), packet(2)], [packet(2), packet(1)], 'session-a').map(row => row.sequence), [3, 2, 1])
})
test('old live sessions never mix with new offline records', () => {
  const result = mergePackets([packet(10)], [packet(1, 'session-b', 'offline')], 'session-b')
  assert.equal(result.length, 1)
  assert.equal(result[0].source, 'offline')
  assert.deepEqual(mergePackets(result, [], null), [])
})
test('frontend retention is bounded to the latest 500 packets', () => {
  const result = mergePackets([], Array.from({ length: 1000 }, (_, index) => packet(index + 1)), 'session-a')
  assert.equal(result.length, 500)
  assert.equal(result[0].sequence, 1000)
  assert.equal(result.at(-1).sequence, 501)
})
test('live and offline packet events validate their source and required fields', () => {
  assert.equal(isPacketEvent({ version: 1, packet: packet(1) }), true)
  assert.equal(isPacketEvent({ version: 1, packet: packet(1, 'b', 'offline') }), true)
  for (const value of [{ version: 2, packet: packet(1) }, { version: 1, packet: { ...packet(1), targetMac: undefined } }, { version: 1, packet: { ...packet(1), source: 'offline' } }, { version: 1, packet: { ...packet(1), status: 'Safe' } }]) assert.equal(isPacketEvent(value), false)
})
test('running status requires an opened session and an explicit live interface', () => {
  assert.equal(isStatusEvent({ version: 1, status }), true)
  assert.equal(isStatusEvent({ version: 1, status: { ...status, interface: null } }), false)
  assert.equal(isStatusEvent({ version: 1, status: { ...status, startedAt: null } }), false)
})
test('offline replay and failed/disconnected states never display live active', () => {
  assert.equal(statusLabel(status), 'Live capture active')
  assert.equal(statusLabel({ ...status, mode: 'offline' }), 'Offline replay running')
  assert.equal(statusLabel({ ...status, mode: 'offline', state: 'completed' }), 'Offline replay completed')
  assert.equal(statusLabel({ ...status, state: 'error' }), 'Capture failed')
  assert.equal(statusLabel(status, false), 'Status unavailable')
})
