import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { io } from 'socket.io-client'
import { isFinding, isFindingEvent } from '../src/services/detection.ts'
const base = 'http://127.0.0.1:5173'
const fixture = await readFile(new URL('../../backend/tests/fixtures/detection-conflict.pcap', import.meta.url))
async function get(path, origin = base) { const response = await fetch(origin + '/api/' + path); assert.equal(response.status, 200); return response.json() }
async function waitFor(predicate) { const deadline = Date.now() + 8000; while (!await predicate()) { assert.ok(Date.now() < deadline, 'Integration timeout'); await new Promise(resolve => setTimeout(resolve, 20)) } }
async function replay() { const form = new FormData(); form.append('file', new File([fixture], 'offline-conflict.pcap')); const response = await fetch(base + '/api/monitor/replay', { method: 'POST', body: form }); assert.ok([200, 202].includes(response.status)); return response.json() }
const socket = io(base, { autoConnect: false, reconnection: false, transports: ['websocket'], extraHeaders: { Origin: base } })
const events = []; socket.on('detection_finding', event => events.push(event))
try {
  assert.equal((await get('health', 'http://127.0.0.1:5001')).phase, 7)
  assert.equal((await get('health')).phase, 7)
  const before = (await get('alerts')).total
  socket.connect(); await waitFor(() => socket.connected)
  const first = await replay()
  await waitFor(() => events.some(event => event.finding.sessionId === first.sessionId))
  assert.ok(events.every(isFindingEvent))
  assert.ok(events.every(event => event.finding.source === 'offline'))
  await waitFor(async () => (await get('monitor/status')).state === 'completed')
  assert.equal((await get('alerts')).total, before + 1)
  socket.disconnect()
  const second = await replay()
  await waitFor(async () => (await get('monitor/status')).state === 'completed' && (await get('detection/status')).pendingPackets === 0)
  socket.connect(); await waitFor(() => socket.connected)
  const restored = await get('alerts?source=offline')
  assert.equal(restored.total, before + 2)
  assert.ok(restored.items.every(isFinding))
  assert.ok(restored.items.some(row => row.sessionId === second.sessionId))
  assert.equal((await get('alerts?source=live')).total, 0)
  assert.equal((await get('alerts?limit=1&offset=1')).items.length, 1)
  assert.equal((await get('alerts?q=ARP_CLAIM_CONFLICT')).total, before + 2)
  assert.equal((await get('incidents')).total, restored.total)
  assert.equal((await get('detection/status')).state, 'ready')
  console.log('Phase 5 integration passed: direct/proxied health, controlled PCAP detection, frontend event contracts, cooldown deduplication, replay isolation, WebSocket reconnect + REST recovery, filters, pagination, and correlated incident references.')
} finally { socket.disconnect() }
