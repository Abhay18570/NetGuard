// Run through backend/tests/run_phase4_validation.py: temporary database + random token.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { io } from 'socket.io-client'
import { isDevice, isDeviceEvent, isTrustEvent } from '../src/services/api.ts'
const base = 'http://127.0.0.1:5173'
const token = process.env.NETGUARD_TEST_ADMIN_TOKEN
assert.ok(token && token.length >= 32, 'Use the isolated validation runner')
const fixture = await readFile(new URL('../../backend/tests/fixtures/offline-arp-updates.pcap', import.meta.url))
async function waitFor(predicate) {
  const until = Date.now() + 8000
  while (!predicate()) { if (Date.now() > until) throw new Error('Integration timeout'); await new Promise(resolve => setTimeout(resolve, 10)) }
}
async function get(path) { const response = await fetch(base + path); assert.equal(response.status, 200); return response.json() }
async function mutate(path, body, method = 'POST', authorized = true) {
  return fetch(base + path, { method, headers: { 'Content-Type': 'application/json', Origin: base, ...(authorized ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) })
}
async function replay() { const form = new FormData(); form.append('file', new File([fixture], 'controlled-offline-updates.pcap')); const response = await fetch(base + '/api/monitor/replay', { method: 'POST', body: form }); assert.equal(response.status, 200); return response.json() }
const socket = io(base, { transports: ['websocket'], autoConnect: false, reconnection: false, extraHeaders: { Origin: base } })
const events = []; socket.onAny((name, payload) => events.push({ name, payload }))
try {
  socket.connect(); await waitFor(() => socket.connected)
  const adapter = (await get('/api/interfaces')).items[0].name
  const initial = await get('/api/devices'); assert.equal(initial.total, 0)
  const unauthorized = await mutate('/api/trusted-mappings', {}, 'POST', false); assert.equal(unauthorized.status, 401)
  const createdResponse = await mutate('/api/trusted-mappings', { ip: '192.0.2.1', mac: '02:00:00:00:00:01', interface: adapter, reason: 'Isolated test baseline' })
  assert.equal(createdResponse.status, 201)
  const created = await createdResponse.json()
  const verifiedResponse = await mutate(`/api/trusted-mappings/${created.id}/verify`, { version: created.version, reason: 'Explicit test verification' })
  assert.equal(verifiedResponse.status, 200)
  const verified = await verifiedResponse.json()
  const session = await replay()
  await waitFor(() => events.some(event => event.name === 'monitor_status' && event.payload.status.state === 'completed'))
  const discovered = events.filter(event => event.name === 'device_discovered')
  const updated = events.filter(event => event.name === 'device_updated')
  assert.equal(discovered.length, 2); assert.equal(updated.length, 1)
  assert.ok([...discovered, ...updated].every(event => isDeviceEvent(event.payload)))
  assert.equal(updated[0].payload.device.observationCount, 2)
  const inventory = await get('/api/devices?source=offline')
  assert.equal(inventory.total, 2); assert.ok(inventory.items.every(isDevice))
  assert.ok(inventory.items.every(row => !row.trusted && row.source === 'offline' && row.lastSessionId === session.sessionId))
  assert.deepEqual(inventory.items.map(row => row.observationCount).sort(), [1, 2])
  assert.equal((await get('/api/devices?source=live')).total, 0)
  assert.equal((await get('/api/devices?trusted=true')).total, 0)
  assert.deepEqual(await get(`/api/trusted-mappings/${created.id}`), verified)
  assert.equal((await get(`/api/trusted-mappings/${created.id}/audit`)).total, 2)
  socket.disconnect()
  await replay() // Deliberately miss this session's events.
  for (let i = 0; i < 100; i++) { if ((await get('/api/monitor/status')).state === 'completed') break; await new Promise(resolve => setTimeout(resolve, 20)) }
  socket.connect(); await waitFor(() => socket.connected)
  const recovered = await get('/api/devices?source=offline')
  assert.equal(recovered.total, 4)
  assert.equal(new Set(recovered.items.map(row => row.id)).size, 4)
  assert.equal(new Set(recovered.items.map(row => row.scope)).size, 2)
  assert.equal((await get('/api/devices?limit=1&offset=1')).items.length, 1)
  assert.equal((await get('/api/devices?q=192.0.2.1')).total, 2)
  const stale = await mutate(`/api/trusted-mappings/${created.id}`, { version: 1, label: 'stale', reason: 'stale test' }, 'PATCH'); assert.equal(stale.status, 409)
  const revoked = await mutate(`/api/trusted-mappings/${created.id}`, { version: verified.version, reason: 'Test revocation' }, 'DELETE'); assert.equal(revoked.status, 200)
  await waitFor(() => events.some(event => event.name === 'trusted_mapping_updated' && event.payload.action === 'revoke'))
  assert.ok(events.filter(event => event.name === 'trusted_mapping_updated').every(event => isTrustEvent(event.payload)))
  const audit = await get(`/api/trusted-mappings/${created.id}/audit`)
  assert.deepEqual(audit.items.map(row => row.action), ['revoke', 'verify', 'create'])
  assert.equal((await get('/api/mapping-conflicts')).total, 0)
  console.log('Phase 4 integration passed: discovery + updates, frontend event validators, REST parity, replay/trust isolation, reconnect recovery, pagination/filtering, administrator authorization, version checks, verification/revocation, atomic audit, and trust events.')
} finally { socket.disconnect() }
