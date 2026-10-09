import './phase5-integration.mjs'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { io } from 'socket.io-client'
import { isAlert, isAlertEvent, isSummary } from '../src/services/alerts.ts'
const base = 'http://127.0.0.1:5173'
const token = process.env.NETGUARD_TEST_ADMIN_TOKEN
assert.ok(token?.length >= 32, 'Use the isolated validation runner')
async function get(path, origin = base) { const response = await fetch(origin + '/api/' + path); assert.equal(response.status, 200); return response.json() }
async function waitFor(predicate) { const deadline = Date.now() + 8000; while (!await predicate()) { assert.ok(Date.now() < deadline, 'Integration timeout'); await new Promise(resolve => setTimeout(resolve, 20)) } }
async function patch(id, body, authorized = true) { return fetch(base + '/api/security-alerts/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Origin: base, ...(authorized ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) }) }
const fixture = await readFile(new URL('../../backend/tests/fixtures/detection-conflict.pcap', import.meta.url))
async function replay() { const body = new FormData(); body.append('file', new File([fixture], 'controlled-offline.pcap')); const response = await fetch(base + '/api/monitor/replay', { method: 'POST', body }); assert.ok([200, 202].includes(response.status)); return response.json() }
const socket = io(base, { autoConnect: false, transports: ['websocket'], reconnection: false, extraHeaders: { Origin: base } })
const created = []; const updated = []; socket.on('alert_created', event => created.push(event)); socket.on('alert_updated', event => updated.push(event))
try {
  const before = (await get('security-alerts')).total
  socket.connect(); await waitFor(() => socket.connected)
  const session = await replay()
  await waitFor(() => created.some(event => event.alert.sessionId === session.sessionId))
  await waitFor(async () => (await get('monitor/status')).state === 'completed')
  const alerts = await get('security-alerts')
  assert.equal(alerts.total, before + 1); assert.ok(alerts.items.every(isAlert)); assert.ok(created.every(isAlertEvent))
  const alert = alerts.items.find(item => item.sessionId === session.sessionId)
  const finding = await get('findings/' + alert.findingId)
  assert.deepEqual(alert.packetIds, finding.packetIds); assert.equal(alert.severity, finding.severity); assert.equal(alert.status, 'New')
  assert.equal(alert.source, 'offline'); assert.equal((await get('security-alerts?source=live')).total, 0)
  assert.deepEqual(await get('security-alerts', 'http://127.0.0.1:5001'), alerts)
  assert.equal((await patch(alert.id, { status: 'Resolved', version: 1, reason: 'Unauthorized test' }, false)).status, 401)
  let version = 1
  for (const status of ['Acknowledged', 'Investigating', 'Resolved']) {
    const response = await patch(alert.id, { status, version, reason: 'Controlled offline review' }); assert.equal(response.status, 200)
    const value = await response.json(); assert.equal(value.version, ++version)
  }
  await waitFor(() => updated.length === 3); assert.ok(updated.every(isAlertEvent))
  assert.equal((await patch(alert.id, { status: 'Investigating', version: 1, reason: 'Stale write' })).status, 409)
  const audit = await get(`security-alerts/${alert.id}/audit`); assert.equal(audit.total, 3)
  assert.deepEqual(audit.items.map(row => row.newStatus), ['Resolved', 'Investigating', 'Acknowledged'])
  assert.equal((await get('security-alerts?status=Resolved')).total, 1)
  socket.disconnect(); const missed = await replay()
  await waitFor(async () => (await get('monitor/status')).state === 'completed' && (await get('detection/status')).pendingPackets === 0)
  socket.connect(); await waitFor(() => socket.connected)
  const recovered = await get('security-alerts'); assert.equal(recovered.total, before + 2)
  assert.ok(recovered.items.some(item => item.sessionId === missed.sessionId))
  assert.equal(new Set(recovered.items.map(item => item.findingId)).size, recovered.total)
  assert.ok(isSummary(await get('security-alerts/summary')))
  assert.equal((await get('alerts')).total, recovered.total)
  console.log('Phase 6 integration passed: direct/proxied alerts, finding evidence parity, created/updated events, authorized lifecycle and audit, unauthorized/stale-write rejection, New counts, source/status filters, offline isolation, and reconnect REST recovery.')
} finally { socket.disconnect() }
