import './phase6-integration.mjs'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { io } from 'socket.io-client'
import { isInvestigation, isInvestigationDetail, isIncidentEvent, isDefenseSummary } from '../src/services/incidents.ts'
const base = 'http://127.0.0.1:5173'; const token = process.env.NETGUARD_TEST_ADMIN_TOKEN
assert.ok(token?.length >= 32, 'Use the isolated test runner')
async function get(path, origin = base) { const response = await fetch(origin + '/api/' + path); assert.equal(response.status, 200); return response.json() }
async function waitFor(predicate) { const deadline = Date.now() + 8000; while (!await predicate()) { assert.ok(Date.now() < deadline, 'Integration timeout'); await new Promise(resolve => setTimeout(resolve, 20)) } }
async function mutate(id, body, suffix = '', authorized = true) { return fetch(base + '/api/incidents/' + id + suffix, { method: suffix ? 'POST' : 'PATCH', headers: { 'Content-Type': 'application/json', Origin: base, ...(authorized ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) }) }
const fixture = await readFile(new URL('../../backend/tests/fixtures/incident-correlated.pcap', import.meta.url))
async function replay() { const body = new FormData(); body.append('file', new File([fixture], 'incident-correlated.pcap')); const response = await fetch(base + '/api/monitor/replay', { method: 'POST', body }); assert.ok([200, 202].includes(response.status)); return response.json() }
const socket = io(base, { autoConnect: false, reconnection: false, transports: ['websocket'], extraHeaders: { Origin: base } }); const events = []
for (const name of ['incident_created', 'incident_updated']) socket.on(name, payload => events.push({ name, payload }))
try {
  socket.connect(); await waitFor(() => socket.connected)
  assert.equal((await get('health')).phase, 7)
  const before = (await get('incidents')).total
  const session = await replay()
  await waitFor(async () => (await get('monitor/status')).state === 'completed' && (await get('detection/status')).pendingPackets === 0 && (await get('defense/summary')).pendingAlerts === 0)
  const page = await get('incidents'); assert.equal(page.total, before + 1); assert.ok(page.items.every(isInvestigation))
  let incident = page.items.find(row => row.sessionId === session.sessionId)
  assert.equal(incident.alertIds.length, 3); assert.equal(incident.findingIds.length, 3)
  assert.equal(incident.source, 'offline'); assert.equal(incident.interface, null)
  const detail = await get('incidents/' + incident.id); assert.ok(isInvestigationDetail(detail)); assert.equal(detail.alerts.length, 3); assert.equal(detail.packetIds.length, 4)
  assert.deepEqual(await get('incidents/' + incident.id, 'http://127.0.0.1:5001'), detail)
  await waitFor(() => events.some(event => event.name === 'incident_updated' && event.payload.incident.id === incident.id))
  assert.ok(events.every(event => isIncidentEvent(event.payload)))
  assert.equal((await mutate(incident.id, { version: incident.version, reason: 'unauthorized', status: 'Investigating' }, '', false)).status, 401)
  let response = await mutate(incident.id, { version: incident.version, reason: 'Begin controlled investigation', status: 'Investigating', assignedTo: 'Isolated validation investigator' })
  assert.equal(response.status, 200); incident = await response.json()
  response = await mutate(incident.id, { version: incident.version, reason: 'Missing external evidence', status: 'Contained' }); assert.equal(response.status, 400)
  response = await mutate(incident.id, { version: incident.version, reason: 'Document offline exercise only', actionId: 'dhcp_leases', confirmed: true, description: 'Reviewed controlled offline evidence; no live network change.', performedAt: new Date(Date.now() - 1000).toISOString() }, '/actions')
  assert.equal(response.status, 200); incident = await response.json(); assert.equal(incident.status, 'Investigating')
  response = await mutate(incident.id, { version: incident.version, reason: 'Record external exercise report', status: 'Contained', containmentConfirmed: true, externalAction: 'Administrator confirms a documented external review exercise; no live network action was performed by this validation.' })
  assert.equal(response.status, 200); incident = await response.json(); assert.equal(incident.containment, 'administrator_report_only')
  response = await mutate(incident.id, { version: incident.version, reason: 'Complete offline review', status: 'Resolved', resolutionNotes: 'Synthetic offline correlation verified; no attack verdict or live defense action.' }); assert.equal(response.status, 200); incident = await response.json()
  response = await mutate(incident.id, { version: incident.version, reason: 'Archive investigation', status: 'Closed' }); assert.equal(response.status, 200); incident = await response.json()
  assert.equal((await mutate(incident.id, { version: 1, reason: 'stale request', status: 'Investigating' })).status, 409)
  const audit = await get('incidents/' + incident.id + '/audit'); assert.equal(audit.total, 8)
  assert.ok(audit.items.some(row => row.action === 'external_action'))
  assert.equal((await fetch(base + `/api/incidents/${incident.id}/export`)).status, 401)
  for (const format of ['json', 'csv']) {
    const exported = await fetch(base + `/api/incidents/${incident.id}/export?format=${format}`, { headers: { Authorization: `Bearer ${token}` } }); assert.equal(exported.status, 200)
    const text = await exported.text(); assert.ok(text.includes(incident.id)); assert.ok(!text.includes(token)); assert.ok(exported.headers.get('content-disposition').includes('.' + format))
    if (format === 'json') { const document = JSON.parse(text); assert.equal(document.incident.alerts.length, 3); assert.equal(document.timeline.length, 8) }
  }
  assert.ok(isDefenseSummary(await get('defense/summary')))
  assert.equal((await get('incidents?source=live')).total, 0)
  assert.equal((await get('incidents?status=Closed')).total, 1)
  socket.disconnect(); const missed = await replay()
  await waitFor(async () => (await get('monitor/status')).state === 'completed' && (await get('detection/status')).pendingPackets === 0 && (await get('defense/summary')).pendingAlerts === 0)
  socket.connect(); await waitFor(() => socket.connected)
  const recovered = await get('incidents'); assert.equal(recovered.total, before + 2); assert.ok(recovered.items.some(row => row.sessionId === missed.sessionId))
  assert.equal(new Set(recovered.items.flatMap(row => row.alertIds)).size, recovered.items.flatMap(row => row.alertIds).length)
  assert.equal((await get('incidents?limit=1&offset=1')).items.length, 1)
  console.log('Phase 7 integration passed: four offline packets → three findings/alerts → one incident; direct/proxied APIs, lifecycle/containment validation, external checklist reports, atomic audit, scoped JSON/CSV export, incident events, replay isolation, filters/pagination, and reconnect recovery.')
} finally { socket.disconnect() }
