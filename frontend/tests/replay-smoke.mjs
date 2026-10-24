// Integration check against already-running local Flask and Vite servers.
// Imports only the explicitly labeled test fixture; never starts live capture.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { io } from 'socket.io-client'
import { isPacketEvent, isStatusEvent, isDeviceEvent } from '../src/services/api.ts'
const fixture = await readFile(new URL('../../backend/tests/fixtures/offline-arp.pcap', import.meta.url))
async function waitFor(predicate, message) {
  const deadline = Date.now() + 5000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message)
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}
for (const base of ['http://127.0.0.1:5001', 'http://127.0.0.1:5173']) {
  const health = await fetch(`${base}/api/health`)
  assert.equal(health.status, 200)
  assert.deepEqual(await health.json(), { status: 'ok', service: 'netguard', phase: 7 })
  const socket = io(base, { transports: ['websocket'], extraHeaders: { Origin: 'http://127.0.0.1:5173' }, reconnection: false })
  const packets = []; const statuses = []; const discoveries = []
  socket.on('device_discovered', event => discoveries.push(event))
  socket.on('arp_packet', event => packets.push(event))
  socket.on('monitor_status', event => statuses.push(event))
  try {
    await waitFor(() => socket.connected, 'WebSocket connection failed')
    const form = new FormData()
    form.append('file', new File([fixture], 'offline-test-fixture.pcap', { type: 'application/vnd.tcpdump.pcap' }))
    const response = await fetch(`${base}/api/monitor/replay`, { method: 'POST', body: form, headers: { Origin: 'http://127.0.0.1:5173' } })
    assert.equal(response.status, 200)
    await waitFor(() => statuses.some(event => event.status?.state === 'completed'), 'Offline replay did not complete')
    assert.equal(packets.length, 2)
    assert.ok(packets.every(event => isPacketEvent(event) && event.packet.source === 'offline' && event.packet.interface === null))
    assert.ok(statuses.every(isStatusEvent))
    assert.deepEqual(statuses.map(event => event.status.state), ['starting', 'running', 'completed'])
    const history = await (await fetch(`${base}/api/packets`)).json()
    assert.deepEqual(history.items.map(packet => packet.id), packets.map(event => event.packet.id).reverse())
    const current = await (await fetch(`${base}/api/monitor/status`)).json()
    assert.equal(current.state, 'completed')
    assert.equal(current.mode, 'offline')
    assert.equal(discoveries.length, 2)
    assert.ok(discoveries.every(event => isDeviceEvent(event) && event.device.source === 'offline' && !event.device.trusted && event.device.observationCount === 1))
    const observed = await (await fetch(`${base}/api/devices?source=offline`)).json()
    const thisReplay = observed.items.filter(device => device.lastSessionId === current.sessionId)
    assert.equal(thisReplay.length, 2)
    assert.deepEqual(thisReplay.map(device => device.ip).sort(), ['192.0.2.1', '192.0.2.2'])
    const missing = await fetch(`${base}/api/monitor/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
    assert.equal(missing.status, 400)
    console.log(`${base}: health 200, WebSocket connected, replay 200, 2 offline packet events + 2 device discovery events, inventory verified, ordered status events, REST buffer match, missing-interface start rejected 400`)
  } finally { socket.disconnect() }
}
