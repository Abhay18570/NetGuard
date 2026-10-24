import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isDevice, isDeviceEvent, isTrustEvent, isTrustedMapping, isDiscoveryEvent } from '../src/services/api.ts'
const device = { id: 'a', ip: '192.0.2.1', mac: '02:00:00:00:00:01', hostname: '', trusted: false, trustedMappingId: null, firstSeen: '2023-11-14T00:00:00Z', lastSeen: '2023-11-14T00:00:00Z', observationCount: 1, interface: null, source: 'offline', scope: 'offline:session-a', lastSessionId: 'session-a' }
const mapping = { id: 'b', ip: device.ip, mac: device.mac, interface: 'en0', source: 'live', label: '', state: 'verified', createdAt: device.firstSeen, updatedAt: device.lastSeen, verifiedAt: device.firstSeen, revokedAt: null, version: 2 }
test('replay inventory cannot be represented as a trusted live mapping', () => {
  assert.equal(isDevice(device), true)
  assert.equal(isDevice({ ...device, trusted: true, trustedMappingId: 'b' }), false)
  assert.equal(isDevice({ ...device, interface: 'en0' }), false)
  assert.equal(isTrustedMapping({ ...mapping, source: 'offline' }), false)
})
test('inventory contracts require time bounds and real observation counts', () => {
  assert.equal(isDevice({ ...device, firstSeen: undefined }), false)
  assert.equal(isDevice({ ...device, observationCount: 0 }), false)
  assert.equal(isDeviceEvent({ version: 1, device }), true)
  assert.equal(isDeviceEvent({ version: 2, device }), false)
})
test('trust updates require versioned live baseline and explicit verification metadata', () => {
  assert.equal(isTrustEvent({ version: 1, mapping, action: 'verify' }), true)
  assert.equal(isTrustedMapping({ ...mapping, verifiedAt: null }), false)
  assert.equal(isTrustedMapping({ ...mapping, version: 0 }), false)
  assert.equal(isTrustEvent({ version: 1, mapping, action: 'auto_trust' }), false)
})
test('inventory failure is distinguishable from capture lifecycle', () => {
  assert.equal(isDiscoveryEvent({ version: 1, status: { state: 'degraded', failedObservations: 2, message: 'Inventory incomplete' } }), true)
  assert.equal(isDiscoveryEvent({ version: 1, status: { state: 'running', failedObservations: 0, message: null } }), false)
})

test('inventory REST failure does not prevent capture workspace loading', async () => {
  const { default: axios, AxiosError } = await import('axios')
  const previous = axios.defaults.adapter
  const capture = { state: 'not_started', captureAvailable: true, interface: null, startedAt: null, reason: 'Select an interface', mode: null, sessionId: null, error: null, revision: 0, bufferCapacity: 1000 }
  axios.defaults.adapter = async config => {
    if (config.url.startsWith('/devices') || config.url === '/discovery/status') throw new AxiosError('database unavailable', 'ERR_BAD_RESPONSE', config, undefined, { status: 503, data: { error: { message: 'Inventory database unavailable' } } })
    const data = config.url === '/health' ? { status: 'ok', service: 'netguard', phase: 7 } : config.url === '/monitor/status' ? capture : config.url === '/interfaces' ? { items: [], total: 0 } : { items: [], total: 0, limit: 100, offset: 0 }
    return { data, status: 200, statusText: 'OK', headers: {}, config }
  }
  try {
    const { api } = await import('../src/services/api.ts?inventory-failure-test')
    const workspace = await api.getWorkspace()
    assert.equal(workspace.monitor.state, 'not_started')
    assert.equal(workspace.inventoryError, 'Inventory database unavailable')
    assert.deepEqual(workspace.data.packets, [])
  } finally { axios.defaults.adapter = previous }
})

test('administrator token is sent only with explicit trusted mapping mutations', async () => {
  const { default: axios } = await import('axios')
  const previous = axios.defaults.adapter
  const requests = []
  axios.defaults.adapter = async config => {
    requests.push(config)
    return { data: config.method === 'post' ? mapping : { items: [], total: 0, limit: 25, offset: 0 }, status: 200, statusText: 'OK', headers: {}, config }
  }
  try {
    const { api } = await import('../src/services/api.ts?authorization-test')
    await api.changeTrust('verify', 'b', { version: 1, reason: 'Unit test verification' }, 'ephemeral-unit-test-credential')
    await api.getDevices()
    assert.equal(requests[0].headers.get('Authorization'), 'Bearer ephemeral-unit-test-credential')
    assert.equal(requests[1].headers.get('Authorization'), undefined)
    assert.ok(requests.every(config => config.baseURL === '/api'))
  } finally { axios.defaults.adapter = previous }
})
