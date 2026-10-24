import './phase7-integration.mjs'
import assert from 'node:assert/strict'
import http from 'node:http'
function request(path, headers) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port: 5001, path, headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)) })
    req.on('error', reject)
  })
}
assert.equal(await request('/api/health', { Host: 'attacker.invalid:5001' }), 400)
assert.equal(await request('/socket.io/?EIO=4&transport=polling', { Host: 'attacker.invalid:5001' }), 400)
assert.equal(await request('/socket.io/?EIO=4&transport=polling', { Origin: 'https://attacker.invalid' }), 400)
console.log('Phase 8 transport validation passed: malicious Host rejected for REST and Socket.IO; foreign Socket.IO origin rejected.')
const { io } = await import('socket.io-client')
const { writeFile } = await import('node:fs/promises')
const reconnectMs = []
const socket = io('http://127.0.0.1:5173', { autoConnect: false, transports: ['websocket'], reconnection: false })
try {
  for (let i = 0; i < 10; i++) {
    const started = performance.now()
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Reconnect timeout')), 3000)
      socket.once('connect', () => { clearTimeout(timer); resolve() })
      socket.connect()
    })
    const response = await fetch('http://127.0.0.1:5173/api/incidents?source=offline')
    assert.equal(response.status, 200)
    assert.ok((await response.json()).total > 0)
    reconnectMs.push(performance.now()-started)
    socket.disconnect()
  }
} finally { socket.disconnect() }
await writeFile(new URL('../../validation/reconnect-performance.json', import.meta.url), JSON.stringify({ samples: 10, connectionAndRestMs: reconnectMs }, null, 2)+'\n')
console.log('Ten WebSocket reconnect + persisted incident REST reconciliation cycles passed.')
