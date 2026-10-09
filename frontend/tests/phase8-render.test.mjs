import test from 'node:test'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { createServer } from 'vite'
import react from '@vitejs/plugin-react'
// Static rendering verifies component composition only, not browser interactions.
for (const page of ['Overview', 'Monitor', 'Devices', 'Threats', 'Incidents', 'Defense', 'Settings']) {
  test(`${page} renders with real providers without fabricating observations`, async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), 'netguard-render-'))
    const server = await createServer({ cacheDir, root: fileURLToPath(new URL('../', import.meta.url)), configFile: false, plugins: [react()], server: { middlewareMode: true, hmr: false, watch: null }, optimizeDeps: { noDiscovery: true, include: [] }, logLevel: 'silent' })
    try {
      const { default: Page } = await server.ssrLoadModule(`/src/pages/${page}.tsx`)
      const { MonitorProvider } = await server.ssrLoadModule('/src/context/MonitorContext.tsx')
      const { AlertProvider } = await server.ssrLoadModule('/src/context/AlertContext.tsx')
      const html = renderToStaticMarkup(React.createElement(MemoryRouter, null, React.createElement(MonitorProvider, null, React.createElement(AlertProvider, null, React.createElement(Page)))))
      assert.ok(html.length > 100)
      assert.ok(!html.includes('192.0.2.'))
      assert.ok(!html.includes('confirmed attack</'))
    } finally { await server.close(); await rm(cacheDir, { recursive: true, force: true }) }
  })
}
