import test from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'
import react from '@vitejs/plugin-react'
// Transform existing TSX in middleware mode only: no listening HTTP/HMR server.
test('incident page renders loading state and source/status filters', async () => {
  const server = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)), configFile: false, plugins: [react()], server: { middlewareMode: true, hmr: false, watch: null }, optimizeDeps: { noDiscovery: true, include: [] }, logLevel: 'silent' })
  try {
    const { default: Incidents } = await server.ssrLoadModule('/src/pages/Incidents.tsx')
    const html = renderToStaticMarkup(React.createElement(Incidents))
    assert.ok(html.includes('Incident history')); assert.ok(html.includes('Loading incidents'))
    assert.ok(html.includes('Incident source')); assert.ok(html.includes('Incident status'))
    assert.ok(!html.includes('confirmed attack</'))
  } finally { await server.close() }
})
test('investigation controls render explicit external-action confirmation and protected export', async () => {
  const server = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)), configFile: false, plugins: [react()], server: { middlewareMode: true, hmr: false, watch: null }, optimizeDeps: { noDiscovery: true, include: [] }, logLevel: 'silent' })
  try {
    const { InvestigationControls } = await server.ssrLoadModule('/src/components/IncidentInvestigation.tsx')
    const html = renderToStaticMarkup(React.createElement(InvestigationControls, { incident: { id: 'test', version: 1, status: 'Investigating', assignedTo: '', resolutionNotes: '' }, recommendations: [{ id: 'dhcp_leases', title: 'Check DHCP', description: 'Review' }], changed: () => {} }))
    assert.ok(html.includes('Administrator token')); assert.ok(html.includes('type="password"'))
    assert.ok(html.includes('Export evidence JSON')); assert.ok(html.includes('Export evidence CSV'))
    assert.ok(html.includes('I confirm this external review/action was completed'))
    assert.ok(html.includes('does not change incident status or network settings'))
    assert.ok(html.includes('disabled=""'))
  } finally { await server.close() }
})
