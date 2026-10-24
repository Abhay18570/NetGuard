import { useCallback, useState, type FormEvent } from 'react'
import { incidentApi, incidentTransitions, validateIncidentChange, type InvestigationDetail, type Recommendation } from '../services/incidents'
import { useCollection } from '../hooks/useCollection'
import { Badge, Card, DataTable, EmptyState } from './ui'
import { Pagination } from './Pagination'
export function IncidentInvestigation({ id, revision, close, recommendations }: { id: string; revision: number; close: () => void; recommendations: Recommendation[] }) {
  const [changed, setChanged] = useState(0); const [offset, setOffset] = useState(0)
  const detail = useCollection(useCallback(async (signal: AbortSignal) => ({ items: [await incidentApi.detail(id, signal)], total: 1, limit: 1, offset: 0 }), [id]), revision + changed)
  const audit = useCollection(useCallback((signal: AbortSignal) => incidentApi.audit(id, offset, signal), [id, offset]), revision + changed)
  const row = detail.items[0]
  return <Card title="Incident investigation" description="Containment and checklist completion are administrator reports, not actions performed or independently verified by NetGuard." action={<button className="text-button" onClick={close}>Close details</button>}>
    {detail.error && <p role="alert" className="feedback">{detail.error} <button onClick={detail.retry}>Retry</button></p>}
    {!row ? <EmptyState title={detail.loading ? 'Loading investigation…' : 'Investigation unavailable'} /> : <>
      <div className="toolbar"><Badge>{row.source === 'offline' ? 'OFFLINE REPLAY · Review scope only' : `Live · ${row.interface}`}</Badge><Badge>{row.status}</Badge><Badge>{row.severity}</Badge></div>
      <dl className="detail-list">{[['Title', row.title], ['Description', row.description], ['Session', row.sessionId], ['First detected', row.firstDetected], ['Last detected', row.lastDetected], ['Assigned investigator', row.assignedTo || 'Unassigned'], ['Resolution notes', row.resolutionNotes || 'None recorded']].map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>
      <DataTable headings={['Alert / Finding', 'Rule / Time', 'Mapping evidence', 'Packet references']} hasRows={!!row.alerts.length} empty={<EmptyState title="No linked evidence" />}>{row.alerts.map(alert => <tr key={alert.id}><td className="mono">{alert.id}<small>{alert.findingId}</small><Badge>{alert.status}</Badge></td><td>{alert.ruleId}<small>{alert.timestamp}</small></td><td>{alert.sourceIp}<small className="mono">{alert.observedMac}</small><small>Prior / expected: {alert.expectedMacs.join(', ') || 'Not observed'}</small></td><td><details><summary>{alert.relatedPacketCount} related packets</summary><p className="wrap-cell mono">{alert.packetIds.join(', ')}</p><p>{alert.reason}</p><pre className="wrap-cell">{JSON.stringify(alert.details, null, 2)}</pre></details></td></tr>)}</DataTable>
      <p className="feedback">Packet IDs reference persisted finding evidence. Raw packet bodies may no longer be retained in the capture buffer.</p>
      <h3 className="feedback">Response checklist reports</h3><div className="settings-body">{recommendations.map(step => { const report = row.completedActions.find(action => action.actionId === step.id); return <div className="recommendation" key={step.id}><div><h3>{step.title}</h3><Badge>{report ? 'Completion reported by administrator' : 'No completion report'}</Badge>{report && <p>{report.actor} · {report.performedAt}<br />{report.description}</p>}</div></div> })}</div>
      <InvestigationControls key={`${row.id}:${row.version}`} incident={row} recommendations={recommendations} changed={() => setChanged(v => v + 1)} />
    </>}
    <h3 className="feedback">Investigation timeline</h3>{audit.error && <p className="feedback" role="alert">{audit.error}</p>}
    <DataTable headings={['Time / Actor', 'Action', 'Status', 'Reason / Details']} hasRows={!!audit.items.length} empty={<EmptyState title={audit.loading ? 'Loading timeline…' : audit.error ? 'Timeline unavailable' : 'No investigation actions recorded'} />}>{audit.items.map(entry => <tr key={entry.id}><td>{entry.timestamp}<small>{entry.actor}</small></td><td>{entry.action}</td><td>{entry.previousStatus || '—'} → {entry.newStatus}</td><td>{entry.reason}<details><summary>Audit evidence</summary><pre className="wrap-cell">{JSON.stringify(entry.details, null, 2)}</pre></details></td></tr>)}</DataTable><Pagination offset={offset} total={audit.total} loading={audit.loading} onChange={setOffset} />
  </Card>
}
export function InvestigationControls({ incident, recommendations, changed }: { incident: InvestigationDetail; recommendations: Recommendation[]; changed: () => void }) {
  const [status, setStatus] = useState(''); const [assigned, setAssigned] = useState(incident.assignedTo); const [notes, setNotes] = useState(incident.resolutionNotes)
  const [confirmed, setConfirmed] = useState(false); const [external, setExternal] = useState(''); const [reason, setReason] = useState(''); const [token, setToken] = useState('')
  const [actionId, setActionId] = useState(''); const [actionConfirmed, setActionConfirmed] = useState(false); const [description, setDescription] = useState(''); const [performedAt, setPerformedAt] = useState('')
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent, action = false) {
    event.preventDefault(); setError('')
    const validation = action ? (!actionConfirmed || !description.trim() || !performedAt || !actionId ? 'Choose an action, describe it, provide its time, and confirm completion.' : '') : validateIncidentChange(status, notes, confirmed, external)
    if (validation) { setError(validation); return }
    setBusy(true)
    try {
      const body = action ? { actionId, description, confirmed: actionConfirmed, performedAt: new Date(performedAt).toISOString(), version: incident.version, reason } : { version: incident.version, reason, assignedTo: assigned, resolutionNotes: notes, ...(status ? { status } : {}), ...(status === 'Contained' ? { containmentConfirmed: confirmed, externalAction: external } : {}) }
      await incidentApi.change(incident.id, body, token, action); setToken(''); changed()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Incident update failed') } finally { setBusy(false) }
  }
  async function download(format: 'json' | 'csv') {
    setBusy(true); setError('')
    try { const blob = await incidentApi.export(incident.id, format, token); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `netguard-incident-${incident.id}.${format}`; document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); setToken('') }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Evidence export failed') } finally { setBusy(false) }
  }
  return <div className="settings-body"><h3>Authorized investigation controls</h3><label className="field">Administrator token<input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></label><label className="field">Audit reason<textarea maxLength={500} value={reason} onChange={e => setReason(e.target.value)} /></label><p>Token stays in memory. Changes require the current version ({incident.version}); refresh if another update wins. Offline actions remain attached only to this replay incident.</p>
    <form onSubmit={event => void submit(event)}><div className="field-grid"><label className="field">Next status<select value={status} onChange={e => setStatus(e.target.value)}><option value="">Keep current status</option>{incidentTransitions[incident.status].map(s => <option key={s}>{s}</option>)}</select></label><label className="field">Assigned investigator<input maxLength={120} value={assigned} onChange={e => setAssigned(e.target.value)} /></label></div><label className="field">Resolution notes<textarea maxLength={2000} value={notes} onChange={e => setNotes(e.target.value)} /></label>
      {status === 'Contained' && <><label className="field">External containment action performed<textarea required maxLength={2000} value={external} onChange={e => setExternal(e.target.value)} /></label><label className="toggle-row"><span>I confirm the described external action was completed. NetGuard did not perform or verify it.</span><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} /></label></>}
      <button className="button" disabled={busy || !token || !reason.trim()}>Save investigation update</button>
    </form>
    <form onSubmit={event => void submit(event, true)}><h3>Response checklist — record a completed external action</h3><label className="field">Investigation step<select value={actionId} onChange={e => setActionId(e.target.value)} required><option value="">Select a completed step</option>{recommendations.map(r => <option key={r.id} value={r.id}>{r.title}</option>)}</select></label><label className="field">Description of work completed<textarea value={description} maxLength={2000} onChange={e => setDescription(e.target.value)} required /></label><label className="field">Performed at (your local time)<input type="datetime-local" required value={performedAt} onChange={e => setPerformedAt(e.target.value)} /></label><label className="toggle-row"><span>I confirm this external review/action was completed. This record does not change incident status or network settings.</span><input type="checkbox" checked={actionConfirmed} onChange={e => setActionConfirmed(e.target.checked)} /></label><button className="button secondary" disabled={busy || !token || !reason.trim()}>Record external action</button></form>
    <div className="toolbar"><button className="button secondary" disabled={busy || !token} onClick={() => void download('json')}>Export evidence JSON</button><button className="button secondary" disabled={busy || !token} onClick={() => void download('csv')}>Export evidence CSV</button></div>{error && <p className="feedback" role="alert">{error}</p>}
  </div>
}
