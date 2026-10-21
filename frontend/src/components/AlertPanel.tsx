import { useCallback, useState, type FormEvent } from 'react'
import { ShieldAlert } from 'lucide-react'
import { alertApi, alertStates, nextStatuses, alertEmptyLabel, type AlertState, type SecurityAlert } from '../services/alerts'
import { useAlerts } from '../context/useAlerts'
import { useCollection } from '../hooks/useCollection'
import { Pagination } from './Pagination'
import { Badge, Card, DataTable, EmptyState, SearchInput } from './ui'
export function AlertPanel() {
  const { revision, connected, summary, error } = useAlerts()
  const [source, setSource] = useState('live'); const [severity, setSeverity] = useState('all'); const [status, setStatus] = useState('all'); const [query, setQuery] = useState(''); const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<SecurityAlert | null>(null)
  const loader = useCallback((signal: AbortSignal) => alertApi.list(source, severity, status, query, offset, signal), [source, severity, status, query, offset])
  const rows = useCollection(loader, revision)
  return <><Card title="Security alerts" action={<Badge>{connected ? 'Connected' : 'Reconnecting'}</Badge>}>
    <div className="toolbar compact-summary"><Badge>{summary ? summary.counts.live.New : '—'} new live</Badge><Badge>{summary ? summary.counts.offline.New : '—'} new offline</Badge></div>
    {!!summary?.pendingFindings && <p className="feedback">{summary.pendingFindings} findings awaiting alert processing.</p>}
    {(error || rows.error) && <p className="feedback" role="alert">{error || rows.error} <button onClick={rows.retry}>Retry</button></p>}
    <div className="toolbar"><SearchInput value={query} onChange={v => { setQuery(v); setOffset(0) }} placeholder="Search alerts" />{[
      { label: 'Alert source', value: source, setter: setSource, values: ['live', 'offline', 'all'] },
      { label: 'Alert severity', value: severity, setter: setSeverity, values: ['all', 'Low', 'Medium', 'High'] },
      { label: 'Alert status', value: status, setter: setStatus, values: ['all', ...alertStates] },
    ].map(filter => <select key={filter.label} aria-label={filter.label} value={filter.value} onChange={e => { filter.setter(e.target.value); setOffset(0) }}>{filter.values.map(value => <option key={value}>{value}</option>)}</select>)}</div>
    <DataTable headings={['Time / Source','Severity','Detection type','IP / MAC','Status','Evidence']} hasRows={rows.items.length > 0} empty={<EmptyState icon={ShieldAlert} title={alertEmptyLabel(rows.loading, rows.error)}/>}>{rows.items.map(alert => <tr key={alert.id}><td title={alert.timestamp}>{new Date(alert.timestamp).toLocaleTimeString()}<small>{alert.source === 'offline' ? 'Offline' : 'Live'}</small></td><td><Badge tone={alert.severity === 'High' ? 'danger' : ''}>{alert.severity}</Badge></td><td>{alert.ruleId}</td><td>{alert.sourceIp}<small className="mono">{alert.observedMac}</small></td><td>{alert.status}</td><td><button className="text-button" onClick={() => setSelected(alert)}>Review</button></td></tr>)}</DataTable>
    <Pagination offset={offset} total={rows.total} loading={rows.loading} onChange={setOffset} />
  </Card>{selected && <AlertDetails key={selected.id} alert={selected} onChange={setSelected} close={() => setSelected(null)} />}</>
}
function AlertDetails({ alert, onChange, close }: { alert: SecurityAlert; onChange: (alert: SecurityAlert) => void; close: () => void }) {
  const { revision } = useAlerts(); const [status, setStatus] = useState<AlertState>(nextStatuses[alert.status][0]); const [reason, setReason] = useState(''); const [token, setToken] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false); const [offset, setOffset] = useState(0)
  const loader = useCallback((signal: AbortSignal) => alertApi.audit(alert.id, offset, signal), [alert.id, offset])
  const audit = useCollection(loader, revision + alert.version)
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(''); try { const updated = await alertApi.update(alert, status, reason, token); onChange(updated); setStatus(nextStatuses[updated.status][0]); setToken(''); setReason('') } catch (cause) { setError(cause instanceof Error ? cause.message : 'Update failed') } finally { setBusy(false) } }
  return <Card title="Alert details" action={<button className="text-button" onClick={close}>Close</button>}><dl className="detail-list">{Object.entries(alert).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}</dd></div>)}</dl>
    <form onSubmit={submit} className="settings-body"><h3>Update status</h3><label className="field">Next status<select value={status} onChange={e => setStatus(e.target.value as AlertState)}>{nextStatuses[alert.status].map(s => <option key={s}>{s}</option>)}</select></label><label className="field">Audit reason<textarea required maxLength={500} value={reason} onChange={e => setReason(e.target.value)} /></label><label className="field">Administrator token<input type="password" autoComplete="off" required value={token} onChange={e => setToken(e.target.value)} /></label><button className="button" disabled={busy}>{busy ? 'Saving…' : 'Update status'}</button>{error && <p role="alert">{error}</p>}</form>
    <h3 className="feedback">Audit history</h3>{audit.error && <p role="alert">{audit.error}</p>}<DataTable headings={['Time','Actor','Transition','Reason']} hasRows={!!audit.items.length} empty={<EmptyState title={audit.loading ? 'Loading audit…' : audit.error ? 'Audit unavailable' : 'No status changes'}/>}>{audit.items.map(entry => <tr key={entry.id}><td>{entry.timestamp}</td><td>{entry.actor}</td><td>{entry.previousStatus} → {entry.newStatus}</td><td>{entry.reason}</td></tr>)}</DataTable><Pagination offset={offset} total={audit.total} loading={audit.loading} onChange={setOffset}/>
  </Card>
}
