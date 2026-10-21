import { useCallback, useState, type FormEvent, type SyntheticEvent } from 'react'
import { ShieldCheck } from 'lucide-react'
import { api } from '../services/api'
import { useCollection } from '../hooks/useCollection'
import { useMonitor } from '../context/useMonitor'
import type { TrustedMapping, TrustAudit } from '../types'
import { Badge, Card, DataTable, EmptyState } from './ui'
import { Pagination } from './Pagination'

const emptyForm = { ip: '', mac: '', interface: '', label: '' }
export function TrustedMappings() {
  const { interfaces, inventoryRevision } = useMonitor()
  const [offset, setOffset] = useState(0); const [localRevision, setRevision] = useState(0)
  const list = useCollection(useCallback(signal => api.getTrustedPage(offset, signal), [offset]), inventoryRevision + localRevision)
  const [token, setToken] = useState(''); const [reason, setReason] = useState('')
  const [form, setForm] = useState(emptyForm); const [editing, setEditing] = useState<TrustedMapping | null>(null); const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [error, setError] = useState('')
  const [auditId, setAuditId] = useState<string | null>(null); const [auditOffset, setAuditOffset] = useState(0)
  const audit = useCollection<TrustAudit>(useCallback(signal => auditId ? api.getAudit(auditId, auditOffset, signal) : Promise.resolve({ items: [], total: 0, limit: 25, offset: 0 }), [auditId, auditOffset]), inventoryRevision + localRevision)
  function edit(row: TrustedMapping) { setEditing(row); setForm({ ip: row.ip, mac: row.mac, interface: row.interface, label: row.label }); setReason(''); setMessage(''); setError(''); setFormOpen(true) }
  async function change(action: 'create' | 'update' | 'verify' | 'revoke', row: TrustedMapping | null = null) {
    setError(''); setMessage('')
    if (!token || !reason.trim()) { setError('Enter your administrator token and an audit reason.'); setFormOpen(true); return }
    setBusy(true)
    try {
      const result = await api.changeTrust(action, row?.id ?? null, { ...(action === 'create' || action === 'update' ? form : {}), reason, ...(row ? { version: row.version } : {}) }, token)
      setMessage(action === 'create' ? 'Mapping created as pending.' : `Mapping ${action === 'update' ? 'updated' : action === 'verify' ? 'verified' : 'revoked'}.`)
      setReason(''); setEditing(null); setForm(emptyForm); setFormOpen(false); setOffset(0); setAuditId(result.id); setAuditOffset(0)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The mapping change failed.'); setFormOpen(true) }
    finally { setBusy(false); setRevision(value => value + 1) }
  }
  function submit(event: FormEvent) { event.preventDefault(); void change(editing ? 'update' : 'create', editing) }
  function toggleForm(event: SyntheticEvent<HTMLDetailsElement>) { setFormOpen(event.currentTarget.open) }
  return <>
    <Card title="Trusted mappings">
      {list.error && <div role="alert" className="error-banner">{list.error} <button className="text-button" onClick={list.retry}>Retry</button></div>}
      <DataTable headings={['IP / Label','MAC address','Interface','State','Actions']} hasRows={!!list.items.length} empty={<EmptyState icon={ShieldCheck} title={list.error ? 'Mappings unavailable' : list.loading ? 'Loading…' : 'No trusted mappings'}/>}>{list.items.map(row => <tr key={row.id}><td>{row.ip}<small>{row.label}</small></td><td className="mono">{row.mac}</td><td>{row.interface}</td><td><Badge tone={row.state === 'verified' ? 'green' : ''}>{row.state}</Badge></td><td><div className="row-actions"><button className="text-button" disabled={busy} onClick={() => edit(row)}>Edit</button><button className="text-button" disabled={busy || row.state !== 'pending'} onClick={() => void change('verify', row)}>Verify</button><button className="text-button" disabled={busy || row.state === 'revoked'} onClick={() => void change('revoke', row)}>Revoke</button><button className="text-button" onClick={() => { setAuditId(row.id); setAuditOffset(0) }}>Audit</button></div></td></tr>)}</DataTable>
      <Pagination offset={offset} total={list.total} loading={list.loading} onChange={setOffset}/>
      <details className="advanced-panel trust-form-disclosure" open={formOpen || !!editing} onToggle={toggleForm}><summary>{editing ? 'Edit mapping' : 'Add trusted mapping'}</summary><form onSubmit={submit} className="settings-body trust-form"><p>New mappings start pending. Verify against an independent inventory.</p><div className="field-grid"><label className="field">IPv4 address<input required value={form.ip} maxLength={15} onChange={event => setForm({ ...form, ip: event.target.value })} placeholder="IPv4 address"/></label><label className="field">Unicast MAC address<input required value={form.mac} maxLength={32} onChange={event => setForm({ ...form, mac: event.target.value })} placeholder="MAC address"/></label><label className="field">Live network interface<select required value={form.interface} onChange={event => setForm({ ...form, interface: event.target.value })}><option value="">Select an interface</option>{form.interface && !interfaces.some(item => item.name === form.interface) && <option value={form.interface}>{form.interface} — unavailable</option>}{interfaces.map(item => <option key={`${item.index}-${item.name}`} value={item.name}>{item.networkName || item.name}{item.description ? ` — ${item.description}` : item.networkName && item.name !== item.networkName ? ` (${item.name})` : ''}</option>)}</select></label><label className="field">Label<input value={form.label} maxLength={120} onChange={event => setForm({ ...form, label: event.target.value })}/></label><label className="field">Administrator token<input type="password" autoComplete="off" value={token} onChange={event => setToken(event.target.value)}/><small>Held in memory only.</small></label><label className="field">Audit reason<input value={reason} maxLength={500} onChange={event => setReason(event.target.value)} placeholder="Reason for change"/></label></div><div className="save-row"><button className="button secondary" type="button" onClick={() => { setToken(''); setReason(''); setEditing(null); setForm(emptyForm); setFormOpen(false); setError('') }}>Clear</button><button className="button" disabled={busy} type="submit">{busy ? 'Saving…' : editing ? 'Update mapping' : 'Create pending mapping'}</button></div>{error && <div className="error-banner" role="alert">{error}</div>}{message && <div className="feedback" role="status">{message}</div>}</form></details>
    </Card>
    {auditId && <Card title="Mapping audit history" action={<button className="text-button" onClick={() => setAuditId(null)}>Close</button>}>{audit.error && <div className="error-banner" role="alert">{audit.error}</div>}<DataTable headings={['Time / Actor','Action','Reason','Before','After']} hasRows={!!audit.items.length} empty={<EmptyState title={audit.error ? 'Audit history unavailable' : audit.loading ? 'Loading…' : 'No audit entries'}/>}>{audit.items.map(row => <tr key={row.id}><td>{row.timestamp}<small>{row.actor}</small></td><td>{row.action}</td><td className="wrap-cell">{row.reason}</td><td>{row.before ? <>{row.before.ip}<small>{row.before.mac}</small><small>{row.before.interface} · {row.before.state} · v{row.before.version}</small><small>{row.before.label}</small></> : '—'}</td><td>{row.after.ip}<small>{row.after.mac}</small><small>{row.after.interface} · {row.after.state} · v{row.after.version}</small><small>{row.after.label}</small></td></tr>)}</DataTable><Pagination offset={auditOffset} total={audit.total} loading={audit.loading} onChange={setAuditOffset}/></Card>}
  </>
}
