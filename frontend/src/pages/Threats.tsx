import { AlertPanel } from '../components/AlertPanel'
import { useCallback, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { Pagination } from '../components/Pagination'
import { useCollection } from '../hooks/useCollection'
import { useDetectionRevision } from '../hooks/useDetection'
import { getFindings, getDetectionStatus, type Finding } from '../services/detection'
export default function Threats() {
  const [source, setSource] = useState('live'); const [severity, setSeverity] = useState('all'); const [q, setQ] = useState(''); const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Finding | null>(null)
  const revision = useDetectionRevision()
  const loader = useCallback((signal: AbortSignal) => getFindings(source, severity, q, offset, signal), [source, severity, q, offset])
  const statusLoader = useCallback(async (signal: AbortSignal) => ({ items: [await getDetectionStatus(signal)], total: 1, limit: 1, offset: 0 }), [])
  const rows = useCollection(loader, revision); const status = useCollection(statusLoader, revision)
  return <><PageTitle title="Threat detection" description="Explainable suspicious observations. Findings are not confirmed attacks." />
    <AlertPanel /><Card title="Detection findings" description="Live observations and offline replay evidence remain separate." action={<Badge>{source === 'offline' ? 'Offline PCAP evidence' : source === 'all' ? 'Mixed sources · See labels' : 'Live observations'}</Badge>}>
      {(rows.error || status.error) && <p className="feedback" role="alert">Detection unavailable: {rows.error || status.error} <button onClick={() => { rows.retry(); status.retry() }}>Retry</button></p>}
      {status.items[0]?.message && <p className="feedback" role="alert">{status.items[0].message} Failed: {status.items[0].failedPackets}; dropped: {status.items[0].droppedPackets}; out of order: {status.items[0].latePackets}.</p>}
      <div className="toolbar"><SearchInput value={q} onChange={v => { setQ(v); setOffset(0) }} placeholder="Search finding, IP, MAC or rule…" /><select aria-label="Finding source" value={source} onChange={e => { setSource(e.target.value); setOffset(0) }}>{['live', 'offline', 'all'].map(v => <option key={v}>{v}</option>)}</select><select aria-label="Finding severity" value={severity} onChange={e => { setSeverity(e.target.value); setOffset(0) }}>{['all', 'Low', 'Medium', 'High'].map(v => <option key={v}>{v}</option>)}</select></div>
      <DataTable headings={['Time / Source', 'Rule', 'Severity / Confidence', 'IP / Observed MAC', 'Reason', 'Investigation']} hasRows={!!rows.items.length} empty={<EmptyState icon={ShieldAlert} title={rows.loading ? 'Loading findings…' : rows.error ? 'Findings unavailable' : 'No matching findings'} description="No findings does not establish network safety. Start a capture or explicitly import an offline PCAP to analyze observed evidence." />}>{rows.items.map(row => <tr key={row.id}><td>{row.timestamp}<small>{row.source === 'offline' ? 'OFFLINE REPLAY' : row.interface}</small></td><td><button className="text-button" onClick={() => setSelected(row)}>{row.ruleId}</button></td><td><Badge tone={row.severity === 'High' ? 'danger' : ''}>{row.severity}</Badge><small>{row.confidence} confidence</small></td><td className="mono">{row.sourceIp}<small>{row.observedMac}</small></td><td>{row.reason}</td><td>{row.status}</td></tr>)}</DataTable>
      <Pagination offset={offset} total={rows.total} loading={rows.loading} onChange={setOffset} />
    </Card>
    {selected && <Card title="Finding evidence" description="Immutable observation evidence; use the associated alert above for audited investigation status changes." action={<button className="text-button" onClick={() => setSelected(null)}>Close</button>}><dl className="detail-list">{Object.entries(selected).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}</dd></div>)}</dl></Card>}
    <Card title="Effective detection configuration" description="Read-only server configuration. Settings drafts do not change these thresholds."><dl className="detail-list">{Object.entries(status.items[0]?.thresholds ?? {}).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}<div><dt>Explicit gateway mapping IDs</dt><dd>{status.items[0]?.gatewayMappingIds.join(', ') || 'None configured'}</dd></div><div><dt>Pending analysis</dt><dd>{status.items[0]?.pendingPackets ?? 'Unavailable'}</dd></div></dl></Card>
  </>
}
