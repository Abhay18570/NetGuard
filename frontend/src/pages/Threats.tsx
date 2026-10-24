import { useCallback, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { AlertPanel } from '../components/AlertPanel'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { Pagination } from '../components/Pagination'
import { useAlerts } from '../context/useAlerts'
import { useCollection } from '../hooks/useCollection'
import { useDetectionRevision } from '../hooks/useDetection'
import { getFindings, getDetectionStatus, type Finding } from '../services/detection'

export default function Threats() {
  const [source, setSource] = useState('all'); const [severity, setSeverity] = useState('all'); const [q, setQ] = useState(''); const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Finding | null>(null)
  const revision = useDetectionRevision(); const { summary: alertSummary } = useAlerts()
  const loader = useCallback((signal: AbortSignal) => getFindings(source, severity, q, offset, signal), [source, severity, q, offset])
  const totalsLoader = useCallback(async (signal: AbortSignal) => {
    const [all, high] = await Promise.all([getFindings('all', 'all', '', 0, signal), getFindings('all', 'High', '', 0, signal)])
    return { items: [{ total: all.total, high: high.total }], total: 1, limit: 1, offset: 0 }
  }, [])
  const statusLoader = useCallback(async (signal: AbortSignal) => ({ items: [await getDetectionStatus(signal)], total: 1, limit: 1, offset: 0 }), [])
  const rows = useCollection(loader, revision); const totals = useCollection(totalsLoader, revision); const status = useCollection(statusLoader, revision)
  const alertCount = alertSummary ? Object.values(alertSummary.counts).reduce((sum, states) => sum + Object.values(states).reduce((count, value) => count + value, 0), 0) : null
  return <>
    <PageTitle title="Threat Detection" />
    <div className="threat-stats" aria-label="Detection summary"><div><strong>{totals.items[0]?.total ?? '—'}</strong><span>Findings</span></div><div><strong>{alertCount ?? '—'}</strong><span>Alerts</span></div><div><strong>{totals.items[0]?.high ?? '—'}</strong><span>High severity</span></div></div>
    <Card title="Findings">
      {(rows.error || status.error || totals.error) && <p className="error-banner" role="alert">{rows.error || status.error || totals.error} <button className="text-button" onClick={() => { rows.retry(); totals.retry(); status.retry() }}>Retry</button></p>}
      {status.items[0]?.message && <p className="feedback" role="alert">{status.items[0].message}</p>}
      <div className="toolbar"><SearchInput value={q} onChange={value => { setQ(value); setOffset(0) }} placeholder="Search IP, MAC or rule"/><select aria-label="Finding source" value={source} onChange={event => { setSource(event.target.value); setOffset(0) }}>{['all','live','offline'].map(value => <option key={value} value={value}>{value === 'all' ? 'All sources' : value === 'live' ? 'Live' : 'Offline'}</option>)}</select><select aria-label="Finding severity" value={severity} onChange={event => { setSeverity(event.target.value); setOffset(0) }}>{['all','Low','Medium','High'].map(value => <option key={value} value={value}>{value === 'all' ? 'All severities' : value}</option>)}</select></div>
      <DataTable headings={['Time','Source','Detection type','Severity','IP / MAC','Status','Evidence']} hasRows={!!rows.items.length} empty={<EmptyState icon={ShieldAlert} title={rows.loading ? 'Loading findings…' : rows.error ? 'Findings unavailable' : 'No findings recorded'} description="Findings appear when observed traffic matches a detection rule."/>}>{rows.items.map(row => <tr key={row.id}><td title={row.timestamp}>{new Date(row.timestamp).toLocaleString()}</td><td><Badge tone={row.source === 'live' ? 'green' : 'muted'}>{row.source === 'live' ? 'Live' : 'Offline'}</Badge></td><td>{row.ruleId}</td><td><Badge tone={row.severity === 'High' ? 'danger' : ''}>{row.severity}</Badge></td><td className="mono">{row.sourceIp}<small>{row.observedMac}</small></td><td>{row.status}</td><td><button className="text-button" onClick={() => setSelected(row)}>Details</button></td></tr>)}</DataTable>
      <Pagination offset={offset} total={rows.total} loading={rows.loading} onChange={setOffset}/>
    </Card>
    {selected && <Card title="Finding details" action={<button className="text-button" onClick={() => setSelected(null)}>Close</button>}><dl className="detail-list">{Object.entries(selected).map(([key,value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}</dd></div>)}</dl></Card>}
    <details className="advanced-panel"><summary>Detection diagnostics</summary><Card title="Effective configuration"><dl className="detail-list">{Object.entries(status.items[0]?.thresholds ?? {}).map(([key,value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}<div><dt>Gateway mappings</dt><dd>{status.items[0]?.gatewayMappingIds.join(', ') || 'None configured'}</dd></div><div><dt>Pending analysis</dt><dd>{status.items[0]?.pendingPackets ?? 'Unavailable'}</dd></div></dl></Card></details>
    <AlertPanel />
  </>
}
