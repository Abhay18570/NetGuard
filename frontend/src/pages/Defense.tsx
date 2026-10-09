import { useCallback, useState } from 'react'
import { api } from '../services/api'
import { incidentApi } from '../services/incidents'
import { useCollection } from '../hooks/useCollection'
import { useIncidentRefresh } from '../hooks/useIncidents'
import { Pagination } from '../components/Pagination'
import { MappingEvidence } from '../components/MappingEvidence'
import { Network, ShieldCheck } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle } from '../components/ui'
import { useMonitor } from '../context/useMonitor'
import { IncidentRecords } from './Incidents'
export default function Defense() {
  const { inventoryRevision } = useMonitor(); const { revision, connected } = useIncidentRefresh()
  const [offset, setOffset] = useState(0)
  const verified = useCollection(useCallback(signal => api.getTrustedPage(offset, signal, 'verified'), [offset]), inventoryRevision)
  const summary = useCollection(useCallback(async signal => ({ items: [await incidentApi.summary(signal)], total: 1, limit: 1, offset: 0 }), []), revision + inventoryRevision)
  const info = summary.items[0]
  return <><PageTitle title="Defense center" description="Verify evidence and record a careful, authorized response." action={<Badge>Advisory only</Badge>} /><div className="notice"><ShieldCheck size={20} /><p>NetGuard performs no network changes or containment. Completed checklist items and containment statuses are administrator reports of external work, not independent verification.</p></div>
    {summary.error && <p className="feedback" role="alert">{summary.error} <button onClick={summary.retry}>Retry</button></p>}
    {info && <Card title="Incident response tracking" description="Live and offline administrative status counts remain separate."><div className="toolbar">{(['live', 'offline'] as const).map(source => <div key={source}><strong>{source === 'offline' ? 'Offline replay' : 'Live observations'}</strong><p>{Object.entries(info.counts[source]).map(([state, count]) => `${state}: ${count}`).join(' · ')}</p></div>)}</div><p className="feedback">{info.pendingAlerts} alerts pending correlation · {info.failedAttempts} failed background attempts. {info.capacityMessage}</p><p className="feedback">Database: {Math.ceil(info.storage.usedBytes / 1048576)} MiB / {Math.floor(info.storage.limitBytes / 1048576)} MiB. {info.storage.atCapacity ? 'Storage limit reached; persistence may be incomplete.' : 'No automatic evidence deletion.'}</p></Card>}
    <div className="overview-grid"><Card title="Recommended investigation checklist" description="Guidance only. Select an incident below to record confirmed external work.">{info ? info.recommendations.map(step => <div className="recommendation" key={step.id}><span className="empty-icon"><ShieldCheck size={20} /></span><div><h3>{step.title}</h3><p>{step.description}</p></div></div>) : <EmptyState title={summary.loading ? 'Loading guidance…' : 'Guidance unavailable'} />}</Card>
    <Card title="Explicit gateway baseline status" description="Live configuration only; never applied to offline replay evidence."><DataTable headings={['Mapping', 'Interface / IP', 'MAC', 'Verification']} hasRows={!!info?.gatewayBaselines.length} empty={<EmptyState title={summary.loading ? 'Loading gateway configuration…' : summary.error ? 'Gateway configuration unavailable' : 'No gateway baseline configured'} description="A gateway is checked only when an administrator explicitly configures a trusted mapping ID. It is never inferred from observed traffic." />}>{info?.gatewayBaselines.map(row => <tr key={row.mappingId}><td>{row.mappingId}</td><td>{row.interface || '—'}<small>{row.ip || '—'}</small></td><td className="mono">{row.mac || '—'}</td><td><Badge tone={row.state === 'verified' ? 'green' : ''}>{row.state}</Badge></td></tr>)}</DataTable></Card></div>
    <Card title="Verified mappings" description="Explicitly verified live mappings. Manage and audit the baseline in Network Devices.">{verified.error && <div className="error-banner" role="alert">{verified.error}</div>}<DataTable headings={['Label / Interface', 'IP address', 'Verified MAC', 'Status']} hasRows={!!verified.items.length} empty={<EmptyState icon={Network} title={verified.error ? 'Verified mappings unavailable' : verified.loading ? 'Loading verified mappings…' : 'No verified mappings available'} description="Only explicitly verified live baselines appear here." />}>{verified.items.map(row => <tr key={row.id}><td>{row.label || row.interface}</td><td>{row.ip}</td><td className="mono">{row.mac}</td><td><Badge tone="green">Verified</Badge></td></tr>)}</DataTable><Pagination offset={offset} total={verified.total} loading={verified.loading} onChange={setOffset} /></Card>
    <MappingEvidence /><IncidentRecords revision={revision} connected={connected} recommendations={info?.recommendations ?? []} />
  </>
}
