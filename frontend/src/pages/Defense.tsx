import { useCallback } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { incidentApi } from '../services/incidents'
import { useCollection } from '../hooks/useCollection'
import { useIncidentRefresh } from '../hooks/useIncidents'
import { Badge, Card, DataTable, EmptyState, PageTitle } from '../components/ui'

export default function Defense() {
  const { revision } = useIncidentRefresh()
  const summary = useCollection(useCallback(async signal => ({ items: [await incidentApi.summary(signal)], total: 1, limit: 1, offset: 0 }), []), revision)
  const info = summary.items[0]
  return <>
    <PageTitle title="Defense Center"/>
    <p className="advisory-note"><ShieldCheck size={16}/> Advice only. NetGuard does not change network settings.</p>
    {summary.error && <p className="error-banner" role="alert">{summary.error} <button className="text-button" onClick={summary.retry}>Retry</button></p>}
    <div className="overview-grid defense-grid">
      <Card title="Recommended actions">{info ? info.recommendations.map(step => <div className="recommendation" key={step.id}><span className="recommendation-number">{step.id}</span><div><h3>{step.title}</h3><p>{step.description}</p></div></div>) : <EmptyState title={summary.loading ? 'Loading…' : 'Guidance unavailable'}/>}</Card>
      <Card title="Gateway verification"><DataTable headings={['Interface / IP','Expected MAC','Status']} hasRows={!!info?.gatewayBaselines.length} empty={<EmptyState title={summary.loading ? 'Loading…' : 'No gateway baseline configured'}/>}>{info?.gatewayBaselines.map(row => <tr key={row.mappingId}><td>{row.interface || '—'}<small>{row.ip || '—'}</small></td><td className="mono">{row.mac || '—'}</td><td><Badge tone={row.state === 'verified' ? 'green' : ''}>{row.state}</Badge></td></tr>)}</DataTable></Card>
    </div>
    <Card title="Trusted mappings" action={<Link className="text-link" to="/devices">Review devices <ArrowRight size={14}/></Link>}><p className="compact-copy">Manage verified network baselines in Network Devices.</p></Card>
    <details className="advanced-panel"><summary>Response and storage diagnostics</summary>{info && <Card title="System status"><div className="diagnostic-grid"><div><strong>Live alerts</strong><span>{Object.entries(info.counts.live).map(([state,count]) => `${state} ${count}`).join(' · ')}</span></div><div><strong>Offline alerts</strong><span>{Object.entries(info.counts.offline).map(([state,count]) => `${state} ${count}`).join(' · ')}</span></div><div><strong>Analysis queue</strong><span>{info.pendingAlerts} pending · {info.failedAttempts} failed</span></div><div><strong>Database</strong><span>{Math.ceil(info.storage.usedBytes / 1048576)} / {Math.floor(info.storage.limitBytes / 1048576)} MiB{info.storage.atCapacity ? ' · At capacity' : ''}</span></div></div>{info.capacityMessage && <p className="feedback">{info.capacityMessage}</p>}</Card>}</details>
  </>
}
