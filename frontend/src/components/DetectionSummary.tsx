import { useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Badge, Card, EmptyState } from './ui'
import { useCollection } from '../hooks/useCollection'
import { useDetectionRevision } from '../hooks/useDetection'
import { getFindings, getDetectionStatus } from '../services/detection'
export function DetectionSummary() {
  const revision = useDetectionRevision()
  const loader = useCallback(async (signal: AbortSignal) => {
    const [live, offline, status] = await Promise.all([getFindings('live', 'all', '', 0, signal), getFindings('offline', 'all', '', 0, signal), getDetectionStatus(signal)])
    return { items: [{ live, offline, status }], total: 1, limit: 1, offset: 0 }
  }, [])
  const result = useCollection(loader, revision); const data = result.items[0]
  const latest = data ? [...data.live.items, ...data.offline.items].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 4) : []
  return <Card title="Threat summary" action={<Link className="text-link" to="/threats">View findings</Link>}>
    {result.error ? <p className="feedback" role="alert">Findings unavailable. <button onClick={result.retry}>Retry</button></p> : !data ? <p className="feedback">Loading…</p> : <>
      <div className="toolbar compact-summary"><Badge>{data.live.total} live</Badge><Badge>{data.offline.total} offline</Badge></div>
      {data.status.message && <p className="feedback" role="alert">{data.status.message}</p>}
      {latest.length ? <ul className="threat-summary-list">{latest.map(item => <li key={item.id}><Badge tone={item.severity === 'High' ? 'danger' : ''}>{item.severity}</Badge><span>{item.sourceIp} · {item.ruleId}</span><Badge tone={item.source === 'live' ? 'green' : 'muted'}>{item.source === 'live' ? 'Live' : 'Offline'}</Badge></li>)}</ul> : <EmptyState title="No findings recorded" />}
    </>}
  </Card>
}
