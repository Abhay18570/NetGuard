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
  return <Card title="Detection findings" description="Suspicious observations · Investigation required" action={<Link className="text-link" to="/threats">View evidence</Link>}>
    {result.error ? <p className="feedback" role="alert">Findings unavailable. <button onClick={result.retry}>Retry</button></p> : !data ? <p className="feedback">Loading findings…</p> : <>
      <div className="toolbar"><Badge>{data.live.total} live findings</Badge><Badge>{data.offline.total} offline replay findings</Badge></div>
      {data.status.message && <p className="feedback" role="alert">{data.status.message}</p>}
      {data.live.items.length ? <ul>{data.live.items.slice(0, 3).map(item => <li key={item.id}><Badge>{item.severity}</Badge> {item.sourceIp} · {item.ruleId} · {item.status}</li>)}</ul> : <EmptyState title="No live findings recorded" description="An empty result does not establish network safety. Offline findings can be reviewed separately in Threat Detection." />}
    </>}
  </Card>
}
