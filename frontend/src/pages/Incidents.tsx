import { useCallback, useState } from 'react'
import { incidentApi, incidentStates, incidentEmptyLabel, type Recommendation } from '../services/incidents'
import { useIncidentRefresh } from '../hooks/useIncidents'
import { useCollection } from '../hooks/useCollection'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { Pagination } from '../components/Pagination'
import { IncidentInvestigation } from '../components/IncidentInvestigation'
export function IncidentRecords({ revision, recommendations }: { revision: number; recommendations: Recommendation[] }) {
  const [source, setSource] = useState('all'); const [severity, setSeverity] = useState('all'); const [status, setStatus] = useState('all'); const [query, setQuery] = useState(''); const [offset, setOffset] = useState(0); const [selected, setSelected] = useState<string | null>(null)
  const rows = useCollection(useCallback(signal => incidentApi.list(source, severity, status, query, offset, signal), [source, severity, status, query, offset]), revision)
  return <><Card title="Incidents">
    {rows.error && <p className="feedback" role="alert">{rows.error} <button onClick={rows.retry}>Retry</button></p>}
    <div className="toolbar"><SearchInput value={query} onChange={v => { setQuery(v); setOffset(0) }} placeholder="Search incidents" />{[
      { label: 'Incident source', value: source, setter: setSource, values: ['all', 'live', 'offline'] },
      { label: 'Incident severity', value: severity, setter: setSeverity, values: ['all', 'Low', 'Medium', 'High'] },
      { label: 'Incident status', value: status, setter: setStatus, values: ['all', ...incidentStates] },
    ].map(filter => <select key={filter.label} aria-label={filter.label} value={filter.value} onChange={e => { filter.setter(e.target.value); setOffset(0) }}>{filter.values.map(value => <option key={value}>{value}</option>)}</select>)}</div>
    <DataTable headings={['Incident','Source','Severity','Status','Alerts','Updated']} hasRows={!!rows.items.length} empty={<EmptyState title={incidentEmptyLabel(rows.loading, rows.error)} />}>{rows.items.map(row => <tr key={row.id}><td><button className="text-button" onClick={() => setSelected(row.id)}>{row.title}</button><small>{row.firstDetected}</small></td><td><Badge tone={row.source === 'live' ? 'green' : 'muted'}>{row.source === 'offline' ? 'Offline' : 'Live'}</Badge></td><td><Badge tone={row.severity === 'High' ? 'danger' : ''}>{row.severity}</Badge></td><td>{row.status}<small>{row.assignedTo || 'Unassigned'}</small></td><td>{row.alertIds.length}</td><td>{row.updatedAt}</td></tr>)}</DataTable><Pagination offset={offset} total={rows.total} loading={rows.loading} onChange={setOffset} />
  </Card>{selected && <IncidentInvestigation id={selected} key={selected} revision={revision} close={() => setSelected(null)} recommendations={recommendations} />}</>
}
export default function Incidents() {
  const { revision } = useIncidentRefresh()
  const summary = useCollection(useCallback(async signal => ({ items: [await incidentApi.summary(signal)], total: 1, limit: 1, offset: 0 }), []), revision)
  const info = summary.items[0]
  return <><PageTitle title="Incident history" />
    {summary.error && <p className="feedback" role="alert">{summary.error}</p>}
    {(info?.pendingAlerts || info?.capacityMessage || info?.failedAttempts) ? <p className="feedback" role="status">{info.pendingAlerts ? `${info.pendingAlerts} alerts awaiting correlation. ` : ''}{info.capacityMessage}{info.failedAttempts ? ` ${info.failedAttempts} processing failures.` : ''}</p> : null}
    <IncidentRecords revision={revision} recommendations={info?.recommendations ?? []} />
  </>
}
