import { useCallback, useState } from 'react'
import { api } from '../services/api'
import { useCollection } from '../hooks/useCollection'
import { useMonitor } from '../context/useMonitor'
import { Badge, Card, DataTable, EmptyState } from './ui'
import { Pagination } from './Pagination'
export function MappingEvidence() {
  const { inventoryRevision } = useMonitor()
  const [offset, setOffset] = useState(0)
  const list = useCollection(useCallback(signal => api.getConflicts(offset, signal), [offset]), inventoryRevision)
  return <Card title="Mapping differences" action={<Badge>Unclassified</Badge>}>
    {list.error && <div className="error-banner" role="alert">{list.error} <button className="text-button" onClick={list.retry}>Retry</button></div>}
    <DataTable headings={['IP / Source','Observed MAC','Verified MAC','Difference']} hasRows={!!list.items.length} empty={<EmptyState title={list.error ? 'Evidence unavailable' : list.loading ? 'Loading…' : 'No mapping differences'}/>}>{list.items.map(row => <tr key={`${row.scope}:${row.ip}`}><td>{row.ip}<small>{row.source === 'offline' ? `Offline · ${row.scope.slice(-8)}` : `Live · ${row.interface}`}</small></td><td className="mono">{row.observedMappings.map(mapping => <div key={mapping.id}>{mapping.mac}</div>)}</td><td className="mono">{row.trustedMappings.length ? row.trustedMappings.map(mapping => <div key={mapping.id}>{mapping.mac}</div>) : row.source === 'offline' ? 'Not compared' : 'No verified baseline'}</td><td className="wrap-cell">{row.reasons.map(reason => <div key={reason}>{reason === 'multiple_observed_macs' ? 'Multiple MACs observed' : 'MAC differs from baseline'}</div>)}</td></tr>)}</DataTable><Pagination offset={offset} total={list.total} loading={list.loading} onChange={setOffset}/>
  </Card>
}
