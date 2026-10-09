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
  return <Card title="Mapping differences" description="Structured evidence for review. These observations have not been classified as attacks." action={<Badge>Unclassified</Badge>}>
    {list.error && <div className="error-banner" role="alert">{list.error} <button className="text-button" onClick={list.retry}>Retry</button></div>}
    <DataTable headings={['IP / Source', 'Observed MAC addresses', 'Verified baseline MACs', 'Difference']} hasRows={!!list.items.length} empty={<EmptyState title={list.error ? 'Mapping evidence unavailable' : list.loading ? 'Loading evidence…' : 'No mapping differences recorded'} description="Comparisons stay within the same live interface or offline replay session. An empty list is not a security verdict." />}>{list.items.map(row => <tr key={`${row.scope}:${row.ip}`}><td>{row.ip}<small>{row.source === 'offline' ? `Offline replay · ${row.scope.slice(-8)}` : `Live · ${row.interface}`}</small></td><td className="mono">{row.observedMappings.map(mapping => <div key={mapping.id}>{mapping.mac}</div>)}</td><td className="mono">{row.trustedMappings.length ? row.trustedMappings.map(mapping => <div key={mapping.id}>{mapping.mac}</div>) : row.source === 'offline' ? 'Offline · Not compared to live trust' : 'No verified baseline'}</td><td className="wrap-cell">{row.reasons.map(reason => <div key={reason}>{reason === 'multiple_observed_macs' ? 'Multiple MAC addresses observed for this IP' : 'Observed MAC differs from verified baseline'}</div>)}</td></tr>)}</DataTable><Pagination offset={offset} total={list.total} loading={list.loading} onChange={setOffset} />
  </Card>
}
