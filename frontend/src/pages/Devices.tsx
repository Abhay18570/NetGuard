import { useCallback, useState } from 'react'
import { Network } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { Pagination } from '../components/Pagination'
import { TrustedMappings } from '../components/TrustedMappings'
import { MappingEvidence } from '../components/MappingEvidence'
import { useMonitor } from '../context/useMonitor'
import { useCollection } from '../hooks/useCollection'
import { api } from '../services/api'
export default function Devices() {
  const { inventoryRevision, inventoryError } = useMonitor()
  const [query, setQuery] = useState(''); const [trusted, setTrusted] = useState(false)
  const [source, setSource] = useState('all'); const [offset, setOffset] = useState(0)
  const list = useCollection(useCallback(signal => api.getDevicePage(query, source, trusted, offset, signal), [query, source, trusted, offset]), inventoryRevision)
  return <><PageTitle title="Network Devices" />
    {inventoryError && <div className="error-banner" role="alert">{inventoryError}</div>}
    <Card title="Observed mappings" action={<Badge>{list.error ? 'Unavailable' : list.loading ? 'Loading…' : `${list.total} devices`}</Badge>}><div className="toolbar"><SearchInput value={query} onChange={value => { setQuery(value.slice(0, 120)); setOffset(0) }} placeholder="Search IP or MAC" /><select aria-label="Observation source" value={source} onChange={event => { setSource(event.target.value); setOffset(0) }}><option value="all">All sources</option><option value="live">Live</option><option value="offline">Offline</option></select><label className="checkbox-label"><input type="checkbox" checked={trusted} onChange={event => { setTrusted(event.target.checked); setOffset(0) }} />Verified only</label></div>
    {list.error && <div className="error-banner" role="alert">{list.error} <button className="text-button" onClick={list.retry}>Retry</button></div>}
    <DataTable headings={['IP address','MAC address','Source','Last observed','Trust']} hasRows={!!list.items.length} empty={<EmptyState icon={Network} title={list.error ? 'Inventory unavailable' : list.loading ? 'Loading devices…' : query || trusted || source !== 'all' ? 'No matching devices' : 'No devices observed'} description="Start monitoring to discover devices."/>}>{list.items.map(device => <tr key={device.id}><td className="mono">{device.ip}</td><td className="mono">{device.mac}</td><td><Badge tone={device.source === 'live' ? 'green' : 'muted'}>{device.source === 'live' ? 'Live' : 'Offline'}</Badge>{device.source === 'live' && <small>{device.interface}</small>}{device.source === 'offline' && <small title={device.scope}>Session {device.lastSessionId.slice(0, 8)}</small>}</td><td>{device.lastSeen}</td><td><Badge tone={device.trusted ? 'green' : ''}>{device.trusted ? 'Verified' : 'Not verified'}</Badge></td></tr>)}</DataTable><Pagination offset={offset} total={list.total} loading={list.loading} onChange={setOffset} /></Card>
    <TrustedMappings /><MappingEvidence />
  </>
}
