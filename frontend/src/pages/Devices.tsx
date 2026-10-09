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
  return <><PageTitle title="Network devices" description="Observed IP–MAC claims and an independently verified network baseline." />
    <div className="notice"><Network size={18} /><p>Inventory records sender claims from passive ARP traffic. One IP may have multiple observed MACs. Observations are never automatically trusted; offline records are isolated by replay session.</p></div>
    {inventoryError && <div className="error-banner" role="alert">{inventoryError}</div>}
    <Card title="Observed inventory" description="First and last seen use packet timestamps, including original timestamps in offline files." action={<Badge>{list.error ? 'Unavailable' : list.loading ? 'Loading…' : `${list.total} mappings`}</Badge>}><div className="toolbar"><SearchInput value={query} onChange={value => { setQuery(value.slice(0, 120)); setOffset(0) }} placeholder="Search IP or MAC…" /><select aria-label="Observation source" value={source} onChange={event => { setSource(event.target.value); setOffset(0) }}><option value="all">All sources</option><option value="live">Live observations</option><option value="offline">Offline replay</option></select><label className="checkbox-label"><input type="checkbox" checked={trusted} onChange={event => { setTrusted(event.target.checked); setOffset(0) }} />Verified live mappings only</label></div>
    {list.error && <div className="error-banner" role="alert">{list.error} <button className="text-button" onClick={list.retry}>Retry</button></div>}
    <DataTable headings={['IP address', 'MAC address', 'Source / Interface', 'First seen', 'Last seen', 'Observations', 'Trust']} hasRows={!!list.items.length} empty={<EmptyState icon={Network} title={list.error ? 'Inventory unavailable' : list.loading ? 'Loading observed inventory…' : query || trusted || source !== 'all' ? 'No matching observations' : 'No device mappings observed yet'} description="Start passive capture or explicitly import an offline PCAP. ARP request targets are not added as discovered devices." />}>{list.items.map(device => <tr key={device.id}><td className="mono">{device.ip}</td><td className="mono">{device.mac}</td><td><Badge tone={device.source === 'live' ? 'green' : ''}>{device.source === 'live' ? `Live · ${device.interface}` : 'Offline replay'}</Badge>{device.source === 'offline' && <small title={device.scope}>Session {device.lastSessionId.slice(0, 8)}</small>}</td><td>{device.firstSeen}</td><td>{device.lastSeen}</td><td>{device.observationCount}</td><td><Badge tone={device.trusted ? 'green' : ''}>{device.trusted ? 'Verified baseline match' : device.source === 'offline' ? 'Offline · Untrusted' : 'Unverified'}</Badge></td></tr>)}</DataTable><Pagination offset={offset} total={list.total} loading={list.loading} onChange={setOffset} /></Card>
    <TrustedMappings /><MappingEvidence />
  </>
}
