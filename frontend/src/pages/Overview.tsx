import { useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Monitor, Network, Radio, ShieldAlert } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle } from '../components/ui'
import { DetectionSummary } from '../components/DetectionSummary'
import { useMonitor } from '../context/useMonitor'
import { useCollection } from '../hooks/useCollection'
import { useDetectionRevision } from '../hooks/useDetection'
import { useIncidentRefresh } from '../hooks/useIncidents'
import { getFindings } from '../services/detection'
import { incidentApi } from '../services/incidents'

export default function Overview() {
  const { data, connection, monitor, inventoryError } = useMonitor()
  const detection = useCollection(useCallback(async signal => ({ items: [{ total: (await getFindings('all', 'all', '', 0, signal)).total }], total: 1, limit: 1, offset: 0 }), []), useDetectionRevision())
  const incidents = useCollection(useCallback(async signal => ({ items: [{ total: (await incidentApi.list('all', 'all', 'all', '', 0, signal)).total }], total: 1, limit: 1, offset: 0 }), []), useIncidentRefresh().revision)
  const recent = [...data.packets].sort((a, b) => b.sequence - a.sequence).slice(0, 5)
  const monitorValue = connection !== 'connected' ? 'Disconnected' : monitor?.state === 'running' ? monitor.mode === 'offline' ? 'Offline analysis' : 'Monitoring' : monitor?.state === 'error' ? 'Capture failed' : monitor?.state === 'stopped' ? 'Stopped' : monitor?.state === 'starting' ? 'Starting' : monitor?.state === 'stopping' ? 'Stopping' : monitor?.state === 'completed' ? 'Completed' : 'Ready'
  const monitorNote = connection !== 'connected' ? 'Backend unavailable' : monitor?.mode === 'offline' ? 'Imported PCAP' : monitor?.interface || 'Select an interface'
  const stats = [
    { label: 'Monitoring status', value: monitorValue, note: monitorNote, icon: Activity },
    { label: 'Network devices', value: connection === 'connected' && !inventoryError ? String(data.deviceTotal) : '—', note: 'Observed mappings', icon: Monitor },
    { label: 'Threats detected', value: detection.items[0] ? String(detection.items[0].total) : '—', note: 'Suspicious findings', icon: ShieldAlert },
    { label: 'Total incidents', value: incidents.items[0] ? String(incidents.items[0].total) : '—', note: 'Correlated investigations', icon: Network },
  ]
  return <>
    <PageTitle title="Network Overview" action={<Link className="button" to="/monitor"><Radio size={15}/>Start Monitoring</Link>} />
    <div className="stats-grid compact-stats">{stats.map(({ label, value, note, icon: Icon }) => <section className="stat-card" key={label}><div className="stat-top"><span>{label}</span><Icon size={17}/></div><div className={`stat-value ${label === 'Monitoring status' ? 'text-value' : ''}`}>{value}</div><div className="stat-note">{note}</div></section>)}</div>
    <div className="overview-grid overview-bottom">
      <Card title="Recent activity" action={<Link className="text-link" to="/monitor">View monitor</Link>}>
        {recent.length ? <DataTable headings={['Time', 'Source', 'Sender IP', 'Operation']} hasRows empty={<EmptyState title="No activity yet"/>}>{recent.map(packet => <tr key={packet.id}><td title={packet.timestamp}>{new Date(packet.timestamp).toLocaleTimeString()}</td><td><Badge tone={packet.source === 'live' ? 'green' : 'muted'}>{packet.source === 'live' ? 'Live' : 'Offline'}</Badge></td><td className="mono">{packet.senderIp}</td><td>{packet.operation}</td></tr>)}</DataTable> : <EmptyState title="No activity yet" description="Start monitoring to see ARP packets here."/>}
      </Card>
      <DetectionSummary />
    </div>
  </>
}
