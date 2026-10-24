import { useMemo, useState, type ChangeEvent } from 'react'
import { Radio, Square, Upload } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { useMonitor } from '../context/useMonitor'
import { api } from '../services/api'

const PROTOCOL_OPTIONS = ['ARP', 'TCP', 'UDP', 'DNS']
const ALL_PROTOCOLS = 'All Supported Protocols'

function savedInterface() { try { const value = JSON.parse(localStorage.getItem('netguard.preferences.v1') || '{}').networkInterface; return typeof value === 'string' ? value : '' } catch { return '' } }
function shortStatus(connected: boolean, state?: string, mode?: string | null) {
  if (!connected) return 'Disconnected'
  if (state === 'running') return mode === 'offline' ? 'Offline analysis' : 'Monitoring'
  if (state === 'error') return 'Capture failed'
  if (state === 'stopped') return 'Stopped'
  if (state === 'starting') return 'Starting'
  if (state === 'stopping') return 'Stopping'
  if (state === 'completed') return 'Completed'
  return 'Ready'
}
export default function Monitor() {
  const { data, monitor, interfaces, connection, streamConnected, refresh } = useMonitor()
  const [query, setQuery] = useState(''); const [operation, setOperation] = useState('All operations')
  const [networkInterface, setNetworkInterface] = useState(savedInterface)
  const [selectedProtocols, setSelectedProtocols] = useState<string[]>(['ARP'])
  const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const busy = !!monitor && ['starting', 'running', 'stopping'].includes(monitor.state)
  const selected = interfaces.some(item => item.name === networkInterface)
  const connected = connection === 'connected'
  const effectiveProtocols = useMemo(() => monitor?.protocols?.length ? monitor.protocols : selectedProtocols, [monitor, selectedProtocols])
  const operationChoices = useMemo(() => ['All operations', ...new Set(data.packets.flatMap(item => item.protocol ? [item.protocol] : item.operation === 'Request' || item.operation === 'Reply' ? [item.operation] : []))], [data.packets])
  const rows = data.packets.filter(row => {
    const matchesText = `${row.senderIp ?? ''} ${row.senderMac ?? ''} ${row.targetIp ?? ''} ${row.targetMac ?? ''} ${(row.protocol ?? row.operation ?? '')}`.toLowerCase().includes(query.toLowerCase())
    const matchesProtocol = operation === 'All operations' || row.protocol === operation || row.operation === operation
    return matchesText && matchesProtocol
  })
  const emptyTitle = query || operation !== 'All operations' ? 'No matching packets' : busy && monitor?.mode === 'live' ? `Monitoring — waiting for ${effectiveProtocols.join(', ')} traffic` : monitor?.state === 'error' ? 'Capture failed' : !connected ? 'Disconnected' : 'Ready to monitor'
  const emptyDescription = query || operation !== 'All operations' ? 'Try another search or protocol filter.' : busy && monitor?.mode === 'live' ? `Packets appear when ${effectiveProtocols.join(', ')} traffic is observed.` : monitor?.state === 'error' ? 'Review the capture error above.' : 'Select an interface and start capture.'
  function toggleProtocol(protocol: string) {
    setSelectedProtocols(current => {
      if (protocol === ALL_PROTOCOLS) {
        return current.includes(ALL_PROTOCOLS) ? ['ARP'] : PROTOCOL_OPTIONS
      }
      const next = current.includes(protocol) ? current.filter(item => item !== protocol) : [...current, protocol]
      if (next.length === 0) return ['ARP']
      return next
    })
  }
  async function action(run: () => Promise<unknown>) {
    setPending(true); setError('')
    try { await run() } catch (cause) { setError(cause instanceof Error ? cause.message : 'The request failed.') }
    finally { await refresh(); setPending(false) }
  }
  function importPcap(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; event.target.value = ''
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.pcap') || file.size > 5 * 1024 * 1024) { setError('Choose a classic .pcap file up to 5 MiB.'); return }
    void action(() => api.replayPcap(file))
  }
  return <>
    <PageTitle title="Live Monitor" />
    <section className="card monitor-control-bar" aria-label="Monitoring controls">
      <label className="field">Network interface<select aria-label="Network interface" value={selected ? networkInterface : ''} disabled={busy || pending || !connected} onChange={event => setNetworkInterface(event.target.value)}><option value="">Select an interface</option>{interfaces.map(item => <option key={`${item.index}-${item.name}`} value={item.name}>{item.networkName || item.name}{item.description ? ` — ${item.description}` : item.networkName && item.name !== item.networkName ? ` (${item.name})` : ''}</option>)}</select></label>
      <div className="monitor-actions"><button className="button" disabled={pending || busy || !connected || !selected || !monitor?.captureAvailable} onClick={() => void action(() => api.startMonitoring(networkInterface, selectedProtocols))}><Radio size={15}/>Start Capture</button><button className="button secondary" disabled={pending || !busy} onClick={() => void action(api.stopMonitoring)}><Square size={14}/>Stop Capture</button></div>
      <div className="monitor-readout"><Badge tone={monitor?.state === 'running' && monitor.mode === 'live' ? 'green' : monitor?.mode === 'offline' ? 'muted' : ''}>{shortStatus(connected, monitor?.state, monitor?.mode)}</Badge><span>{effectiveProtocols.join(', ') || 'ARP'} · {data.packets.length} packets</span></div>
      <label className={`button secondary upload-button ${pending || busy || !connected ? 'disabled' : ''}`} title="Classic Ethernet PCAP, up to 5 MiB"><Upload size={15}/>Import PCAP<input aria-label="Import offline PCAP" type="file" accept=".pcap" disabled={pending || busy || !connected} onChange={importPcap}/></label>
    </section>
    <div className="card protocol-picker" aria-label="Protocol selection">
      <div className="protocol-chips">
        {[ALL_PROTOCOLS, ...PROTOCOL_OPTIONS].map(protocol => {
          const active = protocol === ALL_PROTOCOLS ? selectedProtocols.length === PROTOCOL_OPTIONS.length : selectedProtocols.includes(protocol)
          return <button key={protocol} type="button" className={`button chip ${active ? 'active' : 'secondary'}`} disabled={pending || busy} onClick={() => toggleProtocol(protocol)}>{protocol}</button>
        })}
      </div>
    </div>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {!error && monitor?.error && <div className="error-banner" role="alert">{monitor.error.message}</div>}
    {connected && monitor && !monitor.captureAvailable && !monitor.error && <p className="feedback compact-feedback" role="status">{monitor.reason}</p>}
    {monitor?.mode === 'offline' && <p className="offline-note"><Badge tone="muted">Offline analysis</Badge> Imported records are not live network traffic.</p>}
    <Card title="Packet stream" action={<Badge tone={streamConnected ? 'green' : ''}>{streamConnected ? 'Connected' : 'Disconnected'}</Badge>}>
      <div className="toolbar"><SearchInput value={query} onChange={setQuery} placeholder="Search IP, MAC, or protocol"/><select aria-label="Packet operation" value={operation} onChange={event => setOperation(event.target.value)}>{operationChoices.map(value => <option key={value}>{value}</option>)}</select></div>
      <DataTable headings={['Time','Protocol','Source','Sender IP','Sender MAC','Target IP','Target MAC','Operation','Status']} hasRows={!!rows.length} empty={<EmptyState title={emptyTitle} description={emptyDescription}/>}>{rows.map(row => <tr key={row.id}><td title={row.timestamp}><time dateTime={row.timestamp}>{new Date(row.timestamp).toLocaleTimeString()}</time></td><td><Badge tone="muted">{row.protocol ?? 'ARP'}</Badge></td><td><Badge tone={row.source === 'live' ? 'green' : 'muted'}>{row.source === 'live' ? 'Live' : 'Offline'}</Badge></td><td className="mono">{row.senderIp ?? row.sourceIp ?? ''}</td><td className="mono">{row.senderMac ?? ''}</td><td className="mono">{row.targetIp ?? row.destinationIp ?? ''}</td><td className="mono">{row.targetMac ?? ''}</td><td><Badge tone={row.operation === 'Reply' || row.operation === 'Response' ? 'muted' : ''}>{row.operation}</Badge></td><td><Badge>{row.status}</Badge></td></tr>)}</DataTable>
    </Card>
  </>
}
