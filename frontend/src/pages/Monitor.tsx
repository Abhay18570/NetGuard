import { useState, type ChangeEvent } from 'react'
import { Radio, Square, Upload } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { useMonitor } from '../context/useMonitor'
import { api } from '../services/api'

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
  const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const busy = !!monitor && ['starting', 'running', 'stopping'].includes(monitor.state)
  const selected = interfaces.some(item => item.name === networkInterface)
  const connected = connection === 'connected'
  const rows = data.packets.filter(row => `${row.senderIp} ${row.senderMac} ${row.targetIp} ${row.targetMac}`.toLowerCase().includes(query.toLowerCase()) && (operation === 'All operations' || row.operation === operation))
  const emptyTitle = query || operation !== 'All operations' ? 'No matching packets' : busy && monitor?.mode === 'live' ? 'Monitoring — waiting for ARP traffic' : monitor?.state === 'error' ? 'Capture failed' : !connected ? 'Disconnected' : 'Ready to monitor'
  const emptyDescription = query || operation !== 'All operations' ? 'Try another search or operation.' : busy && monitor?.mode === 'live' ? 'Packets appear when ARP traffic is observed.' : monitor?.state === 'error' ? 'Review the capture error above.' : 'Select an interface and start capture.'
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
    <PageTitle title="Live ARP Monitor" />
    <section className="card monitor-control-bar" aria-label="Monitoring controls">
      <label className="field">Network interface<select aria-label="Network interface" value={selected ? networkInterface : ''} disabled={busy || pending || !connected} onChange={event => setNetworkInterface(event.target.value)}><option value="">Select an interface</option>{interfaces.map(item => <option key={`${item.index}-${item.name}`} value={item.name}>{item.networkName || item.name}{item.description ? ` — ${item.description}` : item.networkName && item.name !== item.networkName ? ` (${item.name})` : ''}</option>)}</select></label>
      <div className="monitor-actions"><button className="button" disabled={pending || busy || !connected || !selected || !monitor?.captureAvailable} onClick={() => void action(() => api.startMonitoring(networkInterface))}><Radio size={15}/>Start Capture</button><button className="button secondary" disabled={pending || !busy} onClick={() => void action(api.stopMonitoring)}><Square size={14}/>Stop Capture</button></div>
      <div className="monitor-readout"><Badge tone={monitor?.state === 'running' && monitor.mode === 'live' ? 'green' : monitor?.mode === 'offline' ? 'muted' : ''}>{shortStatus(connected, monitor?.state, monitor?.mode)}</Badge><span>{data.packets.length} packets</span></div>
      <label className={`button secondary upload-button ${pending || busy || !connected ? 'disabled' : ''}`} title="Classic Ethernet PCAP, up to 5 MiB"><Upload size={15}/>Import PCAP<input aria-label="Import offline PCAP" type="file" accept=".pcap" disabled={pending || busy || !connected} onChange={importPcap}/></label>
    </section>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {!error && monitor?.error && <div className="error-banner" role="alert">{monitor.error.message}</div>}
    {connected && monitor && !monitor.captureAvailable && !monitor.error && <p className="feedback compact-feedback" role="status">{monitor.reason}</p>}
    {monitor?.mode === 'offline' && <p className="offline-note"><Badge tone="muted">Offline analysis</Badge> Imported records are not live network traffic.</p>}
    <Card title="Packet stream" action={<Badge tone={streamConnected ? 'green' : ''}>{streamConnected ? 'Connected' : 'Disconnected'}</Badge>}>
      <div className="toolbar"><SearchInput value={query} onChange={setQuery} placeholder="Search IP or MAC"/><select aria-label="ARP operation" value={operation} onChange={event => setOperation(event.target.value)}>{['All operations','Request','Reply'].map(value => <option key={value}>{value}</option>)}</select></div>
      <DataTable headings={['Time','Source','Sender IP','Sender MAC','Target IP','Target MAC','Operation','Status']} hasRows={!!rows.length} empty={<EmptyState title={emptyTitle} description={emptyDescription}/>}>{rows.map(row => <tr key={row.id}><td title={row.timestamp}><time dateTime={row.timestamp}>{new Date(row.timestamp).toLocaleTimeString()}</time></td><td><Badge tone={row.source === 'live' ? 'green' : 'muted'}>{row.source === 'live' ? 'Live' : 'Offline'}</Badge></td><td className="mono">{row.senderIp}</td><td className="mono">{row.senderMac}</td><td className="mono">{row.targetIp}</td><td className="mono">{row.targetMac}</td><td><Badge tone={row.operation === 'Reply' ? 'muted' : ''}>{row.operation}</Badge></td><td><Badge>{row.status}</Badge></td></tr>)}</DataTable>
    </Card>
  </>
}
