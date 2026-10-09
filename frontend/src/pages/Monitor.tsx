import { useState, type ChangeEvent } from 'react'
import { Radio, Square, Upload } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState, PageTitle, SearchInput } from '../components/ui'
import { useMonitor } from '../context/useMonitor'
import { api } from '../services/api'
import { statusLabel } from '../services/monitorState'
function savedInterface() { try { const value = JSON.parse(localStorage.getItem('netguard.preferences.v1') || '{}').networkInterface; return typeof value === 'string' ? value : '' } catch { return '' } }
export default function Monitor() {
  const { data, monitor, interfaces, connection, streamConnected, refresh } = useMonitor()
  const [query, setQuery] = useState(''); const [operation, setOperation] = useState('All operations')
  const [networkInterface, setNetworkInterface] = useState(savedInterface)
  const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const busy = !!monitor && ['starting', 'running', 'stopping'].includes(monitor.state)
  const selected = interfaces.some(item => item.name === networkInterface)
  const connected = connection === 'connected'
  const rows = data.packets.filter(row => `${row.senderIp} ${row.senderMac} ${row.targetIp} ${row.targetMac}`.toLowerCase().includes(query.toLowerCase()) && (operation === 'All operations' || row.operation === operation))
  async function action(run: () => Promise<unknown>) {
    setPending(true); setError('')
    try { await run() } catch (cause) { setError(cause instanceof Error ? cause.message : 'The monitoring request failed.') }
    finally { await refresh(); setPending(false) }
  }
  function importPcap(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; event.target.value = ''
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.pcap') || file.size > 5 * 1024 * 1024) { setError('Choose a classic .pcap file up to 5 MiB. PCAPNG is not supported.'); return }
    void action(() => api.replayPcap(file))
  }
  return <><PageTitle title="Live ARP monitor" description="Passively observe ARP requests and replies on your selected interface." action={<div className="monitor-actions"><button className="button" disabled={pending || busy || !connected || !selected || !monitor?.captureAvailable} onClick={() => void action(() => api.startMonitoring(networkInterface))}><Radio size={16} />Start capture</button><button className="button secondary" disabled={pending || !busy} onClick={() => void action(api.stopMonitoring)}><Square size={14} />Stop</button></div>} />
    <Card title="Capture session" description="Capture is receive-only. Findings are analyzed separately; NetGuard performs no network actions." action={<Badge tone={monitor?.mode === 'offline' ? 'muted' : ''}>{statusLabel(monitor, connected)}</Badge>}><div className="toolbar"><label className="field">Local network interface<select aria-label="Capture interface" value={selected ? networkInterface : ''} disabled={busy || pending || !connected} onChange={event => setNetworkInterface(event.target.value)}><option value="">Select an interface explicitly</option>{interfaces.map(item => <option key={item.index} value={item.name}>{item.name}</option>)}</select></label><label className={`button secondary upload-button ${pending || busy || !connected ? 'disabled' : ''}`}><Upload size={15} />Import offline PCAP<input aria-label="Import offline PCAP" type="file" accept=".pcap" disabled={pending || busy || !connected} onChange={importPcap} /></label></div><div className="card-foot">Classic Ethernet PCAP · Maximum 5 MiB / 10,000 records · Replay is offline at 20 packets/second</div></Card>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {monitor?.error && <div className="error-banner" role="alert">{monitor.error.message}</div>}
    {monitor?.mode === 'offline' && <div className="notice"><Upload size={18} /><p><strong>Offline PCAP data.</strong> These records came from an imported file, not this network. Original packet timestamps are preserved.</p></div>}
    <Card title="Packet stream" description={connected ? monitor?.reason || 'Monitoring has not started.' : 'Connection unavailable. Displayed records are retained history; session status is unconfirmed.'} action={<Badge>{streamConnected ? 'Stream connected' : 'Stream disconnected'}</Badge>}><div className="toolbar"><SearchInput value={query} onChange={setQuery} placeholder="Search IP or MAC address…" /><select aria-label="ARP operation" value={operation} onChange={event => setOperation(event.target.value)}>{['All operations','Request','Reply'].map(value => <option key={value}>{value}</option>)}</select></div><DataTable headings={['Timestamp','Source / Interface','Sender IP','Sender MAC','Target IP','Target MAC','Operation','Detection status']} hasRows={!!rows.length} empty={<EmptyState title={query || operation !== 'All operations' ? 'No matching packets' : busy ? 'Waiting for ARP packets' : 'No packets in this session'} description="Start capture on a selected local interface or import an offline PCAP. A quiet network may produce no ARP packets." />}>{rows.map(row => <tr key={row.id}><td>{row.timestamp}</td><td><Badge tone={row.source === 'offline' ? 'muted' : 'green'}>{row.source === 'offline' ? 'Offline PCAP' : `Live · ${row.interface}`}</Badge></td><td className="mono">{row.senderIp}</td><td className="mono">{row.senderMac}</td><td className="mono">{row.targetIp}</td><td className="mono">{row.targetMac}</td><td>{row.operation}</td><td><Badge>{row.status}</Badge></td></tr>)}</DataTable><div className="card-foot">{data.packets.length} retained in this view · Latest 500 displayed · Backend retains up to {monitor?.bufferCapacity ?? 1000} · New sessions clear prior records</div></Card></>
}
