import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis, LineChart, Line } from 'recharts'

type Summary = { totalPackets: number; uniqueIps: number; uniqueMacs: number; requests: number; replies: number; requestReplyRatio: number | null; mappings: number; mappingChanges: number; analyticsQueueDepth: number; analyticsDropped: number; findings: {severity:string;method:string;count:number}[]; sessions: {sessionId:string;source:string;interface:string|null;state:string;startedAt:string|null;endedAt:string|null}[] }
type Item = { key?: string; count?: number; service?: string }
type ProtocolMetric = {packetCount:number;uniqueIps?:number;uniqueMacs?:number;mappings?:number;mappingChanges?:number;requests?:number;replies?:number;requestReplyRatio?:number|null;uniqueSourcePorts?:number;uniqueDestinationPorts?:number;flowTuples?:number;topDestinationPorts?:Item[];flags?:Record<string,number>;synPackets?:number;synAckPackets?:number;resetPackets?:number;queries?:number;responses?:number;topDomains?:Item[];recordTypes?:Item[];responseCodes?:Item[];queryFailures?:number}
type Dashboard = {protocol:string;totalPackets:number;uniqueIps:number;protocolCounts:{protocol:string;count:number}[];metrics:Record<string,ProtocolMetric>;timeseries:{timestamp:string;protocolCounts:Record<string,number>;operationCounts?:Record<string,Record<string,number>>}[];topSources:Item[];topDestinationPorts:Item[];findings:{protocol:string;method:string;severity:string;count:number}[];findingsNote:string}
type Anomaly = {id:string; method:string; severity:string; score:number; reason:string}
type PcapResult = {filename:string;captureFormat:string;packetCount:number;ignoredCount:number;captureDurationSeconds:number;processingSeconds:number;flowCount:number;protocolCounts:Record<string,number>;timeline:{timestamp:string;packets:number;protocolCounts:Record<string,number>}[];packetLengthHistogram:{rangeStartBytes:number;rangeEndBytes:number;packets:number}[];flows:{protocol:string;sourceIp:string;sourcePort:number|null;destinationIp:string;destinationPort:number|null;packets:number}[];limitations:string[]}
type Comparison = {comparisons:Record<string,{left:number;right:number;difference:number;relativeChange:number|null}>;interpretation:string}
type Baseline = {id:string;sessionId:string;source:string;createdAt:string;reason:string;sampleCount:number;features:Record<string,unknown>;methodVersion:string}
type BaselineComparison = {differences:Record<string,{baseline:number;observed:number;difference:number;relativeChange:number|null}>;interpretation:string}
export default function Analytics() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [mappings, setMappings] = useState<Item[]>([])
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [pcapResult, setPcapResult] = useState<PcapResult | null>(null)
  const [pcapError, setPcapError] = useState('')
  const [comparing, setComparing] = useState(false)
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [compareError, setCompareError] = useState('')
  const [sessions, setSessions] = useState<Summary['sessions']>([])
  const [baselines, setBaselines] = useState<Baseline[]>([])
  const [baselineError, setBaselineError] = useState('')
  const [baselineMessage, setBaselineMessage] = useState('')
  const [baselineComparison, setBaselineComparison] = useState<BaselineComparison | null>(null)
  const [baselineCompareError, setBaselineCompareError] = useState('')
  const [source, setSource] = useState('all')
  const [protocol, setProtocol] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const qs = new URLSearchParams({source, protocol, window: 'minute'}).toString()
    Promise.all([fetch(`/api/analytics/summary?source=${source}`), fetch(`/api/analytics/dashboard?${qs}`), fetch(`/api/analytics/top?source=${source}&dimension=mapping&limit=10`), fetch(`/api/analytics/anomalies?source=${source}`), fetch('/api/analytics/baselines')]).then(async responses => {
      if (responses.some(response => !response.ok)) throw new Error('Analytics data could not be loaded.')
      return Promise.all(responses.map(response => response.json()))
    }).then(([s, d, m, a, b]) => { if (active) { setSummary(s); setDashboard(d); setMappings(m.items); setAnomalies(a.items); setSessions(s.sessions); setBaselines(b.items) } }).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Analytics data could not be loaded.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [source, protocol])
  const analyzeFile = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setPcapError(''); setPcapResult(null)
    const file = (event.currentTarget.elements.namedItem('captureFile') as HTMLInputElement).files?.[0]
    if (!file) { setPcapError('Choose a PCAP or PCAPNG file first.'); return }
    const form = new FormData(); form.append('file', file)
    try { const response = await fetch('/api/analytics/pcap/analyze?windowSeconds=60', { method: 'POST', body: form }); const body = await response.json(); if (!response.ok) throw new Error(body.message ?? 'PCAP analysis failed.'); setPcapResult(body) }
    catch (reason) { setPcapError(reason instanceof Error ? reason.message : 'PCAP analysis failed.') }
  }
  const compareSessions = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setCompareError(''); setComparison(null); setComparing(true)
    const form = new FormData(event.currentTarget); const leftSessionId = String(form.get('leftSessionId') ?? ''); const rightSessionId = String(form.get('rightSessionId') ?? '')
    try { const response = await fetch(`/api/analytics/compare?leftSessionId=${encodeURIComponent(leftSessionId)}&rightSessionId=${encodeURIComponent(rightSessionId)}`); const body = await response.json(); if (!response.ok) throw new Error(body.message ?? 'Comparison failed.'); setComparison(body) }
    catch (reason) { setCompareError(reason instanceof Error ? reason.message : 'Comparison failed.') }
    finally { setComparing(false) }
  }
  const approveBaseline = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBaselineError(''); setBaselineMessage('')
    const formElement = event.currentTarget; const form = new FormData(formElement)
    try {
      const response = await fetch('/api/analytics/baselines', {method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${String(form.get('adminToken') ?? '')}`}, body:JSON.stringify({sessionId:form.get('sessionId'),reason:form.get('reason')})})
      const body = await response.json()
      if (!response.ok) throw new Error(body.message ?? 'Baseline approval failed.')
      setBaselines(current => [body, ...current]); setBaselineMessage(`Approved baseline ${body.id.slice(0,8)} from ${body.sampleCount} observations.`); formElement.reset()
    } catch (reason) { setBaselineError(reason instanceof Error ? reason.message : 'Baseline approval failed.') }
  }
  const compareBaseline = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBaselineCompareError(''); setBaselineComparison(null)
    const form = new FormData(event.currentTarget); const baselineId = String(form.get('baselineId') ?? ''); const sessionId = String(form.get('targetSessionId') ?? '')
    try { const response = await fetch(`/api/analytics/baselines/${encodeURIComponent(baselineId)}/compare?sessionId=${encodeURIComponent(sessionId)}`); const body = await response.json(); if (!response.ok) throw new Error(body.message ?? 'Baseline comparison failed.'); setBaselineComparison(body) }
    catch (reason) { setBaselineCompareError(reason instanceof Error ? reason.message : 'Baseline comparison failed.') }
  }
  const downloadCaptureReport = (format: 'json' | 'csv') => {
    if (!pcapResult) return
    const content = format === 'json' ? JSON.stringify(pcapResult, null, 2) : Object.entries(pcapResult).map(([key,value]) => {
      const serialized = typeof value === 'string' && /^[=+@-]/.test(value) ? `'${value}` : JSON.stringify(value)
      return `${key},"${serialized.replaceAll('"','""')}"`
    }).join('\n')
    const blob = new Blob([content], {type: format === 'json' ? 'application/json' : 'text/csv'})
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `netguard-offline-analysis.${format}`; link.click(); URL.revokeObjectURL(url)
  }
  const selectedMetric = dashboard?.metrics[protocol === 'all' ? 'ARP' : protocol]
  const visibleProtocols = protocol === 'all' ? ['ARP', 'TCP', 'UDP', 'DNS'] : [protocol]
  const timeline = dashboard?.timeseries.map(point => ({timestamp: point.timestamp, ...point.protocolCounts})) ?? []
  const dnsTimeline = dashboard?.timeseries.map(point => ({
    timestamp: point.timestamp,
    Queries: point.operationCounts?.DNS?.Query ?? 0,
    Responses: point.operationCounts?.DNS?.Response ?? 0,
  })) ?? []
  const findingCount = dashboard?.findings.reduce((total, finding) => total + finding.count, 0) ?? 0
  const metricCards: [string, number | string][] = protocol === 'all'
    ? [['Packets observed', dashboard?.totalPackets ?? 0], ['Unique IP addresses', dashboard?.uniqueIps ?? 0],
       ['TCP directional tuples', dashboard?.metrics.TCP?.flowTuples ?? 0],
       ['DNS queries', dashboard?.metrics.DNS?.queries ?? 0], ['Detection findings', findingCount],
       ['ARP mapping changes', dashboard?.metrics.ARP?.mappingChanges ?? 0]]
    : protocol === 'ARP'
      ? [['ARP packets observed', selectedMetric?.packetCount ?? 0], ['Unique IP addresses', selectedMetric?.uniqueIps ?? 0],
         ['Unique MAC addresses', selectedMetric?.uniqueMacs ?? 0], ['IP–MAC mappings', selectedMetric?.mappings ?? 0],
         ['Mapping changes', selectedMetric?.mappingChanges ?? 0], ['Analytics queue drops', summary?.analyticsDropped ?? 0]]
      : protocol === 'DNS'
        ? [['DNS packets', selectedMetric?.packetCount ?? 0], ['Queries', selectedMetric?.queries ?? 0],
           ['Responses', selectedMetric?.responses ?? 0], ['Queried domains', selectedMetric?.topDomains?.length ?? 0],
           ['Query failures', selectedMetric?.queryFailures ?? 0]]
        : [[`${protocol} packets`, selectedMetric?.packetCount ?? 0], ['Unique IP addresses', selectedMetric?.uniqueIps ?? 0],
           ['Directional flow tuples', selectedMetric?.flowTuples ?? 0],
           ['Unique destination ports', selectedMetric?.uniqueDestinationPorts ?? 0],
           ...(protocol === 'TCP' ? [['SYN packets', selectedMetric?.synPackets ?? 0] as [string, number]] : [])]
  return <section className="analytics-page">
    <header className="page-heading"><div><p className="eyebrow">OBSERVED NETWORK DATA</p><h1>Network Analytics</h1><p>Protocol-aware aggregates from persisted packet observations.</p></div><div className="analytics-selectors"><label>Protocol <select value={protocol} onChange={e => { setLoading(true); setError(''); setProtocol(e.target.value) }}><option value="all">All Protocols</option><option value="ARP">ARP</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="DNS">DNS</option></select></label><label>Data source <select value={source} onChange={e => { setLoading(true); setError(''); setSource(e.target.value) }}><option value="all">Live and offline</option><option value="live">Live capture</option><option value="offline">Offline PCAP</option></select></label></div></header>
    {loading && <p className="feedback" role="status">Loading analytics…</p>}{error && <p className="error-banner" role="alert">{error}</p>}
    {!loading && !error && summary && dashboard && <>
      <p className="analytics-scope">Showing {protocol === 'all' ? 'all four supported protocols' : `${protocol} observations`} from {source === 'all' ? 'live and offline sessions' : source === 'live' ? 'live capture sessions' : 'offline PCAP sessions'} · Values are computed from persisted observations.</p>
      <div className="analytics-metrics">{metricCards.map(([label,value]) => <article className="analytics-card" key={label}><span>{label}</span><strong>{value}</strong></article>)}</div>
      <div className="analytics-grid">
        {protocol === 'all' && <article className="analytics-panel"><h2>Traffic distribution by protocol</h2>{dashboard.totalPackets ? <ResponsiveContainer width="100%" height={250}><BarChart data={dashboard.protocolCounts}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="protocol" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" name="Packets" fill="#318563" /></BarChart></ResponsiveContainer> : <p className="empty-state">No persisted packet observations for this selection.</p>}</article>}
        <article className="analytics-panel"><h2>{protocol === 'all' ? 'Packets over time by protocol' : `${protocol} traffic over time`}</h2>{timeline.length ? <ResponsiveContainer width="100%" height={250}><LineChart data={timeline}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="timestamp" hide /><YAxis allowDecimals={false} /><Tooltip /><Legend />{visibleProtocols.map((name,index) => <Line key={name} type="monotone" dataKey={name} name={name} stroke={['#318563','#4576a8','#a86c36','#8858a8'][index]} connectNulls />)}</LineChart></ResponsiveContainer> : <p className="empty-state">No time-series observations for this selection.</p>}<p className="analytics-note">Packet counts are bucketed by the selected one-minute window.</p></article>
        <article className="analytics-panel"><h2>Top source IPs</h2>{dashboard.topSources.length ? <ResponsiveContainer width="100%" height={250}><BarChart data={dashboard.topSources}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" name="Packets" fill="#318563" /></BarChart></ResponsiveContainer> : <p className="empty-state">No source IP observations in this selection.</p>}<p className="analytics-note">Frequency alone does not indicate malicious activity.</p></article>
        {(protocol === 'all' || protocol === 'TCP' || protocol === 'UDP' || protocol === 'DNS') && <article className="analytics-panel"><h2>Top destination ports and services</h2>{dashboard.topDestinationPorts.length ? <ResponsiveContainer width="100%" height={250}><BarChart data={dashboard.topDestinationPorts}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip formatter={(value, name, item) => [`${value} packets · ${item.payload.service}`, name]} /><Bar dataKey="count" name="Destination port" fill="#509a75" /></BarChart></ResponsiveContainer> : <p className="empty-state">No destination-port observations in this selection.</p>}</article>}
      </div>
      {(protocol === 'all' || protocol === 'ARP') && <div className="analytics-grid">
        <article className="analytics-panel"><h2>ARP requests, replies, and mappings</h2><p><strong>{dashboard.metrics.ARP?.requests ?? 0}</strong> requests · <strong>{dashboard.metrics.ARP?.replies ?? 0}</strong> replies</p><p>Request/reply ratio: {dashboard.metrics.ARP?.requestReplyRatio ?? 'not available (no replies)'}</p><p>{dashboard.metrics.ARP?.uniqueIps ?? 0} unique IPs · {dashboard.metrics.ARP?.uniqueMacs ?? 0} unique MACs · {dashboard.metrics.ARP?.mappings ?? 0} observed IP–MAC mappings · {dashboard.metrics.ARP?.mappingChanges ?? 0} mapping changes</p>{mappings.length ? <ResponsiveContainer width="100%" height={220}><BarChart data={mappings}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" name="Observations" fill="#509a75" /></BarChart></ResponsiveContainer> : <p className="empty-state">No IP–MAC mapping observations in this selection.</p>}</article>
        <article className="analytics-panel"><h2>ARP statistical signals</h2>{anomalies.length ? anomalies.map(a => <p key={a.id}><strong>{a.severity}</strong> · {a.reason}</p>) : <p className="empty-state">No configured ARP statistical threshold was exceeded.</p>}<p className="analytics-note">Statistical signals are observations, not confirmed attacks.</p></article>
      </div>}
      {(protocol === 'all' || protocol === 'TCP' || protocol === 'UDP') && <div className="analytics-grid">
        {visibleProtocols.filter(name => name === 'TCP' || name === 'UDP').map(name => {
          const metric = dashboard.metrics[name]
          return <article className="analytics-panel" key={name}><h2>{name} packet and flow statistics</h2><p>{metric?.packetCount ?? 0} packets · {metric?.flowTuples ?? 0} distinct observed directional tuples</p><p>{metric?.uniqueIps ?? 0} source/destination IP addresses · {metric?.uniqueSourcePorts ?? 0} source ports · {metric?.uniqueDestinationPorts ?? 0} destination ports</p>{metric?.topDestinationPorts?.length ? <p>Common destinations: {metric.topDestinationPorts.map(port => `${port.key} (${port.service}, ${port.count})`).join(' · ')}</p> : <p className="empty-state">No destination-port data recorded.</p>}{name === 'TCP' && <p>Observed flags: {Object.entries(metric?.flags ?? {}).map(([flag,count]) => `${flag} ${count}`).join(' · ') || 'none'} · SYN {metric?.synPackets ?? 0} · SYN-ACK {metric?.synAckPackets ?? 0} · RST {metric?.resetPackets ?? 0}</p>}<p className="analytics-note">A directional tuple is a distinct observed source/destination IP and port combination, not a reconstructed connection.</p></article>
        })}
      </div>}
      {(protocol === 'all' || protocol === 'DNS') && <div className="analytics-grid">
        <article className="analytics-panel"><h2>DNS queries and frequently queried domains</h2><p>{dashboard.metrics.DNS?.queries ?? 0} queries · {dashboard.metrics.DNS?.responses ?? 0} responses · {dashboard.metrics.DNS?.queryFailures ?? 0} nonzero response codes</p>{dashboard.metrics.DNS?.topDomains?.length ? <ResponsiveContainer width="100%" height={230}><BarChart data={dashboard.metrics.DNS.topDomains}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" name="DNS packets" fill="#8858a8" /></BarChart></ResponsiveContainer> : <p className="empty-state">No DNS query names were recorded.</p>}</article>
        <article className="analytics-panel"><h2>DNS query and response trends</h2>{dnsTimeline.some(point => point.Queries || point.Responses) ? <ResponsiveContainer width="100%" height={190}><LineChart data={dnsTimeline}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="timestamp" hide /><YAxis allowDecimals={false} /><Tooltip /><Legend /><Line type="monotone" dataKey="Queries" stroke="#8858a8" connectNulls /><Line type="monotone" dataKey="Responses" stroke="#509a75" connectNulls /></LineChart></ResponsiveContainer> : <p className="empty-state">No DNS query/response trend data for this selection.</p>}<h3>Record types and response codes</h3><p>Record types: {dashboard.metrics.DNS?.recordTypes?.map(item => `${item.key}: ${item.count}`).join(' · ') || 'not recorded'}</p><p>Response codes: {dashboard.metrics.DNS?.responseCodes?.map(item => `${item.key}: ${item.count}`).join(' · ') || 'not recorded'}</p><p className="analytics-note">Failures count recorded DNS responses with a nonzero response code.</p></article>
      </div>}
      <div className="analytics-grid"><article className="analytics-panel"><h2>Detection findings by protocol, method, and severity</h2>{dashboard.findings.length ? <><ResponsiveContainer width="100%" height={230}><BarChart data={dashboard.findings}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="method" /><YAxis allowDecimals={false} /><Tooltip /><Legend /><Bar dataKey="count" name="Findings" fill="#7a9f87" /></BarChart></ResponsiveContainer>{dashboard.findings.map(f => <p key={`${f.protocol}-${f.method}-${f.severity}`}>{f.protocol} · {f.severity} · {f.method}: {f.count}</p>)}</> : <p className="empty-state">No persisted detection findings for this protocol and selection.</p>}<p className="analytics-note">{dashboard.findingsNote}</p></article><article className="analytics-panel"><h2>Finding severity summary</h2>{dashboard.findings.length ? dashboard.findings.map(f => <p key={`${f.protocol}-${f.method}-${f.severity}`}>{f.protocol} · {f.severity}: {f.count}</p>) : <p className="empty-state">No detection findings.</p>}</article></div>
      <article className="analytics-panel"><h2>Capture processing and sessions</h2><p>Analytics queue: {summary.analyticsQueueDepth} pending · {summary.analyticsDropped} dropped</p>{summary.sessions.length ? summary.sessions.map(s => { const duration = s.startedAt && s.endedAt ? Math.max(0, Math.round((Date.parse(s.endedAt) - Date.parse(s.startedAt)) / 1000)) : null; return <p key={s.sessionId}><strong>{s.source === 'offline' ? 'Offline PCAP' : 'Live capture'}</strong> · {s.interface ?? 'no interface'} · {s.state} · {duration === null ? s.startedAt ? 'in progress' : 'duration unavailable' : `${duration}s`}</p> }) : <p className="empty-state">No capture sessions recorded yet.</p>}</article>
      <div className="analytics-grid"><article className="analytics-panel"><h2>Analyze offline capture metadata</h2><p>Supports bounded `.pcap` and `.pcapng` uploads. Payloads are not retained.</p><form onSubmit={analyzeFile}><input name="captureFile" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" aria-label="Choose PCAP or PCAPNG file" /><button className="button" type="submit">Analyze offline file</button></form>{pcapError && <p role="alert" className="error-banner">{pcapError}</p>}{pcapResult && <div role="status"><p>{pcapResult.filename} · {pcapResult.packetCount} packets · {pcapResult.flowCount} flows · {pcapResult.captureDurationSeconds}s capture · {pcapResult.processingSeconds}s processing</p><p>Observed protocols: {Object.entries(pcapResult.protocolCounts).map(([protocol,count]) => `${protocol} ${count}`).join(' · ') || 'none'}</p><div className="analytics-grid"><div><h3>Protocol distribution</h3><ResponsiveContainer width="100%" height={200}><BarChart data={Object.entries(pcapResult.protocolCounts).map(([protocol,count]) => ({protocol,count}))}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="protocol" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#318563" /></BarChart></ResponsiveContainer></div><div><h3>Packet timeline ({pcapResult.timeline.length} occupied windows)</h3><ResponsiveContainer width="100%" height={200}><LineChart data={pcapResult.timeline}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="timestamp" hide /><YAxis allowDecimals={false} /><Tooltip /><Line type="monotone" dataKey="packets" stroke="#509a75" /></LineChart></ResponsiveContainer></div></div><p>Packet lengths (bytes): {pcapResult.packetLengthHistogram.map(bin => `${bin.rangeStartBytes}–${bin.rangeEndBytes}: ${bin.packets}`).join(' · ')}</p><p>Top directional flows:</p>{pcapResult.flows.slice(0,5).map((flow,index) => <p key={`${flow.protocol}-${flow.sourceIp}-${flow.sourcePort}-${index}`}>{flow.protocol} {flow.sourceIp}:{flow.sourcePort ?? '—'} → {flow.destinationIp}:{flow.destinationPort ?? '—'} · {flow.packets} packets</p>)}<button className="button" onClick={() => downloadCaptureReport('json')}>Download analysis JSON</button> <button className="button secondary" onClick={() => downloadCaptureReport('csv')}>Download analysis CSV</button>{pcapResult.limitations.map(note => <p className="analytics-note" key={note}>{note}</p>)}</div>}</article>
      <article className="analytics-panel"><h2>Compare stored sessions</h2>{sessions.length < 2 ? <p className="empty-state">Record at least two analytics sessions to compare them.</p> : <form onSubmit={compareSessions}><label>First session<select name="leftSessionId">{sessions.map(s => <option value={s.sessionId} key={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><label>Second session<select name="rightSessionId" defaultValue={sessions[1]?.sessionId}>{sessions.map(s => <option value={s.sessionId} key={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><button className="button" type="submit" disabled={comparing}>Compare sessions</button></form>}{compareError && <p role="alert" className="error-banner">{compareError}</p>}{comparison && <div role="status">{Object.entries(comparison.comparisons).map(([metric,v]) => <p key={metric}>{metric}: {v.left} → {v.right} (change {v.difference})</p>)}<p className="analytics-note">{comparison.interpretation}</p></div>}</article></div>
      <a className="button" href={`/api/analytics/report?source=${source}&protocol=${protocol}&format=json`} download>Export JSON summary</a>
      <article className="analytics-panel"><h2>Approve an ARP observation baseline</h2><p>Only completed sessions with at least 20 persisted ARP observations are eligible. Approval is administrator-authenticated, reasoned, and audited. This records an analytical reference; it does not create a trusted mapping or suppress alerts.</p><form onSubmit={approveBaseline}><label>Completed session<select name="sessionId" required>{sessions.filter(s => ['completed','stopped'].includes(s.state)).map(s => <option key={s.sessionId} value={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><label>Approval reason<input name="reason" minLength={10} maxLength={500} required /></label><label>Administrator token<input name="adminToken" type="password" autoComplete="off" required /></label><button className="button" type="submit" disabled={!sessions.some(s => ['completed','stopped'].includes(s.state))}>Approve baseline</button></form>{baselineError && <p role="alert" className="error-banner">{baselineError}</p>}{baselineMessage && <p role="status">{baselineMessage}</p>}{baselines.map(b => <p key={b.id}>Approved {b.source} baseline · {b.sampleCount} observations · {b.reason}</p>)}{baselines.length > 0 && sessions.length > 0 && <form onSubmit={compareBaseline}><label>Approved baseline<select name="baselineId">{baselines.map(b => <option key={b.id} value={b.id}>{b.source} · {b.sampleCount} observations · {b.id.slice(0,8)}</option>)}</select></label><label>Observed session<select name="targetSessionId">{sessions.map(s => <option key={s.sessionId} value={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><button className="button secondary" type="submit">Compare to approved baseline</button></form>}{baselineCompareError && <p role="alert" className="error-banner">{baselineCompareError}</p>}{baselineComparison && <div role="status">{Object.entries(baselineComparison.differences).map(([metric,value]) => <p key={metric}>{metric}: baseline {value.baseline}, observed {value.observed}, change {value.difference}</p>)}<p className="analytics-note">{baselineComparison.interpretation}</p></div>}</article>
    </>}
  </section>
}
