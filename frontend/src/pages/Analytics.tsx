import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, LineChart, Line } from 'recharts'

type Summary = { totalPackets: number; uniqueIps: number; uniqueMacs: number; requests: number; replies: number; requestReplyRatio: number | null; mappings: number; mappingChanges: number; analyticsQueueDepth: number; analyticsDropped: number; findings: {severity:string;method:string;count:number}[]; sessions: {sessionId:string;source:string;interface:string|null;state:string;startedAt:string|null;endedAt:string|null}[] }
type Item = { key?: string; count?: number; timestamp?: string; packets?: number; requests?: number; replies?: number }
type Anomaly = {id:string; method:string; severity:string; score:number; reason:string}
type PcapResult = {filename:string;captureFormat:string;packetCount:number;ignoredCount:number;captureDurationSeconds:number;processingSeconds:number;flowCount:number;protocolCounts:Record<string,number>;timeline:{timestamp:string;packets:number;protocolCounts:Record<string,number>}[];packetLengthHistogram:{rangeStartBytes:number;rangeEndBytes:number;packets:number}[];flows:{protocol:string;sourceIp:string;sourcePort:number|null;destinationIp:string;destinationPort:number|null;packets:number}[];limitations:string[]}
type Comparison = {comparisons:Record<string,{left:number;right:number;difference:number;relativeChange:number|null}>;interpretation:string}
type Baseline = {id:string;sessionId:string;source:string;createdAt:string;reason:string;sampleCount:number;features:Record<string,unknown>;methodVersion:string}
type BaselineComparison = {differences:Record<string,{baseline:number;observed:number;difference:number;relativeChange:number|null}>;interpretation:string}
export default function Analytics() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [top, setTop] = useState<Item[]>([])
  const [series, setSeries] = useState<Item[]>([])
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
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const qs = `source=${source}`
    Promise.all([fetch(`/api/analytics/summary?${qs}`), fetch(`/api/analytics/top?${qs}&dimension=source_ip&limit=10`), fetch(`/api/analytics/timeseries?${qs}&window=minute`), fetch(`/api/analytics/top?${qs}&dimension=mapping&limit=10`), fetch(`/api/analytics/anomalies?${qs}`), fetch('/api/analytics/baselines')]).then(async responses => {
      if (responses.some(response => !response.ok)) throw new Error('Analytics data could not be loaded.')
      return Promise.all(responses.map(response => response.json()))
    }).then(([s, t, ts, m, a, b]) => { if (active) { setSummary(s); setTop(t.items); setSeries(ts.items); setMappings(m.items); setAnomalies(a.items); setSessions(s.sessions); setBaselines(b.items) } }).catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Analytics data could not be loaded.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [source])
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
  return <section className="analytics-page">
    <header className="page-heading"><div><p className="eyebrow">OBSERVED NETWORK DATA</p><h1>Network Analytics</h1><p>Aggregates and statistical signals from captured ARP traffic.</p></div><label>Data source <select value={source} onChange={e => { setLoading(true); setError(''); setSource(e.target.value) }}><option value="all">Live and offline</option><option value="live">Live capture</option><option value="offline">Offline PCAP</option></select></label></header>
    {loading && <p className="feedback" role="status">Loading analytics…</p>}{error && <p className="error-banner" role="alert">{error}</p>}
    {!loading && !error && summary && <>
      <p className="analytics-scope">Showing {source === 'all' ? 'live and offline sessions' : source === 'live' ? 'live capture sessions' : 'offline PCAP sessions'} · Values are computed from persisted observations.</p>
      <div className="analytics-metrics">{[['Packets observed',summary.totalPackets],['Unique IP addresses',summary.uniqueIps],['Unique MAC addresses',summary.uniqueMacs],['IP–MAC mappings',summary.mappings],['Mapping changes',summary.mappingChanges],['Analytics queue drops',summary.analyticsDropped]].map(([label,value]) => <article className="analytics-card" key={label}><span>{label}</span><strong>{value}</strong></article>)}</div>
      <div className="analytics-grid"><article className="analytics-panel"><h2>Top source IPs</h2>{top.length ? <ResponsiveContainer width="100%" height={260}><BarChart data={top}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#318563" /></BarChart></ResponsiveContainer> : <p className="empty-state">No source IP observations in this selection.</p>}<p className="analytics-note">Frequency alone does not indicate malicious activity.</p></article>
      <article className="analytics-panel"><h2>ARP packets over time</h2>{series.length ? <ResponsiveContainer width="100%" height={260}><LineChart data={series}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="timestamp" hide /><YAxis allowDecimals={false} /><Tooltip /><Line type="monotone" dataKey="packets" stroke="#318563" /></LineChart></ResponsiveContainer> : <p className="empty-state">No time-series data for this selection.</p>}</article></div>
      <div className="analytics-grid"><article className="analytics-panel"><h2>ARP request and reply counts</h2><p><strong>{summary.requests}</strong> requests · <strong>{summary.replies}</strong> replies</p><p>Request/reply ratio: {summary.requestReplyRatio ?? 'not available (no replies)'}</p></article><article className="analytics-panel"><h2>Findings by detection method and severity</h2>{summary.findings.length ? <ResponsiveContainer width="100%" height={230}><BarChart data={summary.findings}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="method" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#7a9f87" /></BarChart></ResponsiveContainer> : <p className="empty-state">No existing rule findings in this selection.</p>}</article></div>
      <div className="analytics-grid"><article className="analytics-panel"><h2>IP–MAC mapping frequency</h2>{mappings.length ? <ResponsiveContainer width="100%" height={230}><BarChart data={mappings}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="key" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#509a75" /></BarChart></ResponsiveContainer> : <p className="empty-state">No mapping observations in this selection.</p>}</article><article className="analytics-panel"><h2>Statistical frequency signals</h2>{anomalies.length ? anomalies.map(a => <p key={a.id}><strong>{a.severity}</strong> · {a.reason}</p>) : <p className="empty-state">No configured frequency threshold was exceeded.</p>}<p className="analytics-note">Signals are statistical observations, not confirmed attacks.</p></article></div>
      <div className="analytics-grid"><article className="analytics-panel"><h2>Processing, capture duration, and sessions</h2><p>Analytics queue: {summary.analyticsQueueDepth} pending · {summary.analyticsDropped} dropped</p>{summary.sessions.length ? summary.sessions.map(s => { const duration = s.startedAt && s.endedAt ? Math.max(0, Math.round((Date.parse(s.endedAt) - Date.parse(s.startedAt)) / 1000)) : null; return <p key={s.sessionId}><strong>{s.source === 'offline' ? 'Offline PCAP' : 'Live capture'}</strong> · {s.interface ?? 'no interface'} · {s.state} · {duration === null ? s.startedAt ? 'in progress' : 'duration unavailable' : `${duration}s`}</p> }) : <p className="empty-state">No capture sessions recorded yet.</p>}</article><article className="analytics-panel"><h2>Severity counts</h2>{summary.findings.length ? summary.findings.map(f => <p key={`${f.method}-${f.severity}`}>{f.severity} · {f.method}: {f.count}</p>) : <p className="empty-state">No existing rule findings.</p>}</article></div>
      <div className="analytics-grid"><article className="analytics-panel"><h2>Analyze offline capture metadata</h2><p>Supports bounded `.pcap` and `.pcapng` uploads. Payloads are not retained.</p><form onSubmit={analyzeFile}><input name="captureFile" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" aria-label="Choose PCAP or PCAPNG file" /><button className="button" type="submit">Analyze offline file</button></form>{pcapError && <p role="alert" className="error-banner">{pcapError}</p>}{pcapResult && <div role="status"><p>{pcapResult.filename} · {pcapResult.packetCount} packets · {pcapResult.flowCount} flows · {pcapResult.captureDurationSeconds}s capture · {pcapResult.processingSeconds}s processing</p><p>Observed protocols: {Object.entries(pcapResult.protocolCounts).map(([protocol,count]) => `${protocol} ${count}`).join(' · ') || 'none'}</p><div className="analytics-grid"><div><h3>Protocol distribution</h3><ResponsiveContainer width="100%" height={200}><BarChart data={Object.entries(pcapResult.protocolCounts).map(([protocol,count]) => ({protocol,count}))}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="protocol" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#318563" /></BarChart></ResponsiveContainer></div><div><h3>Packet timeline ({pcapResult.timeline.length} occupied windows)</h3><ResponsiveContainer width="100%" height={200}><LineChart data={pcapResult.timeline}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="timestamp" hide /><YAxis allowDecimals={false} /><Tooltip /><Line type="monotone" dataKey="packets" stroke="#509a75" /></LineChart></ResponsiveContainer></div></div><p>Packet lengths (bytes): {pcapResult.packetLengthHistogram.map(bin => `${bin.rangeStartBytes}–${bin.rangeEndBytes}: ${bin.packets}`).join(' · ')}</p><p>Top directional flows:</p>{pcapResult.flows.slice(0,5).map((flow,index) => <p key={`${flow.protocol}-${flow.sourceIp}-${flow.sourcePort}-${index}`}>{flow.protocol} {flow.sourceIp}:{flow.sourcePort ?? '—'} → {flow.destinationIp}:{flow.destinationPort ?? '—'} · {flow.packets} packets</p>)}<button className="button" onClick={() => downloadCaptureReport('json')}>Download analysis JSON</button> <button className="button secondary" onClick={() => downloadCaptureReport('csv')}>Download analysis CSV</button>{pcapResult.limitations.map(note => <p className="analytics-note" key={note}>{note}</p>)}</div>}</article>
      <article className="analytics-panel"><h2>Compare stored sessions</h2>{sessions.length < 2 ? <p className="empty-state">Record at least two analytics sessions to compare them.</p> : <form onSubmit={compareSessions}><label>First session<select name="leftSessionId">{sessions.map(s => <option value={s.sessionId} key={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><label>Second session<select name="rightSessionId" defaultValue={sessions[1]?.sessionId}>{sessions.map(s => <option value={s.sessionId} key={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><button className="button" type="submit" disabled={comparing}>Compare sessions</button></form>}{compareError && <p role="alert" className="error-banner">{compareError}</p>}{comparison && <div role="status">{Object.entries(comparison.comparisons).map(([metric,v]) => <p key={metric}>{metric}: {v.left} → {v.right} (change {v.difference})</p>)}<p className="analytics-note">{comparison.interpretation}</p></div>}</article></div>
      <a className="button" href={`/api/analytics/report?source=${source}&format=json`} download>Export JSON summary</a>
      <article className="analytics-panel"><h2>Approve an observation baseline</h2><p>Only completed sessions with at least 20 persisted observations are eligible. Approval is administrator-authenticated, reasoned, and audited. This records an analytical reference; it does not create a trusted mapping or suppress alerts.</p><form onSubmit={approveBaseline}><label>Completed session<select name="sessionId" required>{sessions.filter(s => ['completed','stopped'].includes(s.state)).map(s => <option key={s.sessionId} value={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><label>Approval reason<input name="reason" minLength={10} maxLength={500} required /></label><label>Administrator token<input name="adminToken" type="password" autoComplete="off" required /></label><button className="button" type="submit" disabled={!sessions.some(s => ['completed','stopped'].includes(s.state))}>Approve baseline</button></form>{baselineError && <p role="alert" className="error-banner">{baselineError}</p>}{baselineMessage && <p role="status">{baselineMessage}</p>}{baselines.map(b => <p key={b.id}>Approved {b.source} baseline · {b.sampleCount} observations · {b.reason}</p>)}{baselines.length > 0 && sessions.length > 0 && <form onSubmit={compareBaseline}><label>Approved baseline<select name="baselineId">{baselines.map(b => <option key={b.id} value={b.id}>{b.source} · {b.sampleCount} observations · {b.id.slice(0,8)}</option>)}</select></label><label>Observed session<select name="targetSessionId">{sessions.map(s => <option key={s.sessionId} value={s.sessionId}>{s.source} · {s.interface ?? 'offline'} · {s.sessionId.slice(0,8)}</option>)}</select></label><button className="button secondary" type="submit">Compare to approved baseline</button></form>}{baselineCompareError && <p role="alert" className="error-banner">{baselineCompareError}</p>}{baselineComparison && <div role="status">{Object.entries(baselineComparison.differences).map(([metric,value]) => <p key={metric}>{metric}: baseline {value.baseline}, observed {value.observed}, change {value.difference}</p>)}<p className="analytics-note">{baselineComparison.interpretation}</p></div>}</article>
    </>}
  </section>
}
