import { NotificationSettings } from '../components/NotificationSettings'
import { useState, type FormEvent } from 'react'
import { Save } from 'lucide-react'
import { Card, PageTitle } from '../components/ui'
import { useMonitor } from '../context/useMonitor'
import type { Preferences } from '../types'
const key = 'netguard.preferences.v1'
const defaults: Preferences = { networkInterface: '', conflictThreshold: 3, windowSeconds: 60, refreshSeconds: 5, notifications: true, autoRefresh: true }
function readPreferences(): Preferences {
  try { const raw = JSON.parse(localStorage.getItem(key) || 'null'); if (!raw || typeof raw !== 'object') return defaults
    return { networkInterface: typeof raw.networkInterface === 'string' && raw.networkInterface.length <= 128 ? raw.networkInterface : '', conflictThreshold: Number.isInteger(raw.conflictThreshold) && raw.conflictThreshold >= 1 && raw.conflictThreshold <= 100 ? raw.conflictThreshold : 3, windowSeconds: Number.isInteger(raw.windowSeconds) && raw.windowSeconds >= 5 && raw.windowSeconds <= 3600 ? raw.windowSeconds : 60, refreshSeconds: Number.isInteger(raw.refreshSeconds) && raw.refreshSeconds >= 1 && raw.refreshSeconds <= 60 ? raw.refreshSeconds : 5, notifications: typeof raw.notifications === 'boolean' ? raw.notifications : true, autoRefresh: typeof raw.autoRefresh === 'boolean' ? raw.autoRefresh : true }
  } catch { return defaults }
}
export default function Settings() {
  const { interfaces, connection } = useMonitor()
  const [preferences, setPreferences] = useState(readPreferences); const [message, setMessage] = useState(''); const [failed, setFailed] = useState(false)
  function update<K extends keyof Preferences>(field: K, value: Preferences[K]) { setPreferences(current => ({ ...current, [field]: value })); setMessage('') }
  function save(event: FormEvent) { event.preventDefault(); try { localStorage.setItem(key, JSON.stringify(preferences)); setFailed(false); setMessage('Preferences saved.') } catch { setFailed(true); setMessage('Browser storage is unavailable. Preferences could not be saved.') } }
  return <><PageTitle title="Settings"/><p className="compact-copy settings-note">Preferred interface and alert notifications are saved in this browser.</p><NotificationSettings/><form onSubmit={save}><Card title="Preferred interface"><div className="settings-body"><label className="field">Network interface<select disabled={connection !== 'connected' || !interfaces.length} value={preferences.networkInterface} onChange={event => update('networkInterface', event.target.value)} aria-describedby="interface-help"><option value="">{connection !== 'connected' ? 'Backend disconnected' : interfaces.length ? 'No preferred interface' : 'No interfaces found'}</option>{preferences.networkInterface && !interfaces.some(item => item.name === preferences.networkInterface) && <option value={preferences.networkInterface} disabled>{preferences.networkInterface} — unavailable</option>}{interfaces.map(item => <option key={`${item.index}-${item.name}`} value={item.name}>{item.networkName || item.name}{item.description ? ` — ${item.description}` : item.networkName && item.name !== item.networkName ? ` (${item.name})` : ''}</option>)}</select><small id="interface-help">Used as the initial selection in Live Protocol Monitor.</small></label></div></Card><div className="save-row"><button type="button" className="button secondary" onClick={() => { setPreferences(defaults); setMessage('Defaults restored. Save to keep them.'); setFailed(false) }}>Restore defaults</button><button className="button" type="submit"><Save size={16}/>Save preferences</button></div>{message && <p role={failed ? 'alert' : 'status'} className={failed ? 'error-banner' : 'feedback'}>{message}</p>}</form></>
}

