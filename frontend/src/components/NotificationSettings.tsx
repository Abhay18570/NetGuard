import { useState } from 'react'
import { Card } from './ui'
import { useAlerts } from '../context/useAlerts'
import { requestDesktopPermission } from '../services/notifications'
export function NotificationSettings() {
  const { preferences, savePreferences } = useAlerts(); const [permission, setPermission] = useState(typeof Notification === 'undefined' ? 'unsupported' : Notification.permission as string)
  return <Card title="Alert notifications"><div className="settings-body">
    {(['inApp', 'desktop', 'replay'] as const).map(key => <label className="toggle-row" key={key}><span>{key === 'inApp' ? 'In-app alerts' : key === 'desktop' ? 'Desktop alerts' : 'Offline replay alerts'}</span><input type="checkbox" checked={preferences[key]} onChange={e => savePreferences({ ...preferences, [key]: e.target.checked })} /></label>)}
    <fieldset className="severity-options"><legend>Alert severity</legend>{['High', 'Medium', 'Low'].map(severity => <label key={severity}><input type="checkbox" checked={preferences.severities.includes(severity)} onChange={e => savePreferences({ ...preferences, severities: e.target.checked ? [...preferences.severities, severity] : preferences.severities.filter(v => v !== severity) })} /> {severity}</label>)}</fieldset>
    <p className="permission-state">Desktop permission: {permission}</p><button className="button secondary" type="button" disabled={permission === 'denied' || permission === 'unsupported' || permission === 'granted'} onClick={async () => { try { setPermission(await requestDesktopPermission(typeof Notification === 'undefined' ? undefined : Notification)) } catch { setPermission('Permission request failed') } }}>Request desktop permission</button>
    <details className="advanced-inline"><summary>Notification limits</summary><small>One notification every five seconds; queue limit 20. Alerts remain available in Threat Detection.</small></details>
  </div></Card>
}
