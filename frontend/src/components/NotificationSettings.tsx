import { useState } from 'react'
import { Card } from './ui'
import { useAlerts } from '../context/useAlerts'
import { requestDesktopPermission } from '../services/notifications'
export function NotificationSettings() {
  const { preferences, savePreferences } = useAlerts(); const [permission, setPermission] = useState(typeof Notification === 'undefined' ? 'unsupported' : Notification.permission as string)
  return <Card title="Alert notifications" description="Browser-local preferences. Offline notifications are off by default; every alert remains in the alert list."><div className="settings-body">
    {(['inApp', 'desktop', 'replay'] as const).map(key => <label className="toggle-row" key={key}><span>{key === 'inApp' ? 'In-app toasts' : key === 'desktop' ? 'Desktop notifications (generic text only)' : 'Include offline replay notifications'}</span><input type="checkbox" checked={preferences[key]} onChange={e => savePreferences({ ...preferences, [key]: e.target.checked })} /></label>)}
    <div className="toolbar">{['High', 'Medium', 'Low'].map(severity => <label key={severity}><input type="checkbox" checked={preferences.severities.includes(severity)} onChange={e => savePreferences({ ...preferences, severities: e.target.checked ? [...preferences.severities, severity] : preferences.severities.filter(v => v !== severity) })} /> {severity}</label>)}</div>
    <p>Desktop permission: {permission}. Enabling the preference alone does not request permission.</p><button className="button secondary" type="button" disabled={permission === 'denied' || permission === 'unsupported' || permission === 'granted'} onClick={async () => { try { setPermission(await requestDesktopPermission(typeof Notification === 'undefined' ? undefined : Notification)) } catch { setPermission('Permission request failed') } }}>Request desktop permission</button>
    <small>At most one notification every five seconds, with a queue of 20. Suppression is reported; alert records are never removed.</small>
  </div></Card>
}
