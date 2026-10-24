import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { io } from 'socket.io-client'
import { alertApi, isAlertEvent, type AlertSummary, type SecurityAlert } from '../services/alerts'
import { desktopText, normalizePreferences, NotificationQueue, type NotificationPreferences } from '../services/notifications'
import { AlertsContext } from './useAlerts'
const key = 'netguard.notifications.v1'
function initialPreferences() { try { const saved = localStorage.getItem(key); if (saved) return normalizePreferences(JSON.parse(saved)); const legacy = JSON.parse(localStorage.getItem('netguard.preferences.v1') || '{}'); return normalizePreferences({ inApp: legacy.notifications !== false }) } catch { return normalizePreferences(null) } }
export function AlertProvider({ children }: { children: ReactNode }) {
  const [revision, setRevision] = useState(0); const [connected, setConnected] = useState(false)
  const [summary, setSummary] = useState<AlertSummary | null>(null); const [error, setError] = useState('')
  const [preferences, setPreferences] = useState(initialPreferences); const preferenceRef = useRef(preferences)
  useEffect(() => { preferenceRef.current = preferences }, [preferences])
  const [toast, setToast] = useState<SecurityAlert | null>(null); const [suppressed, setSuppressed] = useState(0); const [notificationError, setNotificationError] = useState('')
  function savePreferences(value: NotificationPreferences) { setPreferences(value); if (!value.inApp) setToast(null); try { localStorage.setItem(key, JSON.stringify(value)); setNotificationError('') } catch { setNotificationError('Browser storage unavailable; preferences apply only for this visit.') } }
  useEffect(() => {
    let active = true; let request: AbortController | null = null; let scheduled: ReturnType<typeof setTimeout> | undefined
    let toastTimer: ReturnType<typeof setTimeout> | undefined
    const started = Date.now(); const queue = new NotificationQueue(); const socket = io({ autoConnect: false })
    async function reconcile() {
      request?.abort(); const controller = new AbortController(); request = controller
      try {
        const [counts, latest] = await Promise.all([alertApi.summary(controller.signal), alertApi.list('all', 'all', 'New', '', 0, controller.signal)])
        if (!active || controller.signal.aborted) return
        setSummary(counts); setError(''); setRevision(v => v + 1)
        // Historical alerts remain visible in REST without flooding notifications at page open.
        for (const alert of [...latest.items].reverse()) if (Date.parse(alert.createdAt) >= started) queue.offer(alert, preferenceRef.current)
        if (latest.total > latest.items.length) setNotificationError('Notification recovery reads the latest 25 New alerts. Review the full alert list for older or missed records.')
      } catch (cause) { if (active && !controller.signal.aborted) { setError(cause instanceof Error ? cause.message : 'Alerts unavailable'); setSummary(null) } }
    }
    function refresh() { if (!scheduled) scheduled = setTimeout(() => { scheduled = undefined; void reconcile() }, 200) }
    socket.on('connect', () => { setConnected(true); refresh() }); socket.on('disconnect', () => { setConnected(false); refresh() })
    socket.on('alert_created', (event: unknown) => { if (!isAlertEvent(event)) return; if (!event.recovered && Date.parse(event.alert.createdAt) >= started) queue.offer(event.alert, preferenceRef.current); refresh() })
    socket.on('alert_updated', (event: unknown) => { if (isAlertEvent(event)) { queue.cancel(event.alert); setToast(current => current?.id === event.alert.id ? null : current); refresh() } })
    const poll = setInterval(refresh, 3000)
    const notifications = setInterval(() => {
      setSuppressed(queue.suppressed)
      const alert = queue.take(Date.now(), preferenceRef.current)
      if (!alert) return
      if (preferenceRef.current.inApp) { setToast(alert); clearTimeout(toastTimer); toastTimer = setTimeout(() => setToast(null), 8000) }
      if (preferenceRef.current.desktop && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
        try { const content = desktopText(alert); new Notification(content.title, { body: content.body, tag: alert.id }) }
        catch { setNotificationError('Desktop notification delivery failed. All alerts remain in the alert list.') }
      }
    }, 500)
    socket.connect(); void reconcile()
    return () => { active = false; request?.abort(); clearTimeout(scheduled); clearTimeout(toastTimer); clearInterval(poll); clearInterval(notifications); socket.disconnect() }
  }, [])
  return <AlertsContext.Provider value={{ revision, connected, summary, error, suppressed, notificationError, preferences, savePreferences }}>{children}
    {toast && preferences.inApp && <aside className="alert-toast" role="status"><strong>{toast.source === 'offline' ? 'Offline analysis' : 'Live observation'} · {toast.severity}</strong><p>New suspicious observation · {toast.ruleId}</p><Link to="/threats" onClick={() => setToast(null)}>Review alerts</Link><button className="text-button" onClick={() => setToast(null)}>Dismiss</button></aside>}
    {(suppressed > 0 || notificationError) && <aside className="notification-limit" role="status">{suppressed > 0 ? `${suppressed} notifications suppressed by queue or deduplication limits. All alerts remain in Threat Detection. ` : ''}{notificationError}</aside>}
  </AlertsContext.Provider>
}
