import type { SecurityAlert } from './alerts'
export interface NotificationPreferences { inApp: boolean; desktop: boolean; replay: boolean; severities: string[] }
export const defaults: NotificationPreferences = { inApp: true, desktop: false, replay: false, severities: ['High', 'Medium', 'Low'] }
export function normalizePreferences(v: unknown): NotificationPreferences {
  if (!v || typeof v !== 'object') return { ...defaults, severities: [...defaults.severities] }
  const p = v as Record<string, unknown>
  return { inApp: typeof p.inApp === 'boolean' ? p.inApp : true, desktop: p.desktop === true, replay: p.replay === true, severities: Array.isArray(p.severities) ? p.severities.filter((s): s is string => typeof s === 'string' && ['High', 'Medium', 'Low'].includes(s)) : [...defaults.severities] }
}
export class NotificationQueue {
  queue: SecurityAlert[] = []; seen = new Map<string, number>(); retiredBefore = -Infinity; suppressed = 0; last = -Infinity
  readonly capacity: number; readonly cooldown: number
  constructor(capacity = 20, cooldown = 5000) { this.capacity = capacity; this.cooldown = cooldown }
  offer(alert: SecurityAlert, preferences: NotificationPreferences) {
    if (this.seen.has(alert.id)) return
    const timestamp = Date.parse(alert.createdAt)
    if (timestamp <= this.retiredBefore) { this.suppressed++; return }
    this.remember(alert)
    if ((!preferences.inApp && !preferences.desktop) || !preferences.severities.includes(alert.severity) || (alert.source === 'offline' && !preferences.replay)) return
    if (this.queue.length >= this.capacity) {
      this.suppressed++
      const lower = this.queue.findIndex(item => item.severity !== 'High')
      if (alert.severity !== 'High' || lower < 0) return
      this.queue.splice(lower, 1)
    }
    this.queue.push(alert)
  }
  remember(alert: SecurityAlert) {
    this.seen.set(alert.id, Date.parse(alert.createdAt))
    if (this.seen.size > 2000) { const [id, timestamp] = this.seen.entries().next().value!; this.retiredBefore = Math.max(this.retiredBefore, timestamp); this.seen.delete(id) }
  }
  cancel(alert: SecurityAlert) { this.remember(alert); this.queue = this.queue.filter(item => item.id !== alert.id) }
  take(now: number, preferences: NotificationPreferences) {
    if (now - this.last < this.cooldown) return undefined
    while (this.queue.length) {
      const alert = this.queue.shift()!
      if ((!preferences.inApp && !preferences.desktop) || !preferences.severities.includes(alert.severity) || (alert.source === 'offline' && !preferences.replay)) continue
      this.last = now; return alert
    }
    return undefined
  }
}
export interface DesktopAPI { permission: NotificationPermission; requestPermission: () => Promise<NotificationPermission> }
export async function requestDesktopPermission(api?: DesktopAPI): Promise<string> { if (!api) return 'unsupported'; if (api.permission !== 'default') return api.permission; return api.requestPermission() }
export function desktopText(alert: SecurityAlert) { return { title: `NetGuard · ${alert.severity} ${alert.source === 'offline' ? 'offline' : 'live'} alert`, body: 'A suspicious observation requires review. Open NetGuard for details.' } }
