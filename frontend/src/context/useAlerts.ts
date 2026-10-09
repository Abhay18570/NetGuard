import { createContext, useContext } from 'react'
import type { AlertSummary } from '../services/alerts'
import type { NotificationPreferences } from '../services/notifications'
export interface AlertsContextValue { revision: number; connected: boolean; summary: AlertSummary | null; error: string; suppressed: number; notificationError: string; preferences: NotificationPreferences; savePreferences: (value: NotificationPreferences) => void }
export const AlertsContext = createContext<AlertsContextValue | null>(null)
export function useAlerts() { const context = useContext(AlertsContext); if (!context) throw new Error('Alert provider required'); return context }
