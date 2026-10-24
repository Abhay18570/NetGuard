import { createContext, useContext } from 'react'
import type { ConnectionState, MonitorStatus, NetworkInterface, Snapshot } from '../types'
interface MonitorContextValue { data: Snapshot; connection: ConnectionState; error: string; monitor: MonitorStatus | null; interfaces: NetworkInterface[]; streamConnected: boolean; inventoryRevision: number; inventoryError: string; refresh: () => Promise<void> }
export const MonitorContext = createContext<MonitorContextValue | null>(null)
export function useMonitor() { const value = useContext(MonitorContext); if (!value) throw new Error('MonitorProvider is required'); return value }
