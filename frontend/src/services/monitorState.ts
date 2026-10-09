import type { MonitorStatus, Packet } from '../types'
export const DISPLAY_PACKET_LIMIT = 500
export function mergePackets(current: Packet[], incoming: Packet[], sessionId: string | null): Packet[] {
  if (!sessionId) return []
  const unique = new Map<string, Packet>()
  for (const packet of [...current, ...incoming]) {
    if (packet.sessionId === sessionId) unique.set(packet.id, packet)
  }
  return [...unique.values()].sort((a, b) => b.sequence - a.sequence).slice(0, DISPLAY_PACKET_LIMIT)
}
export function statusLabel(status: MonitorStatus | null, connected = true): string {
  if (!connected) return 'Status unavailable'
  if (!status) return 'Monitoring Not Started'
  if (status.mode === 'offline') {
    return { not_started: 'Offline replay', starting: 'Preparing replay', running: 'Offline replay running', stopping: 'Stopping replay', stopped: 'Offline replay stopped', completed: 'Offline replay completed', error: 'Offline replay failed' }[status.state]
  }
  return { not_started: 'Monitoring Not Started', starting: 'Starting capture', running: 'Live capture active', stopping: 'Stopping capture', stopped: 'Capture stopped', completed: 'Capture completed', error: 'Capture failed' }[status.state]
}
