import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { io } from 'socket.io-client'
import { MonitorContext } from './useMonitor'
import { api, emptySnapshot, isPacketEvent, isStatusEvent, isDeviceEvent, isTrustEvent, isDiscoveryEvent } from '../services/api'
import { mergePackets } from '../services/monitorState'
import type { ConnectionState, MonitorStatus, NetworkInterface, Packet } from '../types'
export function MonitorProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState(emptySnapshot)
  const [connection, setConnection] = useState<ConnectionState>('loading')
  const [inventoryRevision, setInventoryRevision] = useState(0)
  const [inventoryError, setInventoryError] = useState('')
  const [error, setError] = useState('')
  const [monitor, setMonitor] = useState<MonitorStatus | null>(null)
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [streamConnected, setStreamConnected] = useState(false)
  const pending = useRef<AbortController | null>(null)
  const staged = useRef<Packet[]>([])
  const latest = useRef<MonitorStatus | null>(null)
  const applyStatus = useCallback((status: MonitorStatus) => {
    if (latest.current && status.revision < latest.current.revision) return
    const changed = latest.current?.sessionId !== status.sessionId
    latest.current = status
    setMonitor(status)
    if (changed) setData(current => ({ ...current, packets: [] }))
  }, [])
  const load = useCallback(async (controller: AbortController) => {
    try {
      const result = await api.getWorkspace(controller.signal)
      if (controller.signal.aborted) return
      applyStatus(result.monitor)
      setInventoryError(result.inventoryError)
      const incoming = [...result.data.packets, ...staged.current]
      const sessionId = latest.current?.sessionId ?? null
      staged.current = []
      setData(current => ({ ...result.data, packets: mergePackets(current.packets, incoming, sessionId) }))
      setInterfaces(result.interfaces); setConnection('connected'); setError('')
    } catch (cause) {
      if (controller.signal.aborted) return
      setConnection('error'); setInterfaces([])
      setError(cause instanceof Error ? cause.message : 'Unable to connect to the backend.')
    }
  }, [applyStatus])
  const refresh = useCallback(async () => {
    pending.current?.abort()
    const controller = new AbortController(); pending.current = controller
    setConnection('loading'); setError('')
    await load(controller)
  }, [load])
  useEffect(() => {
    let active = true
    let poll: AbortController | null = null
    let inventoryTimer: number | undefined
    let inventoryRequest: AbortController | null = null
    const socket = io({ path: '/socket.io', autoConnect: false })
    function reload() {
      pending.current?.abort(); poll?.abort(); inventoryRequest?.abort()
      window.clearTimeout(inventoryTimer); inventoryTimer = undefined
      const controller = new AbortController(); pending.current = controller
      // Reconnect can follow a server restart with a reset revision counter.
      latest.current = null
      void load(controller)
    }
    socket.on('connect', () => { setStreamConnected(true); setInventoryRevision(value => value + 1); reload() })
    socket.on('disconnect', () => { setStreamConnected(false); setConnection('disconnected') })
    socket.on('connect_error', () => { setStreamConnected(false) })
    socket.on('monitor_status', (event: unknown) => {
      if (isStatusEvent(event)) applyStatus(event.status)
      else setError('Received an invalid monitoring status event. Recheck the connection.')
    })
    socket.on('arp_packet', (event: unknown) => {
      if (!isPacketEvent(event)) { setError('Received an invalid packet event.'); return }
      // Only retain packets for the authoritative current session. On reconnect,
      // the REST snapshot recovers bounded history missed by the socket stream.
      if (!latest.current) { staged.current = [...staged.current, event.packet].slice(-500); return }
      if (event.packet.sessionId !== latest.current.sessionId) return
      setData(current => ({ ...current, packets: mergePackets(current.packets, [event.packet], event.packet.sessionId) }))
    })
    const inventoryChanged = (event: unknown) => {
      if (isDeviceEvent(event) || isTrustEvent(event)) {
        if (inventoryTimer !== undefined) return
        inventoryTimer = window.setTimeout(() => {
          inventoryTimer = undefined
          setInventoryRevision(value => value + 1)
          inventoryRequest?.abort()
          const controller = new AbortController(); inventoryRequest = controller
          Promise.all([api.getDevicePage('', 'all', false, 0, controller.signal), api.getDiscoveryStatus(controller.signal)]).then(([result, status]) => {
            if (!active || controller.signal.aborted) return
            setData(current => ({ ...current, devices: result.items, deviceTotal: result.total }))
            setInventoryError(status.message || '')
          }).catch((cause: unknown) => {
            if (active && !controller.signal.aborted) setInventoryError(cause instanceof Error ? cause.message : 'Inventory unavailable.')
          })
        }, 500)
      }
      else setInventoryError('Received an invalid inventory update. Refresh the inventory.')
    }
    socket.on('device_discovered', inventoryChanged)
    socket.on('device_updated', inventoryChanged)
    socket.on('trusted_mapping_updated', inventoryChanged)
    socket.on('discovery_status', (event: unknown) => {
      if (isDiscoveryEvent(event)) setInventoryError(event.status.message || '')
    })
    socket.connect()
    // Socket.IO is an external system; initial requests update state asynchronously.
    // oxlint-disable-next-line react/set-state-in-effect
    reload()
    const timer = window.setInterval(() => {
      // Reconcile status even on a quiet network and recover dropped transport events.
      if (!pending.current || pending.current.signal.aborted) return
      poll?.abort()
      const controller = new AbortController(); poll = controller
      api.getMonitorStatus(controller.signal).then(status => {
        if (active && !controller.signal.aborted) applyStatus(status)
      }).catch(() => {
        if (active && !controller.signal.aborted) setConnection('disconnected')
      })
    }, 3000)
    return () => { active = false; inventoryRequest?.abort(); window.clearTimeout(inventoryTimer); poll?.abort(); window.clearInterval(timer); pending.current?.abort(); socket.disconnect() }
  }, [load, applyStatus])
  return <MonitorContext.Provider value={{ data, connection, error, monitor, interfaces, streamConnected, inventoryRevision, inventoryError, refresh }}>{children}</MonitorContext.Provider>
}
