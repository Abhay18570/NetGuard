import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import { isIncidentEvent } from '../services/incidents'
export function useIncidentRefresh() {
  const [revision, setRevision] = useState(0); const [connected, setConnected] = useState(false)
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const refresh = () => { if (!timer) timer = setTimeout(() => { timer = undefined; setRevision(v => v + 1) }, 250) }
    const socket = io({ autoConnect: false })
    socket.on('connect', () => { setConnected(true); refresh() }); socket.on('disconnect', () => { setConnected(false); refresh() })
    for (const event of ['incident_created', 'incident_updated']) socket.on(event, (value: unknown) => { if (isIncidentEvent(value)) refresh() })
    const poll = setInterval(refresh, 3000); socket.connect()
    return () => { clearInterval(poll); clearTimeout(timer); socket.disconnect() }
  }, [])
  return { revision, connected }
}
