import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import { isFindingEvent } from '../services/detection'
// REST is authoritative: reconnect and polling recover missed or coalesced events.
export function useDetectionRevision() {
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const socket = io({ autoConnect: false }); let timer: ReturnType<typeof setTimeout> | undefined
    const refresh = () => { if (!timer) timer = setTimeout(() => { timer = undefined; setRevision(v => v + 1) }, 250) }
    socket.on('connect', refresh)
    socket.on('disconnect', refresh)
    socket.on('detection_finding', (event: unknown) => { if (isFindingEvent(event)) refresh() })
    const poll = setInterval(refresh, 3000); socket.connect()
    return () => { clearInterval(poll); clearTimeout(timer); socket.disconnect() }
  }, [])
  return revision
}
