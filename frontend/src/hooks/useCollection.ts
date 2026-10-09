import { useEffect, useState } from 'react'
import type { CollectionResponse } from '../types'
export function useCollection<T>(loader: (signal: AbortSignal) => Promise<CollectionResponse<T>>, revision = 0) {
  const [data, setData] = useState<CollectionResponse<T>>({ items: [], total: 0, limit: 25, offset: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    // These loading updates describe synchronization with the external REST API.
    // oxlint-disable-next-line react/set-state-in-effect
    setLoading(true)
    setError('')
    loader(controller.signal).then(result => { if (!controller.signal.aborted) setData(result) })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) {
          setData({ items: [], total: 0, limit: 25, offset: 0 })
          setError(cause instanceof Error ? cause.message : 'Unable to load inventory.')
        }
      }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [loader, revision, retry])
  return { ...data, loading, error, retry: () => setRetry(value => value + 1) }
}
