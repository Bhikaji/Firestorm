import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../services/api'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
  refresh: () => void
  setData: (updater: T | ((current: T | null) => T | null)) => void
  lastUpdated: number | null
}

/**
 * Small data-fetching hook with explicit loading/error states and manual
 * refresh. Requests are aborted when the component unmounts or params change.
 */
export function useAsync<T>(fetcher: () => Promise<T>, deps: unknown[] = [], options: { enabled?: boolean } = {}): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(options.enabled !== false)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [nonce, setNonce] = useState(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    if (options.enabled === false) return
    let cancelled = false
    setLoading(true)
    fetcher()
      .then((result) => {
        if (cancelled || !mounted.current) return
        setData(result)
        setError(null)
        setLastUpdated(Date.now())
      })
      .catch((err: unknown) => {
        if (cancelled || !mounted.current) return
        setError(err instanceof ApiError ? err.message : 'Unable to load data')
      })
      .finally(() => {
        if (!cancelled && mounted.current) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, options.enabled])

  const refresh = useCallback(() => setNonce((value) => value + 1), [])
  return { data, loading, error, refresh, setData, lastUpdated }
}

export function useNow(intervalMs = 1000): Date {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])
  return now
}

export function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return debounced
}
