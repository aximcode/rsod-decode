import { useEffect, useRef, useState } from 'react'

/**
 * Lazy-fetch hook for tab content.
 *
 * Returns `null` until `active` becomes true, then calls `fetcher()`.
 * Resets to `null` whenever any value in `deps` changes so the next
 * activation triggers a fresh fetch.
 */
export function useTabData<T>(
  active: boolean,
  deps: unknown[],
  fetcher: () => Promise<T>,
  fallback: T,
): { data: T | null; loading: boolean } {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const prevDeps = useRef<unknown[]>(deps)

  // Reset when deps change
  useEffect(() => {
    const changed = deps.some((d, i) => d !== prevDeps.current[i])
    if (changed) {
      prevDeps.current = deps
      setData(null)
    }
  }) // intentionally no dep array — runs every render to compare

  // Fetch when tab becomes active and data hasn't been loaded yet.
  // `loading` is intentionally NOT in the dep array: setting it here
  // would re-run this effect, fire the cleanup, set stale=true, and
  // silently drop the in-flight fetch's result.
  useEffect(() => {
    if (!active || data !== null) return
    let stale = false
    setLoading(true)
    fetcher()
      .then(r => { if (!stale) { setData(r); setLoading(false) } })
      .catch(() => { if (!stale) { setData(fallback); setLoading(false) } })
    return () => { stale = true }
  }, [active, data]) // eslint-disable-line react-hooks/exhaustive-deps

  return { data, loading }
}
