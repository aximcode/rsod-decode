import { useEffect, useRef, useState } from 'react'
import * as api from '../api'

interface Props {
  sessionId: string
  frameIndex: number
  expandAddr: number | null
  typeOffset: number
  cuOffset: number
  varKey?: string
  anchorRef: React.RefObject<HTMLElement | null>
  onClose: () => void
}

// Module-level cache: key → fields (persists across hovers)
const cache = new Map<string, api.ExpandField[]>()

function cacheKey(sessionId: string, frameIndex: number, addr: number, to: number, co: number, vk?: string): string {
  return `${sessionId}:${frameIndex}:${addr}:${to}:${co}:${vk ?? ''}`
}

export function VarTooltip({ sessionId, frameIndex, expandAddr, typeOffset, cuOffset, varKey, anchorRef, onClose }: Props) {
  const [fields, setFields] = useState<api.ExpandField[] | null>(null)
  const [loading, setLoading] = useState(true)
  const tooltipRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const key = cacheKey(sessionId, frameIndex, expandAddr ?? 0, typeOffset, cuOffset, varKey)
    const cached = cache.get(key)
    if (cached) {
      setFields(cached)
      setLoading(false)
      return
    }

    let stale = false
    api.expandVar(sessionId, frameIndex, expandAddr ?? 0, typeOffset, cuOffset, undefined, 8, varKey)
      .then(r => {
        if (stale) return
        cache.set(key, r.fields)
        setFields(r.fields)
        setLoading(false)
      })
      .catch(() => {
        if (!stale) { setFields([]); setLoading(false) }
      })
    return () => { stale = true }
  }, [sessionId, frameIndex, expandAddr, typeOffset, cuOffset, varKey])

  // Position tooltip near the anchor element
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null)
  useEffect(() => {
    const el = anchorRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    setPos({ top: rect.bottom + 4, left: rect.left })
  }, [anchorRef])

  // Close on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (tooltipRef.current && !tooltipRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [onClose])

  if (!pos) return null

  return (
    <div
      ref={tooltipRef}
      className="fixed z-50 bg-zinc-800 border border-zinc-600 rounded shadow-lg shadow-black/50 p-2 font-mono text-xs max-w-md"
      style={{ top: pos.top, left: pos.left }}
      onMouseLeave={onClose}
    >
      {loading && <div className="text-zinc-500 animate-pulse">loading...</div>}
      {!loading && fields && fields.length === 0 && (
        <div className="text-zinc-600 italic">no fields</div>
      )}
      {!loading && fields && fields.length > 0 && (
        <div className="space-y-0.5">
          {fields.slice(0, 8).map(f => (
            <div key={f.name} className="flex gap-2">
              <span className="text-yellow-300 shrink-0">{f.name}</span>
              <span className="text-zinc-500 shrink-0">{f.type}</span>
              <span className="text-zinc-300 truncate">
                {f.value !== null
                  ? f.value >= 0x10000
                    ? `0x${f.value.toString(16).toUpperCase()}`
                    : `${f.value}`
                  : '\u2014'}
                {f.string_preview && (
                  <span className="text-green-400 ml-1">
                    &quot;{f.string_preview.length > 32 ? f.string_preview.slice(0, 32) + '\u2026' : f.string_preview}&quot;
                  </span>
                )}
              </span>
            </div>
          ))}
          {fields.length > 8 && (
            <div className="text-zinc-600 italic">...and more</div>
          )}
        </div>
      )}
    </div>
  )
}
