import { useRef, useState } from 'react'
import * as api from '../../api'
import type { VarInfo } from '../../types'
import { formatValueWithHex } from '../HexAddress'
import { VarTooltip } from '../VarTooltip'

interface VarsTableProps {
  vars: VarInfo[]
  isCrashFrame: boolean
  label: string
  sessionId: string
  frameIndex: number
  onNavigateMemory: (addr: number) => void
  note?: string
}

export function VarsTable({ vars, isCrashFrame, label, sessionId, frameIndex, onNavigateMemory, note }: VarsTableProps) {
  if (vars.length === 0) {
    return <div className="text-zinc-600 text-sm">No {label} available for this frame</div>
  }
  return (
    <>
      {note && (
        <div className="text-xs text-zinc-600 mb-3 italic">{note}</div>
      )}
      {!note && !isCrashFrame && (
        <div className="text-xs text-zinc-600 mb-3 italic">
          Register values are from the crash point, not this frame's call site
        </div>
      )}
      <table className="w-full text-sm font-mono">
        <thead>
          <tr className="text-left text-xs text-zinc-500 uppercase tracking-wider">
            <th className="pb-2 pr-4">Name</th>
            <th className="pb-2 pr-4">Type</th>
            <th className="pb-2 pr-4">Location</th>
            <th className="pb-2">Value</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/50">
          {vars.map((v) => (
            <VarRow key={`${frameIndex}-${v.name}`} v={v} isCrashFrame={isCrashFrame} depth={0}
                    sessionId={sessionId} frameIndex={frameIndex} onNavigateMemory={onNavigateMemory} />
          ))}
        </tbody>
      </table>
    </>
  )
}

function VarRow({ v, isCrashFrame, depth, sessionId, frameIndex, onNavigateMemory }: {
  v: VarInfo | api.ExpandField; isCrashFrame: boolean; depth: number
  sessionId: string; frameIndex: number; onNavigateMemory: (addr: number) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [children, setChildren] = useState<api.ExpandField[] | null>(null)
  const [totalCount, setTotalCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [showTooltip, setShowTooltip] = useState(false)
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const nameRef = useRef<HTMLSpanElement>(null)

  const varKey = 'var_key' in v ? (v as { var_key?: string }).var_key : undefined
  const canExpand = v.is_expandable && (v.expand_addr !== null || !!varKey)
  const showToggle = v.is_expandable
  const approximate = 'approximate' in v && v.approximate
  const location = 'location' in v ? v.location : ''
  const access = 'access' in v ? (v as api.ExpandField).access : undefined

  const toggle = () => {
    if (!canExpand) return
    if (expanded) {
      setExpanded(false)
      return
    }
    setExpanded(true)
    if (children !== null) return
    setLoading(true)
    api.expandVar(sessionId, frameIndex, v.expand_addr ?? 0, v.type_offset, v.cu_offset, undefined, undefined, varKey)
      .then(r => { setChildren(r.fields); setTotalCount(r.total_count); setLoading(false) })
      .catch(() => { setChildren([]); setLoading(false) })
  }

  const loadMore = () => {
    if (!children || loading) return
    setLoading(true)
    api.expandVar(sessionId, frameIndex, v.expand_addr ?? 0, v.type_offset, v.cu_offset, children.length, undefined, varKey)
      .then(r => { setChildren([...children, ...r.fields]); setLoading(false) })
      .catch(() => setLoading(false))
  }

  const indent = depth * 16
  const hasMore = children !== null && children.length < totalCount

  return (
    <>
      <tr className="hover:bg-zinc-800/30">
        <td className="py-1.5 pr-4" style={{ paddingLeft: indent }}>
          {showToggle ? (
            <button
              onClick={toggle}
              disabled={!canExpand}
              className={`mr-1 w-4 inline-block ${canExpand ? 'text-zinc-500 hover:text-zinc-300' : 'text-zinc-700 cursor-default'}`}
            >
              {loading && !children ? '\u00B7' : expanded ? '\u25BC' : '\u25B6'}
            </button>
          ) : (
            <span className="inline-block w-4 mr-1" />
          )}
          <span
            ref={nameRef}
            className={`text-yellow-300 ${canExpand && !expanded ? 'cursor-help' : ''}`}
            onMouseEnter={() => {
              if (!canExpand || expanded) return
              hoverTimer.current = setTimeout(() => setShowTooltip(true), 300)
            }}
            onMouseLeave={() => {
              if (hoverTimer.current) { clearTimeout(hoverTimer.current); hoverTimer.current = null }
            }}
          >{v.name}</span>
          {access && <span className="text-zinc-600 text-xs ml-1">{access}</span>}
          {showTooltip && canExpand && (
            <VarTooltip
              sessionId={sessionId}
              frameIndex={frameIndex}
              expandAddr={v.expand_addr}
              typeOffset={v.type_offset}
              cuOffset={v.cu_offset}
              varKey={varKey}
              anchorRef={nameRef}
              onClose={() => setShowTooltip(false)}
            />
          )}
        </td>
        <td className="py-1.5 pr-4 text-zinc-400">{v.type}</td>
        <td className="py-1.5 pr-4 text-zinc-500">{location}</td>
        <td className={`py-1.5 ${approximate ? 'text-zinc-500 italic' : 'text-zinc-200'}`}>
          {approximate && v.value !== null ? '~ ' : ''}{formatValueWithHex(v.value, onNavigateMemory)}
          {v.string_preview && (
            <span className="text-green-400 ml-2">
              &quot;{v.string_preview.length > 48 ? v.string_preview.slice(0, 48) + '\u2026' : v.string_preview}&quot;
            </span>
          )}
        </td>
      </tr>
      {expanded && children?.map((child) => (
        <VarRow key={child.name} v={child} isCrashFrame={isCrashFrame} depth={depth + 1}
                sessionId={sessionId} frameIndex={frameIndex} onNavigateMemory={onNavigateMemory} />
      ))}
      {expanded && hasMore && (
        <tr>
          <td colSpan={4} className="py-1" style={{ paddingLeft: indent + 20 }}>
            <button onClick={loadMore} disabled={loading}
              className="text-xs text-blue-400 hover:text-blue-300 disabled:text-zinc-600">
              {loading ? 'loading\u2026' : `show more (${children!.length} of ${totalCount})`}
            </button>
          </td>
        </tr>
      )}
      {expanded && children?.length === 0 && !loading && (
        <tr><td colSpan={4} className="py-1 text-zinc-600 text-xs italic" style={{ paddingLeft: indent + 20 }}>
          memory not available
        </td></tr>
      )}
    </>
  )
}
