import { useCallback, useRef, useState } from 'react'
import type { FrameSummary } from '../types'

interface Props {
  frames: FrameSummary[]
  callVerified: Record<string, boolean>
  selectedIndex: number
  onSelect: (index: number) => void
}

export function BacktracePanel({ frames, callVerified, selectedIndex, onSelect }: Props) {
  const [width, setWidth] = useState(320)
  const widthRef = useRef(320)
  const startX = useRef(0)
  const startW = useRef(0)
  widthRef.current = width

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    startX.current = e.clientX
    startW.current = widthRef.current

    const onMouseMove = (ev: MouseEvent) => {
      const newW = Math.max(200, Math.min(800, startW.current + ev.clientX - startX.current))
      setWidth(newW)
    }
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [])

  return (
    <div className="shrink-0 border-r border-zinc-800 overflow-y-auto bg-zinc-900 relative flex" style={{ width }}>
      <div className="flex-1 overflow-y-auto">
      <div className="px-3 py-2 border-b border-zinc-800 text-xs text-zinc-500 font-medium uppercase tracking-wider">
        Backtrace ({frames.length} frames)
      </div>
      <div className="divide-y divide-zinc-800/50">
        {frames.map(frame => {
          const isSelected = frame.index === selectedIndex
          const verified = callVerified[String(frame.address)]
          return (
            <button
              key={frame.index}
              onClick={() => onSelect(frame.index)}
              aria-selected={isSelected}
              className={`w-full text-left px-3 py-2 text-sm font-mono transition-colors ${
                isSelected
                  ? 'bg-blue-950 border-l-2 border-blue-400'
                  : 'hover:bg-zinc-800/50 border-l-2 border-transparent'
              }`}
            >
              <div className="flex items-baseline gap-2 min-w-0">
                <span className="text-zinc-600 shrink-0">#{frame.index}</span>
                <span className={`truncate ${
                  isSelected ? 'text-blue-200'
                  : frame.is_synthetic ? 'text-violet-300 italic'
                  : 'text-zinc-200'}`}>
                  {frame.symbol ?? '???'}
                </span>
                {frame.is_synthetic && (
                  <span
                    className="shrink-0 text-[10px] uppercase tracking-wider px-1 py-px rounded bg-violet-950 text-violet-300 border border-violet-800"
                    title="Synthetic frame — re-materialized from a tail-called function. No stack frame existed at runtime, so param/local values are unavailable."
                  >
                    tail
                  </span>
                )}
                {verified === true && <span className="text-green-500 shrink-0" title="Call verified">&#10003;</span>}
                {verified === false && <span className="text-yellow-500 shrink-0" title="Stale return address">&#9888;</span>}
              </div>
              {frame.source_loc && (
                <div className="text-xs text-zinc-500 truncate mt-0.5 pl-5">
                  {frame.source_loc}
                </div>
              )}
              {frame.module && (
                <div className="text-xs text-zinc-600 truncate pl-5">
                  [{frame.module}]
                </div>
              )}
              {frame.inlines.map((inline, i) => (
                <div key={i} className="text-xs text-zinc-500 pl-5 mt-0.5">
                  <span className="text-zinc-600">&#8627; inlined</span>{' '}
                  <span className="text-zinc-400">{inline.function}</span>
                  {inline.source_loc && (
                    <span className="text-zinc-600 ml-1">{inline.source_loc}</span>
                  )}
                </div>
              ))}
            </button>
          )
        })}
      </div>
      </div>
      {/* Drag handle */}
      <div
        onMouseDown={onMouseDown}
        className="w-1 cursor-col-resize hover:bg-blue-500/50 active:bg-blue-500/70 shrink-0"
      />
    </div>
  )
}
