import { useCallback, useEffect, useRef } from 'react'
import type { SourceLine } from '../../types'

interface SourceData {
  file: string
  target_line: number
  lines: SourceLine[]
}

interface Props {
  source: SourceData | null
  loading: boolean
}

export function SourceView({ source, loading }: Props) {
  const targetRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  const scrollToTarget = useCallback(() => {
    targetRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' })
  }, [])

  // Auto-scroll to the target line when source data arrives or changes.
  useEffect(() => {
    if (source && source.lines.length > 0) {
      // Small delay so the DOM renders before we measure.
      const id = requestAnimationFrame(() => {
        targetRef.current?.scrollIntoView({ block: 'center' })
      })
      return () => cancelAnimationFrame(id)
    }
  }, [source])

  if (loading) {
    return (
      <div className="text-zinc-500 text-sm flex items-center gap-2">
        <span className="animate-spin inline-block w-4 h-4 border-2 border-zinc-600 border-t-zinc-300 rounded-full" />
        Loading source...
      </div>
    )
  }
  if (!source || source.lines.length === 0) {
    return <div className="text-zinc-600 text-sm">No source available for this frame</div>
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between px-2 py-1 shrink-0">
        <span className="text-zinc-500 text-xs truncate">{source.file}</span>
        <button
          onClick={scrollToTarget}
          className="text-xs text-zinc-500 hover:text-zinc-200 border border-zinc-700 rounded px-2 py-0.5 hover:border-zinc-500 transition-colors shrink-0 ml-2"
          title={`Jump to line ${source.target_line}`}
        >
          Go to line {source.target_line}
        </button>
      </div>
      <div
        ref={containerRef}
        className="overflow-auto flex-1 min-h-0 font-mono text-sm"
      >
        {source.lines.map(line => (
          <div
            key={line.number}
            ref={line.is_target ? targetRef : undefined}
            className={`flex py-px px-2 ${
              line.is_target
                ? 'bg-yellow-950/40 text-yellow-200 sticky top-0 bottom-0 z-10'
                : 'text-zinc-300'
            }`}
          >
            <span className={`w-4 shrink-0 ${line.is_target ? 'text-yellow-400' : ''}`}>
              {line.is_target ? '\u25B6' : ''}
            </span>
            <span className="text-zinc-600 w-12 shrink-0 text-right mr-3">
              {line.number}
            </span>
            <span className="whitespace-pre">{line.text}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
