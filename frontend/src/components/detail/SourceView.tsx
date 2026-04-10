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
    <div className="font-mono text-sm">
      {source.file && (
        <div className="text-zinc-500 text-xs mb-2">{source.file}</div>
      )}
      {source.lines.map(line => (
        <div
          key={line.number}
          className={`flex py-px px-2 rounded ${line.is_target ? 'bg-yellow-950/40 text-yellow-200' : 'text-zinc-300'}`}
        >
          <span className={`w-4 shrink-0 ${line.is_target ? 'text-yellow-400' : ''}`}>{line.is_target ? '\u25B6' : ''}</span>
          <span className="text-zinc-600 w-12 shrink-0 text-right mr-3">{line.number}</span>
          <span className="whitespace-pre">{line.text}</span>
        </div>
      ))}
    </div>
  )
}
