import type { CrashSummary } from '../types'

interface Props {
  crash: CrashSummary
  onNewAnalysis: () => void
}

function hex(n: number | null): string {
  return n !== null ? `0x${n.toString(16).toUpperCase()}` : '?'
}

export function CrashBanner({ crash, onNewAnalysis }: Props) {
  return (
    <div className="bg-red-950 border-b border-red-900 px-4 py-3 font-mono text-sm shrink-0">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-0.5 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-bold">RSOD</span>
            {crash.exception_desc && (
              <span className="text-zinc-200">{crash.exception_desc}</span>
            )}
          </div>

          <div className="text-zinc-300">
            <span className="text-zinc-500">PC:</span>{' '}
            <span className="text-yellow-300">{hex(crash.crash_pc)}</span>
            {crash.crash_symbol && (
              <span className="text-zinc-400 ml-2"> {crash.crash_symbol}</span>
            )}
          </div>

          {crash.esr !== null && (
            <div className="text-zinc-300">
              <span className="text-zinc-500">ESR:</span>{' '}
              <span>{hex(crash.esr)}</span>
              {crash.far !== null && (
                <>
                  <span className="text-zinc-500 ml-3"> FAR:</span>{' '}
                  <span>{hex(crash.far)}</span>
                  {crash.far < 0x100 && (
                    <span className="text-red-400 ml-2">NULL deref</span>
                  )}
                </>
              )}
            </div>
          )}

          <div className="text-zinc-400">
            <span className="text-zinc-500">Image:</span>{' '}
            {crash.image_name}
            <span className="text-zinc-600 ml-2"> {crash.format}</span>
          </div>
        </div>

        <button
          onClick={onNewAnalysis}
          className="shrink-0 text-xs text-zinc-500 hover:text-zinc-300 border border-zinc-700 rounded px-2 py-1 hover:border-zinc-500 transition-colors"
        >
          New Analysis
        </button>
      </div>
    </div>
  )
}
