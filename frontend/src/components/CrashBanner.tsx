import type { CrashSummary, LbrEntry } from '../types'

type BackendId = 'pyelftools' | 'gdb' | 'lldb'

interface Props {
  crash: CrashSummary
  onNewAnalysis: () => void
  backend: string
  gdbAvailable: boolean
  lldbAvailable: boolean
  onSwitchBackend: (backend: BackendId) => void
  backendSwitching: boolean
  lbr?: LbrEntry[]
}

function hex(n: number | null): string {
  return n !== null ? `0x${n.toString(16).toUpperCase()}` : '?'
}

export function CrashBanner({
  crash, onNewAnalysis, backend, gdbAvailable, lldbAvailable,
  onSwitchBackend, backendSwitching, lbr,
}: Props) {
  const backends: { id: BackendId; label: string; enabled: boolean }[] = [
    { id: 'pyelftools', label: 'pyelf', enabled: true },
    { id: 'gdb',        label: 'gdb',   enabled: gdbAvailable  || backend === 'gdb'  },
    { id: 'lldb',       label: 'lldb',  enabled: lldbAvailable || backend === 'lldb' },
  ]

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

          {lbr && lbr.length > 0 && (
            <div className="text-zinc-400 text-xs">
              <span className="text-zinc-500">LBR:</span>{' '}
              {lbr.map((e, i) => (
                <span key={i} className="ml-2">
                  <span className="text-zinc-600">{e.type}</span>{' '}
                  <span className="text-zinc-300">{e.module}+0x{e.offset.toString(16).toUpperCase()}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-1.5 items-end shrink-0">
          <button
            onClick={onNewAnalysis}
            className="text-xs text-zinc-500 hover:text-zinc-300 border border-zinc-700 rounded px-2 py-1 hover:border-zinc-500 transition-colors"
          >
            New Analysis
          </button>
          <div className="flex items-center gap-1 text-xs">
            <span className="text-zinc-500 mr-1">backend:</span>
            {backends.map(b => {
              const current = backend === b.id
              const clickable = b.enabled && !current && !backendSwitching
              return (
                <button
                  key={b.id}
                  onClick={clickable ? () => onSwitchBackend(b.id) : undefined}
                  disabled={!clickable}
                  className={[
                    'border rounded px-1.5 py-0.5 transition-colors',
                    current
                      ? 'border-zinc-400 text-zinc-200 bg-zinc-800'
                      : b.enabled
                      ? 'border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-500'
                      : 'border-zinc-800 text-zinc-700 cursor-not-allowed',
                    backendSwitching && !current ? 'opacity-50 cursor-wait' : '',
                  ].join(' ')}
                  title={b.enabled ? `switch to ${b.id}` : `${b.id} not available`}
                >
                  {b.label}
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
