import type { FrameDetail, VarInfo } from '../types'

interface Props {
  frame: FrameDetail | null
  loading: boolean
  error?: string | null
  isCrashFrame: boolean
}

function formatValue(value: number | null): string {
  if (value === null) return '\u2014'
  const hex = `0x${value.toString(16).toUpperCase()}`
  if (value < 0x10000) {
    return `${hex} (${value})`
  }
  return hex
}

function filterParams(params: VarInfo[]): VarInfo[] {
  return params.filter(p => p.name !== '???')
}

const TABS = ['Params', 'Locals', 'Disassembly', 'Source'] as const

export function DetailPanel({ frame, loading, error, isCrashFrame }: Props) {
  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center text-zinc-500">
        <span className="animate-spin inline-block w-5 h-5 border-2 border-zinc-600 border-t-zinc-300 rounded-full mr-2" />
        Loading frame...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex-1 flex items-center justify-center text-red-400 text-sm">
        Failed to load frame: {error}
      </div>
    )
  }

  if (!frame) {
    return (
      <div className="flex-1 flex items-center justify-center text-zinc-600">
        Select a frame from the backtrace
      </div>
    )
  }

  const params = filterParams(frame.params)

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Frame header */}
      <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-900/50 font-mono text-sm">
        <span className="text-zinc-500">#{frame.index}</span>{' '}
        <span className="text-zinc-200">{frame.symbol ?? '???'}</span>
        {frame.source_loc && (
          <span className="text-zinc-500 ml-2">{frame.source_loc}</span>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-zinc-800 text-sm">
        {TABS.map(tab => {
          const active = tab === 'Params'
          const disabled = tab !== 'Params'
          return (
            <button
              key={tab}
              disabled={disabled}
              className={`px-4 py-2 transition-colors ${
                active
                  ? 'text-blue-300 border-b-2 border-blue-400 bg-zinc-800/30'
                  : disabled
                    ? 'text-zinc-700 cursor-not-allowed'
                    : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {tab}
            </button>
          )
        })}
      </div>

      {/* Params content */}
      <div className="flex-1 overflow-auto p-4">
        {params.length === 0 ? (
          <div className="text-zinc-600 text-sm">No parameters available for this frame</div>
        ) : (
          <>
            {!isCrashFrame && (
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
                {params.map((p, i) => (
                  <tr key={i} className="hover:bg-zinc-800/30">
                    <td className="py-1.5 pr-4 text-yellow-300">{p.name}</td>
                    <td className="py-1.5 pr-4 text-zinc-400">{p.type}</td>
                    <td className="py-1.5 pr-4 text-zinc-500">{p.location}</td>
                    <td className={`py-1.5 ${isCrashFrame ? 'text-zinc-200' : 'text-zinc-500'}`}>{formatValue(p.value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}
