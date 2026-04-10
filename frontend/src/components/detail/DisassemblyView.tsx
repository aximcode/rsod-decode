import type { Instruction } from '../../types'

interface Props {
  instructions: Instruction[] | null
  loading: boolean
}

export function DisassemblyView({ instructions, loading }: Props) {
  if (loading) {
    return (
      <div className="text-zinc-500 text-sm flex items-center gap-2">
        <span className="animate-spin inline-block w-4 h-4 border-2 border-zinc-600 border-t-zinc-300 rounded-full" />
        Loading disassembly...
      </div>
    )
  }
  if (!instructions || instructions.length === 0) {
    return <div className="text-zinc-600 text-sm">No disassembly available for this frame</div>
  }

  let prevSource = ''
  return (
    <div className="font-mono text-sm space-y-0">
      {instructions.map(insn => {
        const showSource = insn.source_line && insn.source_line !== prevSource
        if (insn.source_line) prevSource = insn.source_line
        return (
          <div key={insn.address}>
            {showSource && (
              <div className="text-zinc-500 mt-3 mb-0.5 text-xs">{insn.source_line}</div>
            )}
            <div className={`flex gap-3 py-px px-2 rounded ${insn.is_target ? 'bg-red-950/60 text-red-200' : 'text-zinc-300'}`}>
              <span className={`w-4 shrink-0 ${insn.is_target ? 'text-red-400' : ''}`}>{insn.is_target ? '\u25B6' : ''}</span>
              <span className="text-zinc-500 w-16 shrink-0 text-right">{insn.address.toString(16)}:</span>
              <span className={`w-16 shrink-0 ${insn.is_target ? 'text-red-300 font-bold' : 'text-blue-300'}`}>{insn.mnemonic}</span>
              <span className="text-zinc-300">{insn.op_str}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
