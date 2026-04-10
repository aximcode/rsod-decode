import { useEffect, useRef, useState } from 'react'
import * as api from '../api'
import type { FrameDetail, Instruction, SourceLine, VarInfo } from '../types'

interface Props {
  sessionId: string
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

function filterVars(vars: VarInfo[]): VarInfo[] {
  return vars.filter(v => v.name !== '???')
}

type TabId = 'Params' | 'Locals' | 'Disassembly' | 'Source'
const TABS: TabId[] = ['Params', 'Locals', 'Disassembly', 'Source']

export function DetailPanel({ sessionId, frame, loading, error, isCrashFrame }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>('Params')
  const [disasm, setDisasm] = useState<Instruction[] | null>(null)
  const [disasmLoading, setDisasmLoading] = useState(false)
  const [source, setSource] = useState<{ file: string; target_line: number; lines: SourceLine[] } | null>(null)
  const [sourceLoading, setSourceLoading] = useState(false)
  const prevFrameIndex = useRef<number | null>(null)

  // Reset tab data when frame changes
  useEffect(() => {
    if (frame && frame.index !== prevFrameIndex.current) {
      prevFrameIndex.current = frame.index
      setDisasm(null)
      setSource(null)
    }
  }, [frame])

  // Fetch disasm when tab selected
  useEffect(() => {
    if (activeTab !== 'Disassembly' || !frame || disasm !== null || disasmLoading) return
    setDisasmLoading(true)
    api.getDisasm(sessionId, frame.index).then(r => {
      setDisasm(r.instructions)
      setDisasmLoading(false)
    }).catch(() => {
      setDisasm([])
      setDisasmLoading(false)
    })
  }, [activeTab, frame, sessionId, disasm, disasmLoading])

  // Fetch source when tab selected
  useEffect(() => {
    if (activeTab !== 'Source' || !frame || source !== null || sourceLoading) return
    setSourceLoading(true)
    api.getSource(sessionId, frame.index).then(r => {
      setSource(r)
      setSourceLoading(false)
    }).catch(() => {
      setSource({ file: '', target_line: 0, lines: [] })
      setSourceLoading(false)
    })
  }, [activeTab, frame, sessionId, source, sourceLoading])

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
          const active = tab === activeTab
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 transition-colors ${
                active
                  ? 'text-blue-300 border-b-2 border-blue-400 bg-zinc-800/30'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {tab}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto p-4">
        {activeTab === 'Params' && <VarsTable vars={filterVars(frame.params)} isCrashFrame={isCrashFrame} label="parameters" />}
        {activeTab === 'Locals' && <VarsTable vars={filterVars(frame.locals)} isCrashFrame={isCrashFrame} label="local variables" />}
        {activeTab === 'Disassembly' && <DisassemblyView instructions={disasm} loading={disasmLoading} />}
        {activeTab === 'Source' && <SourceView source={source} loading={sourceLoading} />}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared variable table (Params + Locals)
// ---------------------------------------------------------------------------

function VarsTable({ vars, isCrashFrame, label }: { vars: VarInfo[]; isCrashFrame: boolean; label: string }) {
  if (vars.length === 0) {
    return <div className="text-zinc-600 text-sm">No {label} available for this frame</div>
  }
  return (
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
          {vars.map((v, i) => (
            <tr key={i} className="hover:bg-zinc-800/30">
              <td className="py-1.5 pr-4 text-yellow-300">{v.name}</td>
              <td className="py-1.5 pr-4 text-zinc-400">{v.type}</td>
              <td className="py-1.5 pr-4 text-zinc-500">{v.location}</td>
              <td className={`py-1.5 ${v.approximate ? 'text-zinc-500 italic' : 'text-zinc-200'}`}>
                {v.approximate && v.value !== null ? '~ ' : ''}{formatValue(v.value)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

// ---------------------------------------------------------------------------
// Disassembly view
// ---------------------------------------------------------------------------

function DisassemblyView({ instructions, loading }: { instructions: Instruction[] | null; loading: boolean }) {
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

// ---------------------------------------------------------------------------
// Source view
// ---------------------------------------------------------------------------

function SourceView({ source, loading }: { source: { file: string; target_line: number; lines: SourceLine[] } | null; loading: boolean }) {
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
