import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../../api'
import type { FrameDetail, Instruction, ModuleInfo, SourceLine, VarInfo } from '../../types'
import { useTabData } from '../../hooks/useTabData'
import { ExpressionEval } from '../ExpressionEval'
import { MemoryView } from '../MemoryView'
import { DisassemblyView } from './DisassemblyView'
import { RsodLogView } from './RsodLogView'
import { SourceView } from './SourceView'
import { VarsTable } from './VarsTable'

interface Props {
  sessionId: string
  frame: FrameDetail | null
  loading: boolean
  error?: string | null
  isCrashFrame: boolean
  memoryNav: { addr: number; id: number } | null
  onNavigateMemory: (addr: number) => void
  backend: string
  rsodText?: string
  modules?: ModuleInfo[]
}

function filterVars(vars: VarInfo[]): VarInfo[] {
  return vars.filter(v => v.name !== '???')
}

type TabId = 'Params' | 'Locals' | 'Globals' | 'Disassembly' | 'Source' | 'Memory' | 'RSOD Log'
const TABS: TabId[] = ['Params', 'Locals', 'Globals', 'Disassembly', 'Source', 'Memory', 'RSOD Log']

export function DetailPanel({ sessionId, frame, loading, error, isCrashFrame, memoryNav, onNavigateMemory, backend, rsodText, modules }: Props) {
  const [evalOpen, setEvalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<TabId>('Params')
  const [memoryAddr, setMemoryAddr] = useState<number | null>(null)
  const prevNavId = useRef(0)

  const frameIndex = frame?.index ?? -1

  const disasm = useTabData<Instruction[]>(
    activeTab === 'Disassembly' && frame !== null,
    [sessionId, frameIndex, backend],
    () => api.getDisasm(sessionId, frameIndex).then(r => r.instructions),
    [],
  )

  const source = useTabData<{ file: string; target_line: number; lines: SourceLine[] }>(
    activeTab === 'Source' && frame !== null,
    [sessionId, frameIndex, backend],
    () => api.getSource(sessionId, frameIndex),
    { file: '', target_line: 0, lines: [] },
  )

  // Handle external memory navigation requests
  useEffect(() => {
    if (memoryNav && memoryNav.id !== prevNavId.current) {
      prevNavId.current = memoryNav.id
      setMemoryAddr(memoryNav.addr)
      setActiveTab('Memory')
    }
  }, [memoryNav])

  const handleNavigateMemory = useCallback((addr: number) => {
    setMemoryAddr(addr)
    setActiveTab('Memory')
    onNavigateMemory(addr)
  }, [onNavigateMemory])

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
    <div className="h-full flex flex-col overflow-hidden">
      {/* Frame header */}
      <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-900/50 font-mono text-sm">
        <span className="text-zinc-500">#{frame.index}</span>{' '}
        <span className="text-zinc-200">{frame.symbol ?? '???'}</span>
        {frame.source_loc && (
          <span className="text-zinc-500 ml-2">{frame.source_loc}</span>
        )}
      </div>

      {/* Expression evaluator */}
      <div className="border-b border-zinc-800">
        <button
          onClick={() => setEvalOpen(!evalOpen)}
          className="w-full px-4 py-1 text-xs text-zinc-500 hover:text-zinc-300 text-left flex items-center gap-1"
        >
          <span>{evalOpen ? '\u25BE' : '\u25B8'}</span>
          Expression
        </button>
        {evalOpen && (
          <div className="px-4 pb-2">
            <ExpressionEval
              sessionId={sessionId}
              frameIndex={frame.index}
              backend={backend}
              onNavigateMemory={handleNavigateMemory}
            />
          </div>
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
      <div className="flex-1 min-h-0 overflow-auto p-4">
        {activeTab === 'Params' && <VarsTable vars={filterVars(frame.params)} isCrashFrame={isCrashFrame} label="parameters" sessionId={sessionId} frameIndex={frame.index} onNavigateMemory={handleNavigateMemory} />}
        {activeTab === 'Locals' && <VarsTable vars={filterVars(frame.locals)} isCrashFrame={isCrashFrame} label="local variables" sessionId={sessionId} frameIndex={frame.index} onNavigateMemory={handleNavigateMemory} />}
        {activeTab === 'Globals' && <VarsTable vars={filterVars(frame.globals)} isCrashFrame={isCrashFrame} label="global variables" sessionId={sessionId} frameIndex={frame.index} onNavigateMemory={handleNavigateMemory} note="Runtime values not available — expand structs to see initial values from the ELF image" />}
        {activeTab === 'Disassembly' && <DisassemblyView instructions={disasm.data} loading={disasm.loading} />}
        {activeTab === 'Source' && <SourceView source={source.data} loading={source.loading} />}
        {activeTab === 'Memory' && <MemoryView sessionId={sessionId} address={memoryAddr} onNavigateMemory={handleNavigateMemory} />}
        {activeTab === 'RSOD Log' && <RsodLogView rsodText={rsodText} modules={modules} />}
      </div>
    </div>
  )
}
