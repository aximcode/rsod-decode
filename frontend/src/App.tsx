import { useCallback, useRef, useState } from 'react'
import { useSession } from './hooks/useSession'
import { UploadForm } from './components/UploadForm'
import { CrashBanner } from './components/CrashBanner'
import { BacktracePanel } from './components/BacktracePanel'
import { DetailPanel } from './components/detail'
import { RegisterPanel } from './components/RegisterPanel'
import { LldbConsole } from './components/LldbConsole'
import { GdbPanel } from './components/GdbPanel'

type ConsoleTab = 'lldb' | 'gdb'

export function App() {
  const {
    state, upload, selectFrame, switchBackend,
    loadSession, closeView, deleteCurrent,
  } = useSession()
  const [consoleOpen, setConsoleOpen] = useState(false)
  const [consoleHeight, setConsoleHeight] = useState(256)
  const [consoleTab, setConsoleTab] = useState<ConsoleTab>('lldb')
  const dragging = useRef(false)
  const [memoryNav, setMemoryNav] = useState<{ addr: number; id: number } | null>(null)
  const navIdRef = useRef(0)

  const navigateToMemory = useCallback((addr: number) => {
    setMemoryNav({ addr, id: ++navIdRef.current })
  }, [])

  const onDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    dragging.current = true
    const startY = e.clientY
    const startH = consoleHeight
    const onMove = (ev: MouseEvent) => {
      if (!dragging.current) return
      setConsoleHeight(Math.max(100, Math.min(600, startH + startY - ev.clientY)))
    }
    const onUp = () => {
      dragging.current = false
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [consoleHeight])

  if (state.status !== 'loaded') {
    return (
      <UploadForm
        onUpload={upload}
        onOpenSession={loadSession}
        uploading={state.status === 'uploading'}
        error={state.status === 'error' ? state.message : undefined}
      />
    )
  }

  return (
    <div className="flex flex-col h-screen">
      <CrashBanner
        sessionId={state.sessionId}
        crash={state.data.crash_summary}
        sessionName={state.data.name}
        onCloseView={closeView}
        onDelete={deleteCurrent}
        backend={state.data.backend}
        gdbAvailable={state.data.gdb_available}
        lldbAvailable={state.data.lldb_available}
        onSwitchBackend={switchBackend}
        backendSwitching={state.frameLoading}
        lbr={state.data.lbr}
      />
      <div className="flex flex-1 min-h-0 overflow-hidden">
        <BacktracePanel
          frames={state.data.frames}
          callVerified={state.data.call_verified}
          selectedIndex={state.selectedFrame}
          onSelect={selectFrame}
        />
        <div className="flex flex-col flex-1 min-h-0 overflow-hidden">
          <div className="flex-1 min-h-0 overflow-hidden">
            <DetailPanel
              sessionId={state.sessionId}
              frame={state.frameDetail}
              loading={state.frameLoading}
              error={state.frameError}
              isCrashFrame={state.selectedFrame === 0}
              memoryNav={memoryNav}
              onNavigateMemory={navigateToMemory}
              backend={state.data.backend}
              rsodText={state.data.rsod_text}
              modules={state.data.modules}
            />
          </div>
          <div
            className={`flex items-center gap-3 bg-zinc-900 border-t border-zinc-700/50 px-3 ${consoleOpen ? 'cursor-ns-resize' : ''}`}
            onMouseDown={consoleOpen ? onDragStart : undefined}
          >
            <button
              onClick={(e) => { e.stopPropagation(); setConsoleOpen(!consoleOpen) }}
              className="text-xs text-zinc-400 hover:text-zinc-200 py-1"
            >
              {consoleOpen ? '\u25BE' : '\u25B4'} Terminal
            </button>
            {consoleOpen && (
              <div className="flex items-center gap-1 text-xs">
                {(['lldb', 'gdb'] as ConsoleTab[]).map(tab => (
                  <button
                    key={tab}
                    onClick={(e) => { e.stopPropagation(); setConsoleTab(tab) }}
                    className={`px-2 py-0.5 rounded border transition-colors ${
                      consoleTab === tab
                        ? 'border-zinc-400 text-zinc-200 bg-zinc-800'
                        : 'border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-500'
                    }`}
                  >
                    {tab.toUpperCase()}
                  </button>
                ))}
              </div>
            )}
          </div>
          {consoleOpen && (
            <div className="overflow-hidden" style={{ height: consoleHeight }}>
              {consoleTab === 'lldb' ? (
                <LldbConsole sessionId={state.sessionId} />
              ) : (
                <GdbPanel sessionId={state.sessionId} selectedFrame={state.selectedFrame} />
              )}
            </div>
          )}
        </div>
        <RegisterPanel
          registers={state.data.registers}
          vRegisters={state.data.v_registers}
          format={state.data.format}
          onNavigateMemory={navigateToMemory}
          frameRegisters={state.frameDetail?.frame_registers}
        />
      </div>
    </div>
  )
}
