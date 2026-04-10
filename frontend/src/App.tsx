import { useCallback, useRef, useState } from 'react'
import { useSession } from './hooks/useSession'
import { UploadForm } from './components/UploadForm'
import { CrashBanner } from './components/CrashBanner'
import { BacktracePanel } from './components/BacktracePanel'
import { DetailPanel } from './components/detail'
import { RegisterPanel } from './components/RegisterPanel'
import { GdbPanel } from './components/GdbPanel'

export function App() {
  const { state, upload, selectFrame, reset, switchBackend } = useSession()
  const [gdbOpen, setGdbOpen] = useState(false)
  const [gdbHeight, setGdbHeight] = useState(256)
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
    const startH = gdbHeight
    const onMove = (ev: MouseEvent) => {
      if (!dragging.current) return
      setGdbHeight(Math.max(100, Math.min(600, startH + startY - ev.clientY)))
    }
    const onUp = () => {
      dragging.current = false
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [gdbHeight])

  if (state.status !== 'loaded') {
    return (
      <UploadForm
        onUpload={upload}
        uploading={state.status === 'uploading'}
        error={state.status === 'error' ? state.message : undefined}
      />
    )
  }

  return (
    <div className="flex flex-col h-screen">
      <CrashBanner
        crash={state.data.crash_summary}
        onNewAnalysis={reset}
        backend={state.data.backend}
        gdbAvailable={state.data.gdb_available}
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
            className={`flex items-center bg-zinc-900 border-t border-zinc-700/50 px-3 ${gdbOpen ? 'cursor-ns-resize' : ''}`}
            onMouseDown={gdbOpen ? onDragStart : undefined}
          >
            <button
              onClick={() => setGdbOpen(!gdbOpen)}
              className="text-xs text-zinc-400 hover:text-zinc-200 py-1"
            >
              {gdbOpen ? '\u25BE' : '\u25B4'} GDB Terminal
            </button>
          </div>
          {gdbOpen && (
            <div className="overflow-hidden" style={{ height: gdbHeight }}>
              <GdbPanel sessionId={state.sessionId} selectedFrame={state.selectedFrame} />
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
