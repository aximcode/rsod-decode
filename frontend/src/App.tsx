import { useCallback, useRef, useState } from 'react'
import { useSession } from './hooks/useSession'
import { UploadForm } from './components/UploadForm'
import { CrashBanner } from './components/CrashBanner'
import { BacktracePanel } from './components/BacktracePanel'
import { DetailPanel } from './components/DetailPanel'
import { RegisterPanel } from './components/RegisterPanel'
import { GdbPanel } from './components/GdbPanel'

export function App() {
  const { state, upload, selectFrame, reset } = useSession()
  const [gdbOpen, setGdbOpen] = useState(false)
  const [gdbHeight, setGdbHeight] = useState(256)
  const dragging = useRef(false)

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
      <CrashBanner crash={state.data.crash_summary} onNewAnalysis={reset} />
      <div className="flex flex-1 overflow-hidden">
        <BacktracePanel
          frames={state.data.frames}
          callVerified={state.data.call_verified}
          selectedIndex={state.selectedFrame}
          onSelect={selectFrame}
        />
        <div className="flex flex-col flex-1 overflow-hidden">
          <div className={`flex-1 overflow-hidden ${gdbOpen ? '' : 'flex-1'}`}>
            <DetailPanel
              sessionId={state.sessionId}
              frame={state.frameDetail}
              loading={state.frameLoading}
              error={state.frameError}
              isCrashFrame={state.selectedFrame === 0}
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
          format={state.data.format}
        />
      </div>
    </div>
  )
}
