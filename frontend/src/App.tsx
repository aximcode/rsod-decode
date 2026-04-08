import { useSession } from './hooks/useSession'
import { UploadForm } from './components/UploadForm'
import { CrashBanner } from './components/CrashBanner'
import { BacktracePanel } from './components/BacktracePanel'
import { DetailPanel } from './components/DetailPanel'

export function App() {
  const { state, upload, selectFrame, reset } = useSession()

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
        <DetailPanel
          frame={state.frameDetail}
          loading={state.frameLoading}
          error={state.frameError}
        />
      </div>
    </div>
  )
}
