import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../api'
import type { FrameDetail, SessionData, UploadOptions } from '../types'

type SessionState =
  | { status: 'idle' }
  | { status: 'uploading' }
  | { status: 'loaded'; sessionId: string; data: SessionData; selectedFrame: number; frameDetail: FrameDetail | null; frameLoading: boolean; frameError: string | null }
  | { status: 'error'; message: string }

export function useSession() {
  const [state, setState] = useState<SessionState>({ status: 'idle' })
  const sessionIdRef = useRef<string | null>(null)

  // Keep ref in sync
  useEffect(() => {
    sessionIdRef.current = state.status === 'loaded' ? state.sessionId : null
  }, [state])

  // Clean up session on page unload
  useEffect(() => {
    const cleanup = () => {
      if (sessionIdRef.current) {
        navigator.sendBeacon(`/api/session/${sessionIdRef.current}`)
      }
    }
    window.addEventListener('beforeunload', cleanup)
    return () => window.removeEventListener('beforeunload', cleanup)
  }, [])

  const upload = useCallback(async (
    rsodLog: File | Blob,
    symbolFile: File,
    extraSymbols?: File[],
    opts?: UploadOptions,
  ) => {
    setState({ status: 'uploading' })
    try {
      const created = await api.createSession(rsodLog, symbolFile, extraSymbols, opts)
      sessionIdRef.current = created.session_id
      const data = await api.getSession(created.session_id)

      let frameDetail: FrameDetail | null = null
      if (data.frames.length > 0) {
        frameDetail = await api.getFrame(created.session_id, 0)
      }

      setState({
        status: 'loaded',
        sessionId: created.session_id,
        data,
        selectedFrame: 0,
        frameDetail,
        frameLoading: false,
        frameError: null,
      })
    } catch (e) {
      sessionIdRef.current = null
      setState({ status: 'error', message: e instanceof Error ? e.message : String(e) })
    }
  }, [])

  const selectFrame = useCallback(async (index: number) => {
    const sid = sessionIdRef.current
    if (!sid) return

    setState(prev => {
      if (prev.status !== 'loaded') return prev
      return { ...prev, selectedFrame: index, frameLoading: true, frameError: null }
    })

    try {
      const detail = await api.getFrame(sid, index)
      setState(prev => {
        if (prev.status !== 'loaded' || prev.selectedFrame !== index) return prev
        return { ...prev, frameDetail: detail, frameLoading: false }
      })
    } catch (e) {
      setState(prev => {
        if (prev.status !== 'loaded' || prev.selectedFrame !== index) return prev
        return { ...prev, frameDetail: null, frameLoading: false, frameError: e instanceof Error ? e.message : String(e) }
      })
    }
  }, [])

  const reset = useCallback(async () => {
    const sid = sessionIdRef.current
    sessionIdRef.current = null
    if (sid) {
      api.deleteSession(sid).catch(() => {})
    }
    setState({ status: 'idle' })
  }, [])

  return { state, upload, selectFrame, reset }
}
