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

  // Sessions persist across restarts (SQLite at ~/.rsod-debug/).
  // Page refresh / tab close used to DELETE the session via a
  // `beforeunload` handler — that defeats the whole point of the
  // persistent store, so it's gone now. Delete is an explicit user
  // action via the CrashBanner Delete button.

  // Load an existing session by ID. Used for:
  //  - permalink hydration on mount (via the hash route)
  //  - clicking a HistoryPanel row
  //  - after a dedup-hit /api/session response (importSession too)
  const loadSession = useCallback(async (sessionId: string) => {
    setState({ status: 'uploading' })
    try {
      sessionIdRef.current = sessionId
      const data = await api.getSession(sessionId)

      let frameDetail: FrameDetail | null = null
      if (data.frames.length > 0) {
        frameDetail = await api.getFrame(sessionId, 0)
      }

      setState({
        status: 'loaded',
        sessionId,
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

  // Auto-load session from URL hash on mount
  useEffect(() => {
    const hash = window.location.hash
    const match = hash.match(/^#session\/(.+)$/)
    if (match?.[1]) {
      loadSession(match[1])
    }
  }, [loadSession])

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

  const switchBackend = useCallback(async (backend: 'pyelftools' | 'gdb' | 'lldb') => {
    const sid = sessionIdRef.current
    if (!sid) return

    setState(prev => {
      if (prev.status !== 'loaded') return prev
      return { ...prev, frameLoading: true, frameError: null }
    })

    try {
      const result = await api.switchBackend(sid, backend)
      // Re-fetch current frame with new backend
      let frameDetail: FrameDetail | null = null
      let selectedFrame = 0
      setState(prev => {
        if (prev.status === 'loaded') selectedFrame = prev.selectedFrame
        return prev
      })
      frameDetail = await api.getFrame(sid, selectedFrame)

      setState(prev => {
        if (prev.status !== 'loaded') return prev
        return {
          ...prev,
          data: { ...prev.data, backend: result.backend },
          frameDetail,
          frameLoading: false,
          frameError: null,
        }
      })
    } catch (e) {
      setState(prev => {
        if (prev.status !== 'loaded') return prev
        return { ...prev, frameLoading: false, frameError: e instanceof Error ? e.message : String(e) }
      })
    }
  }, [])

  // Close the current view without touching persistent storage. The
  // session stays in SQLite so the user can reopen it from history
  // or via its permalink. Back to the upload screen.
  const closeView = useCallback(() => {
    sessionIdRef.current = null
    window.location.hash = ''
    setState({ status: 'idle' })
  }, [])

  // Permanently drop the current session: DELETE the row + files on
  // disk, then return to the upload screen. Bound to the Delete
  // button in CrashBanner; no other code path calls this.
  const deleteCurrent = useCallback(async () => {
    const sid = sessionIdRef.current
    if (sid) {
      try { await api.deleteSession(sid) } catch { /* already gone is fine */ }
    }
    sessionIdRef.current = null
    window.location.hash = ''
    setState({ status: 'idle' })
  }, [])

  return {
    state, upload, selectFrame, switchBackend,
    loadSession, closeView, deleteCurrent,
  }
}
