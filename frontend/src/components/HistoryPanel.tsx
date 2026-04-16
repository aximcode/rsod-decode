import { useCallback, useEffect, useState } from 'react'
import * as api from '../api'
import type { HistoryEntry } from '../types'

interface Props {
  onOpen: (sessionId: string) => void
  refreshKey?: number
}

function formatTimestamp(iso: string): { relative: string; full: string } {
  const date = new Date(iso)
  const full = date.toLocaleString()
  const diffMs = Date.now() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return { relative: 'just now', full }
  if (diffSec < 3600) return { relative: `${Math.floor(diffSec / 60)}m ago`, full }
  if (diffSec < 86400) return { relative: `${Math.floor(diffSec / 3600)}h ago`, full }
  if (diffSec < 604800) return { relative: `${Math.floor(diffSec / 86400)}d ago`, full }
  return { relative: date.toLocaleDateString(), full }
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  // Revoke on next tick so the browser has a chance to start the
  // download before the URL dies.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function HistoryPanel({ onOpen, refreshKey }: Props) {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const reload = useCallback(async () => {
    setError(null)
    try {
      const { sessions } = await api.getHistory()
      setEntries(sessions)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => { void reload() }, [reload, refreshKey])

  const handleExport = useCallback(async (id: string) => {
    setBusy(id)
    try {
      const { blob, filename } = await api.exportSession(id)
      triggerDownload(blob, filename)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }, [])

  const handleDelete = useCallback(async (id: string) => {
    if (!window.confirm(`Delete session ${id.slice(0, 8)}? This removes the persisted files.`)) return
    setBusy(id)
    try {
      await api.deleteSession(id)
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }, [reload])

  if (error) {
    return (
      <div className="bg-red-900/30 border border-red-800 rounded-lg p-3 text-red-200 text-sm">
        Failed to load history: {error}
      </div>
    )
  }
  if (entries === null) {
    return <div className="text-zinc-500 text-sm">Loading history…</div>
  }
  if (entries.length === 0) {
    return (
      <div className="text-zinc-500 text-sm">
        No saved sessions yet. Upload an RSOD above to start.
      </div>
    )
  }

  return (
    <div className="border border-zinc-700 rounded-lg overflow-hidden">
      <div className="bg-zinc-800/50 px-3 py-2 border-b border-zinc-700 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-zinc-400">
          Recent sessions ({entries.length})
        </span>
        <button
          type="button"
          onClick={reload}
          className="text-xs text-zinc-500 hover:text-zinc-300"
        >
          refresh
        </button>
      </div>
      <ul className="divide-y divide-zinc-800">
        {entries.map(entry => {
          const ts = formatTimestamp(entry.created_at)
          const rowBusy = busy === entry.id
          const shortId = entry.id.slice(0, 8)
          return (
            <li
              key={entry.id}
              className={`px-3 py-2 text-sm hover:bg-zinc-800/60 transition-colors ${
                rowBusy ? 'opacity-50' : ''
              }`}
            >
              <div className="flex items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => onOpen(entry.id)}
                  className="flex-1 text-left min-w-0"
                  title={`Open ${entry.id}`}
                >
                  <div className="flex items-baseline gap-2 min-w-0">
                    <span className="font-mono text-zinc-300 truncate">
                      {entry.name || entry.image_name || '(unnamed)'}
                    </span>
                    {entry.name && (
                      <span className="text-xs text-zinc-500 truncate">
                        {entry.image_name}
                      </span>
                    )}
                    <span
                      className="font-mono text-xs text-zinc-600"
                      title={entry.id}
                    >
                      {shortId}
                    </span>
                    {entry.imported_from && (
                      <span
                        className="text-xs text-purple-400"
                        title={`imported from ${entry.imported_from}`}
                      >
                        imported
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-zinc-500 mt-0.5 truncate">
                    {entry.exception_desc || '(no exception)'}
                    {entry.crash_symbol && (
                      <>
                        {' · '}
                        <span className="text-zinc-400">{entry.crash_symbol}</span>
                      </>
                    )}
                    {' · '}
                    {entry.frame_count} frame{entry.frame_count === 1 ? '' : 's'}
                    {' · '}
                    <span title={ts.full}>{ts.relative}</span>
                  </div>
                </button>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    disabled={rowBusy}
                    onClick={() => handleExport(entry.id)}
                    className="text-xs text-zinc-500 hover:text-zinc-200 border border-zinc-700 rounded px-2 py-0.5 hover:border-zinc-500 transition-colors disabled:opacity-40"
                    title="Export as .rsod.zip bundle"
                  >
                    export
                  </button>
                  <button
                    type="button"
                    disabled={rowBusy}
                    onClick={() => handleDelete(entry.id)}
                    className="text-xs text-red-500 hover:text-red-300 border border-red-900 rounded px-2 py-0.5 hover:border-red-600 transition-colors disabled:opacity-40"
                    title="Delete this session permanently"
                  >
                    delete
                  </button>
                </div>
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
