import { useEffect, useRef, useState } from 'react'
import * as api from '../api'
import { HexAddress } from './HexAddress'

interface Props {
  sessionId: string
  frameIndex: number
  backend: string
  onNavigateMemory: (addr: number) => void
}

interface EvalEntry {
  expr: string
  value?: string
  type?: string
  error?: string
  loading?: boolean
}

const MAX_HISTORY = 20

function isHexAddr(s: string): number | null {
  const m = s.match(/^0x([0-9a-fA-F]+)/)
  if (!m?.[1]) return null
  const v = parseInt(m[1], 16)
  return v >= 0x10000 ? v : null
}

export function ExpressionEval({ sessionId, frameIndex, backend, onNavigateMemory }: Props) {
  const [inputVal, setInputVal] = useState('')
  const [history, setHistory] = useState<EvalEntry[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const prevFrame = useRef(frameIndex)

  // Re-evaluate history when frame changes
  useEffect(() => {
    if (frameIndex === prevFrame.current) return
    prevFrame.current = frameIndex
    if (history.length === 0 || (backend !== 'gdb' && backend !== 'lldb')) return

    const exprs = history.map(h => h.expr)
    setHistory(exprs.map(expr => ({ expr, loading: true })))

    Promise.all(
      exprs.map(expr =>
        api.evalExpression(sessionId, frameIndex, expr).catch(e => ({
          error: e instanceof Error ? e.message : String(e),
        }))
      )
    ).then(results => {
      setHistory(exprs.map((expr, i) => ({
        expr,
        ...results[i],
        loading: false,
      })))
    })
  }, [frameIndex, sessionId, backend, history.length])

  const submit = () => {
    const expr = inputVal.trim()
    if (!expr) return
    setInputVal('')

    // Remove duplicate if already in history
    const filtered = history.filter(h => h.expr !== expr)
    const entry: EvalEntry = { expr, loading: true }
    const newHistory = [entry, ...filtered].slice(0, MAX_HISTORY)
    setHistory(newHistory)

    api.evalExpression(sessionId, frameIndex, expr)
      .then(result => {
        setHistory(prev =>
          prev.map(h => h.expr === expr && h.loading ? { expr, ...result } : h)
        )
      })
      .catch(e => {
        setHistory(prev =>
          prev.map(h => h.expr === expr && h.loading
            ? { expr, error: e instanceof Error ? e.message : String(e) }
            : h)
        )
      })
  }

  if (backend !== 'gdb' && backend !== 'lldb') {
    return (
      <div className="text-xs text-zinc-600 italic px-1">
        Expression evaluation requires the LLDB backend
      </div>
    )
  }

  return (
    <div className="text-xs font-mono">
      <div className="flex gap-1.5 items-center">
        <span className="text-zinc-500 shrink-0">Eval:</span>
        <input
          ref={inputRef}
          value={inputVal}
          onChange={e => setInputVal(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') submit() }}
          placeholder="ctx->config->origin.x"
          className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 text-zinc-200 focus:outline-none focus:border-blue-500"
          spellCheck={false}
        />
        <button
          onClick={submit}
          className="px-2 py-0.5 bg-zinc-700 hover:bg-zinc-600 text-zinc-300 rounded transition-colors shrink-0"
        >
          Eval
        </button>
      </div>

      {history.length > 0 && (
        <div className="mt-1.5 space-y-0.5 max-h-32 overflow-y-auto">
          {history.map((entry, i) => (
            <div key={`${entry.expr}-${i}`} className="flex gap-2 px-1 py-0.5 rounded hover:bg-zinc-800/50">
              <button
                onClick={() => { setInputVal(entry.expr); inputRef.current?.focus() }}
                className="text-blue-400 hover:text-blue-300 shrink-0 text-left"
                title="Edit expression"
              >
                {entry.expr}
              </button>
              <span className="text-zinc-600">=</span>
              {entry.loading ? (
                <span className="text-zinc-500 animate-pulse">...</span>
              ) : entry.error ? (
                <span className="text-red-400 truncate" title={entry.error}>{entry.error}</span>
              ) : (
                <span className="text-zinc-300 truncate">
                  {entry.type && <span className="text-zinc-600">({entry.type}) </span>}
                  <ResultValue value={entry.value ?? ''} onNavigateMemory={onNavigateMemory} />
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ResultValue({ value, onNavigateMemory }: { value: string; onNavigateMemory: (addr: number) => void }) {
  const addr = isHexAddr(value)
  if (addr !== null) {
    return (
      <>
        <HexAddress value={addr} onNavigate={onNavigateMemory} />
        {value.length > value.indexOf(' ') && value.includes(' ') && (
          <span className="text-green-400 ml-1">{value.slice(value.indexOf(' '))}</span>
        )}
      </>
    )
  }
  return <>{value}</>
}
