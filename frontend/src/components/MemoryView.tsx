import { useEffect, useMemo, useRef, useState } from 'react'
import * as api from '../api'
import { HexAddress } from './HexAddress'

interface Props {
  sessionId: string
  address: number | null
  onNavigateMemory: (addr: number) => void
}

const BYTES_PER_ROW = 16
const DEFAULT_SIZE = 256

export function MemoryView({ sessionId, address, onNavigateMemory }: Props) {
  const [inputVal, setInputVal] = useState('')
  const [data, setData] = useState<(number | null)[] | null>(null)
  const [baseAddr, setBaseAddr] = useState<number>(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fetchId = useRef(0)

  // Sync input field when address changes externally
  useEffect(() => {
    if (address !== null) {
      setInputVal(`0x${address.toString(16).toUpperCase()}`)
    }
  }, [address])

  // Fetch memory when address changes
  useEffect(() => {
    if (address === null) return
    const id = ++fetchId.current
    setLoading(true)
    setError(null)
    api.getMemory(sessionId, address, DEFAULT_SIZE)
      .then(r => {
        if (id !== fetchId.current) return
        setBaseAddr(r.address)
        setData(r.bytes)
        setLoading(false)
      })
      .catch(e => {
        if (id !== fetchId.current) return
        setError(e instanceof Error ? e.message : String(e))
        setData(null)
        setLoading(false)
      })
  }, [address, sessionId])

  const submitAddr = () => {
    const cleaned = inputVal.trim().replace(/^0x/i, '')
    const val = parseInt(cleaned, 16)
    if (!isNaN(val)) onNavigateMemory(val)
  }

  const rows = useMemo(() => {
    if (!data) return []
    const result: { offset: number; bytes: (number | null)[] }[] = []
    for (let i = 0; i < data.length; i += BYTES_PER_ROW) {
      result.push({ offset: i, bytes: data.slice(i, i + BYTES_PER_ROW) })
    }
    return result
  }, [data])

  if (address === null) {
    return (
      <div>
        <AddressBar value={inputVal} onChange={setInputVal} onSubmit={submitAddr} />
        <div className="text-zinc-600 text-sm mt-4">Enter an address or click a hex value to view memory</div>
      </div>
    )
  }

  return (
    <div>
      <AddressBar value={inputVal} onChange={setInputVal} onSubmit={submitAddr} />

      {loading && (
        <div className="text-zinc-500 text-sm flex items-center gap-2 mt-3">
          <span className="animate-spin inline-block w-4 h-4 border-2 border-zinc-600 border-t-zinc-300 rounded-full" />
          Reading memory...
        </div>
      )}

      {error && (
        <div className="text-red-400 text-sm mt-3">Failed to read memory: {error}</div>
      )}

      {!loading && !error && data && (
        <div className="mt-3 font-mono text-xs">
          {/* Header */}
          <div className="flex text-zinc-600 mb-1">
            <span className="w-40 shrink-0">ADDRESS</span>
            <span className="flex-1">
              {Array.from({ length: BYTES_PER_ROW }, (_, i) =>
                i.toString(16).toUpperCase().padStart(2, '0')
              ).map((h, i) => (
                <span key={i} className={i === 8 ? 'ml-2' : ''}>
                  {h}{' '}
                </span>
              ))}
            </span>
            <span className="w-40 text-right">ASCII</span>
          </div>

          {/* Rows */}
          {rows.map(row => {
            const allNull = row.bytes.every(b => b === null)
            return (
              <div key={row.offset} className="flex py-px hover:bg-zinc-800/30">
                <span className="w-40 shrink-0 text-zinc-500">
                  <HexAddress value={baseAddr + row.offset} onNavigate={onNavigateMemory} className="text-zinc-500 hover:text-zinc-300" />
                </span>
                <span className="flex-1">
                  {row.bytes.map((b, i) => (
                    <span
                      key={i}
                      className={`${i === 8 ? 'ml-2' : ''}${b === null ? ' text-zinc-700' : ' text-zinc-300'}`}
                    >
                      {b !== null ? b.toString(16).toUpperCase().padStart(2, '0') : '\u00B7\u00B7'}{' '}
                    </span>
                  ))}
                </span>
                <span className={`w-40 text-right ${allNull ? 'text-zinc-700' : 'text-zinc-500'}`}>
                  {row.bytes.map((b) => {
                    if (b === null) return '\u00B7'
                    if (b >= 0x20 && b < 0x7F) return String.fromCharCode(b)
                    return '.'
                  }).join('')}
                </span>
              </div>
            )
          })}

          {data.every(b => b === null) && (
            <div className="text-zinc-600 text-sm mt-2 italic">
              No readable memory at this address range
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function AddressBar({ value, onChange, onSubmit }: {
  value: string
  onChange: (v: string) => void
  onSubmit: () => void
}) {
  return (
    <div className="flex gap-2 items-center">
      <label className="text-xs text-zinc-500 shrink-0">Address:</label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') onSubmit() }}
        placeholder="0xADDRESS"
        className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-sm font-mono text-zinc-200 w-48 focus:outline-none focus:border-blue-500"
        spellCheck={false}
      />
      <button
        onClick={onSubmit}
        className="px-3 py-1 text-xs bg-zinc-700 hover:bg-zinc-600 text-zinc-200 rounded transition-colors"
      >
        Go
      </button>
    </div>
  )
}
