import { useCallback, useRef, useState } from 'react'
import type { UploadOptions } from '../types'

interface Props {
  onUpload: (rsod: File | Blob, sym: File, extras?: File[], opts?: UploadOptions) => void
  uploading: boolean
  error?: string
}

export function UploadForm({ onUpload, uploading, error }: Props) {
  const [rsodFile, setRsodFile] = useState<File | null>(null)
  const [symFile, setSymFile] = useState<File | null>(null)
  const [extraFiles, setExtraFiles] = useState<File[]>([])
  const [pasteText, setPasteText] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [base, setBase] = useState('')
  const [tag, setTag] = useState('')
  const [commit, setCommit] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const dropRef = useRef<HTMLDivElement>(null)

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const files = Array.from(e.dataTransfer.files)
    for (const f of files) {
      const name = f.name.toLowerCase()
      if (name.endsWith('.map') || name.endsWith('.efi') || name.endsWith('.so') || name.endsWith('.debug') || name.endsWith('.pdb')) {
        if (!symFile) {
          setSymFile(f)
        } else {
          setExtraFiles(prev => [...prev, f])
        }
      } else {
        setRsodFile(f)
      }
    }
  }, [symFile])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const rsod = rsodFile ?? (pasteText ? new Blob([pasteText], { type: 'text/plain' }) : null)
    if (!rsod || !symFile) return
    const opts: UploadOptions = {}
    if (base) opts.base = base
    if (tag) opts.tag = tag
    if (commit) opts.commit = commit
    onUpload(rsod, symFile, extraFiles.length > 0 ? extraFiles : undefined, opts)
  }

  const hasRsod = rsodFile !== null || pasteText.length > 0
  const canSubmit = hasRsod && symFile !== null && !uploading

  return (
    <div className="flex items-center justify-center min-h-screen p-8">
      <form onSubmit={handleSubmit} className="w-full max-w-2xl space-y-6">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-zinc-100 tracking-tight">RSOD Debugger</h1>
          <p className="text-zinc-400 mt-2">Upload a UEFI crash dump and symbol file for interactive analysis</p>
        </div>

        {error && (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-4 text-red-200 text-sm">
            {error}
          </div>
        )}

        {/* Drop zone */}
        <div
          ref={dropRef}
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          role="region"
          aria-label="File drop zone"
          className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
            dragOver
              ? 'border-blue-400 bg-blue-900/20'
              : 'border-zinc-600 hover:border-zinc-500'
          }`}
        >
          <p className="text-zinc-300 text-lg mb-2">
            Drop RSOD log and symbol files here
          </p>
          <p className="text-zinc-500 text-sm">
            .txt/.log for RSOD capture, .map/.efi/.so/.debug/.pdb for symbols
          </p>
          {(rsodFile ?? symFile) && (
            <div className="mt-4 text-left space-y-1">
              {rsodFile && (
                <div className="text-sm text-zinc-300">
                  <span className="text-green-400">RSOD:</span> {rsodFile.name}
                  <button type="button" onClick={() => setRsodFile(null)} aria-label={`Remove ${rsodFile.name}`} className="ml-2 text-zinc-500 hover:text-zinc-300">&times;</button>
                </div>
              )}
              {symFile && (
                <div className="text-sm text-zinc-300">
                  <span className="text-blue-400">Symbols:</span> {symFile.name}
                  <button type="button" onClick={() => setSymFile(null)} aria-label={`Remove ${symFile.name}`} className="ml-2 text-zinc-500 hover:text-zinc-300">&times;</button>
                </div>
              )}
              {extraFiles.map(f => (
                <div key={`${f.name}-${f.size}-${f.lastModified}`} className="text-sm text-zinc-300">
                  <span className="text-purple-400">Extra:</span> {f.name}
                  <button type="button" onClick={() => setExtraFiles(prev => prev.filter(x => x !== f))} aria-label={`Remove ${f.name}`} className="ml-2 text-zinc-500 hover:text-zinc-300">&times;</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* File inputs */}
        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="text-sm text-zinc-400">RSOD log</span>
            <input
              type="file"
              accept=".txt,.log"
              onChange={e => { const f = e.target.files?.[0] ?? null; setRsodFile(f); if (f) setPasteText('') }}
              className="mt-1 block w-full text-sm text-zinc-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-zinc-700 file:text-zinc-200 hover:file:bg-zinc-600 file:cursor-pointer"
            />
          </label>
          <label className="block">
            <span className="text-sm text-zinc-400">Symbol file</span>
            <input
              type="file"
              accept=".map,.efi,.so,.debug,.elf,.pdb"
              onChange={e => setSymFile(e.target.files?.[0] ?? null)}
              className="mt-1 block w-full text-sm text-zinc-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-zinc-700 file:text-zinc-200 hover:file:bg-zinc-600 file:cursor-pointer"
            />
          </label>
        </div>

        {/* Paste area */}
        <div>
          <label className="block">
            <span className="text-sm text-zinc-400">Or paste RSOD text</span>
            <textarea
              value={pasteText}
              onChange={e => { setPasteText(e.target.value); if (e.target.value) setRsodFile(null) }}
              placeholder="Paste serial console output here..."
              rows={4}
              className="mt-1 block w-full rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-200 text-sm font-mono p-3 placeholder:text-zinc-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none resize-y"
            />
          </label>
        </div>

        {/* Advanced options */}
        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-sm text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
          >
            <span className={`transition-transform ${showAdvanced ? 'rotate-90' : ''}`}>&#9654;</span>
            Advanced options
          </button>
          {showAdvanced && (
            <div className="mt-3 grid grid-cols-3 gap-3">
              <label className="block">
                <span className="text-xs text-zinc-500">Base address (hex)</span>
                <input
                  type="text"
                  value={base}
                  onChange={e => setBase(e.target.value)}
                  placeholder="180000000"
                  className="mt-1 block w-full rounded bg-zinc-800 border border-zinc-700 text-zinc-200 text-sm font-mono px-2 py-1 focus:border-blue-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs text-zinc-500">Git tag</span>
                <input
                  type="text"
                  value={tag}
                  onChange={e => setTag(e.target.value)}
                  placeholder="v1.0.3"
                  className="mt-1 block w-full rounded bg-zinc-800 border border-zinc-700 text-zinc-200 text-sm font-mono px-2 py-1 focus:border-blue-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs text-zinc-500">Git commit</span>
                <input
                  type="text"
                  value={commit}
                  onChange={e => setCommit(e.target.value)}
                  placeholder="abc1234"
                  className="mt-1 block w-full rounded bg-zinc-800 border border-zinc-700 text-zinc-200 text-sm font-mono px-2 py-1 focus:border-blue-500 focus:outline-none"
                />
              </label>
            </div>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full py-3 rounded-lg font-medium text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed bg-red-700 hover:bg-red-600 text-white"
        >
          {uploading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="animate-spin inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full" />
              Analyzing...
            </span>
          ) : (
            'Analyze RSOD'
          )}
        </button>
      </form>
    </div>
  )
}
