import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

interface Props {
  sessionId: string
}

export function LldbConsole({ sessionId }: Props) {
  const termRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    if (!termRef.current) return

    const term = new Terminal({
      theme: {
        background: '#18181b',
        foreground: '#d4d4d8',
        cursor: '#d4d4d8',
        selectionBackground: '#3f3f46',
      },
      fontFamily: 'monospace',
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(termRef.current)
    fit.fit()

    terminalRef.current = term
    fitRef.current = fit

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${location.host}/ws/lldb/${sessionId}`)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => {
      setConnected(false)
      term.write('\r\n\x1b[90m[LLDB session ended]\x1b[0m\r\n')
    }
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data))
      } else {
        term.write(ev.data)
      }
    }

    // Forward keystrokes to the server-side line editor.
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data)
      }
    })

    // Refit on container resize; we don't send rows/cols since LLDB
    // is in-process and doesn't care about terminal geometry.
    const observer = new ResizeObserver(() => {
      fit.fit()
    })
    observer.observe(termRef.current)

    return () => {
      observer.disconnect()
      ws.close()
      term.dispose()
      wsRef.current = null
      terminalRef.current = null
      fitRef.current = null
    }
  }, [sessionId])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-900 border-t border-zinc-700/50 text-xs">
        <span className="text-zinc-400 font-medium">LLDB</span>
        <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-zinc-600'}`} />
      </div>
      <div ref={termRef} className="flex-1 min-h-0 bg-[#18181b]" />
    </div>
  )
}
