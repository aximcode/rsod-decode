import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

interface Props {
  sessionId: string
  selectedFrame: number
}

export function GdbPanel({ sessionId, selectedFrame }: Props) {
  const termRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const [connected, setConnected] = useState(false)
  const prevFrame = useRef(selectedFrame)

  // Initialize terminal + WebSocket
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

    // Connect WebSocket
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${location.host}/ws/gdb/${sessionId}`)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => {
      setConnected(false)
      term.write('\r\n\x1b[90m[GDB session ended]\x1b[0m\r\n')
    }
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data))
      } else {
        term.write(ev.data)
      }
    }

    // Terminal input → WebSocket
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data)
      }
    })

    // Handle resize
    const observer = new ResizeObserver(() => {
      fit.fit()
      if (ws.readyState === WebSocket.OPEN) {
        const msg = JSON.stringify({
          type: 'resize',
          rows: term.rows,
          cols: term.cols,
        })
        const ctrl = new Uint8Array(1 + msg.length)
        ctrl[0] = 0x01
        ctrl.set(new TextEncoder().encode(msg), 1)
        ws.send(ctrl)
      }
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

  // Frame sync: send frame_select when selectedFrame changes
  useEffect(() => {
    if (prevFrame.current === selectedFrame) return
    prevFrame.current = selectedFrame
    const ws = wsRef.current
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    const msg = JSON.stringify({ type: 'frame_select', index: selectedFrame })
    const ctrl = new Uint8Array(1 + msg.length)
    ctrl[0] = 0x01
    ctrl.set(new TextEncoder().encode(msg), 1)
    ws.send(ctrl)
  }, [selectedFrame])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-900 border-t border-zinc-700/50 text-xs">
        <span className="text-zinc-400 font-medium">GDB</span>
        <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-zinc-600'}`} />
      </div>
      <div ref={termRef} className="flex-1 min-h-0 bg-[#18181b]" />
    </div>
  )
}
