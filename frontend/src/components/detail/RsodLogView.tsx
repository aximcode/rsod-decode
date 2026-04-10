import type { ModuleInfo } from '../../types'

interface Props {
  rsodText?: string
  modules?: ModuleInfo[]
}

export function RsodLogView({ rsodText, modules }: Props) {
  return (
    <div className="font-mono text-xs">
      {modules && modules.length > 0 && (
        <div className="mb-4">
          <div className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Loaded Modules</div>
          <table className="w-full">
            <thead>
              <tr className="text-left text-zinc-600">
                <th className="pr-3 pb-1">#</th>
                <th className="pr-3 pb-1">Module</th>
                <th className="pr-3 pb-1">Base</th>
                <th className="pr-3 pb-1">Size</th>
                <th className="pb-1">Debug Path</th>
              </tr>
            </thead>
            <tbody>
              {modules.map(m => (
                <tr key={m.index} className="text-zinc-400">
                  <td className="pr-3 py-0.5 text-zinc-600">{m.index}</td>
                  <td className="pr-3 py-0.5 text-zinc-300">{m.name}</td>
                  <td className="pr-3 py-0.5 text-zinc-500">{m.base ? `0x${m.base.toString(16).toUpperCase()}` : ''}</td>
                  <td className="pr-3 py-0.5 text-zinc-600">{m.size ? `${(m.size / 1024).toFixed(0)}K` : ''}</td>
                  <td className="py-0.5 text-zinc-600 truncate max-w-xs" title={m.debug_path}>{m.debug_path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rsodText ? (
        <pre className="text-zinc-400 whitespace-pre-wrap break-all">{rsodText}</pre>
      ) : (
        <div className="text-zinc-600">No RSOD text available</div>
      )}
    </div>
  )
}
