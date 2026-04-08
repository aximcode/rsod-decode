interface Props {
  registers: Record<string, string>
  format: string
}

const SPECIAL_REGS = new Set(['PC', 'ESR', 'FAR', 'SP', 'FP', 'LR', 'ELR', 'SPSR', 'RIP', 'RSP', 'RBP'])

function sortRegisters(regs: Record<string, string>, format: string): [string, string][] {
  const entries = Object.entries(regs)

  if (format.includes('arm64')) {
    // X0-X28 first (numerically sorted), then FP/LR/SP/PC/ESR/FAR/etc.
    const numbered: [string, string][] = []
    const special: [string, string][] = []
    for (const [k, v] of entries) {
      const m = k.match(/^X(\d+)$/)
      if (m) {
        numbered.push([k, v])
      } else {
        special.push([k, v])
      }
    }
    numbered.sort((a, b) => {
      const na = parseInt(a[0].slice(1))
      const nb = parseInt(b[0].slice(1))
      return na - nb
    })
    const specialOrder = ['FP', 'LR', 'SP', 'PC', 'ELR', 'SPSR', 'ESR', 'FAR', 'FPSR']
    special.sort((a, b) => {
      const ia = specialOrder.indexOf(a[0])
      const ib = specialOrder.indexOf(b[0])
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
    })
    return [...numbered, ...special]
  }

  // x86: sort alphabetically, special first
  const special: [string, string][] = []
  const general: [string, string][] = []
  for (const [k, v] of entries) {
    if (SPECIAL_REGS.has(k)) {
      special.push([k, v])
    } else {
      general.push([k, v])
    }
  }
  general.sort((a, b) => a[0].localeCompare(b[0]))
  return [...general, ...special]
}

export function RegisterPanel({ registers, format }: Props) {
  const sorted = sortRegisters(registers, format)
  if (sorted.length === 0) return null

  return (
    <div className="w-56 shrink-0 border-l border-zinc-800 overflow-y-auto bg-zinc-900">
      <div className="px-3 py-2 border-b border-zinc-800 text-xs text-zinc-500 font-medium uppercase tracking-wider">
        Registers
      </div>
      <div className="px-3 py-1 font-mono text-xs">
        {sorted.map(([name, value]) => {
          const isSpecial = SPECIAL_REGS.has(name)
          return (
            <div
              key={name}
              className={`flex justify-between py-0.5 ${isSpecial ? 'text-yellow-300' : 'text-zinc-300'}`}
            >
              <span className={`w-10 shrink-0 ${isSpecial ? 'text-yellow-400' : 'text-zinc-500'}`}>{name}</span>
              <span className="text-right">{value}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
