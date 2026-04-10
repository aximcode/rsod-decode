import type { ReactNode } from 'react'

interface Props {
  value: number
  onNavigate: (addr: number) => void
  className?: string
}

export function HexAddress({ value, onNavigate, className }: Props) {
  const hex = `0x${value.toString(16).toUpperCase()}`
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onNavigate(value) }}
      className={`text-blue-300 hover:text-blue-200 hover:underline cursor-pointer ${className ?? ''}`}
      title={`View memory at ${hex}`}
    >
      {hex}
    </button>
  )
}

export function formatValueWithHex(
  value: number | null,
  onNavigate: (addr: number) => void,
): ReactNode {
  if (value === null) return <>{'\u2014'}</>
  if (value >= 0x10000) {
    return <HexAddress value={value} onNavigate={onNavigate} />
  }
  const hex = `0x${value.toString(16).toUpperCase()}`
  return <>{hex} ({value})</>
}
