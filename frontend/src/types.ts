export interface CrashSummary {
  format: string
  exception_desc: string
  crash_pc: number | null
  crash_symbol: string
  image_name: string
  image_base: number
  esr: number | null
  far: number | null
  sp: number | null
}

export interface InlineInfo {
  function: string
  source_loc: string
}

export interface FrameSummary {
  index: number
  address: number
  call_addr: number
  is_crash_frame: boolean
  is_synthetic?: boolean
  module: string
  symbol: string | null
  sym_offset: number
  source_loc: string
  inlines: InlineInfo[]
}

export interface VarInfo {
  name: string
  type: string
  location: string
  reg_name: string | null
  value: number | null
  approximate: boolean
  is_expandable: boolean
  expand_addr: number | null
  string_preview: string | null
  type_offset: number
  cu_offset: number
  var_key?: string
}

export interface ExpandField {
  name: string
  type: string
  value: number | null
  byte_size: number
  is_expandable: boolean
  expand_addr: number | null
  string_preview: string | null
  type_offset: number
  cu_offset: number
  access?: string
  var_key?: string
}

export interface FrameDetail extends FrameSummary {
  params: VarInfo[]
  locals: VarInfo[]
  globals: VarInfo[]
  call_verified: boolean | null
  frame_registers?: Record<string, string>
}

export interface Instruction {
  address: number
  mnemonic: string
  op_str: string
  is_target: boolean
  source_line: string
}

export interface SourceLine {
  number: number
  text: string
  is_target: boolean
}

export interface ModuleInfo {
  index: number
  name: string
  base: number
  size: number
  debug_path: string
}

export interface LbrEntry {
  type: string
  addr: number
  module: string
  offset: number
}

export interface SessionData {
  crash_summary: CrashSummary
  frames: FrameSummary[]
  registers: Record<string, string>
  v_registers: Record<string, string>
  format: string
  call_verified: Record<string, boolean>
  rsod_text: string
  backend: string
  gdb_available: boolean
  lldb_available: boolean
  modules: ModuleInfo[]
  lbr: LbrEntry[]
  name: string | null
}

export interface CreateSessionResponse {
  session_id: string
  crash_summary: CrashSummary
  frame_count: number
}

export interface UploadOptions {
  base?: string
  tag?: string
  commit?: string
}

export interface HistoryEntry {
  id: string
  created_at: string
  image_name: string
  exception_desc: string
  crash_pc: number | null
  crash_symbol: string
  frame_count: number
  backend: string
  imported_from: string | null
  name: string | null
}
