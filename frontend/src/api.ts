import type {
  CreateSessionResponse,
  ExpandField,
  FrameDetail,
  Instruction,
  SessionData,
  SourceLine,
  UploadOptions,
} from './types'

export type { ExpandField }

class ApiError extends Error {
  override name = 'ApiError'
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) {
    let message = `HTTP ${res.status}`
    const text = await res.text().catch(() => '')
    if (text) {
      try {
        const body = JSON.parse(text)
        if (body.error) message = body.error
      } catch {
        message = text.slice(0, 200)
      }
    }
    throw new ApiError(res.status, message)
  }
  return await res.json() as T
}

export async function createSession(
  rsodLog: File | Blob,
  symbolFile: File,
  extraSymbols?: File[],
  opts?: UploadOptions,
): Promise<CreateSessionResponse> {
  const form = new FormData()
  form.append('rsod_log', rsodLog)
  form.append('symbol_file', symbolFile)
  if (extraSymbols) {
    for (const f of extraSymbols) {
      form.append('extra_symbols[]', f)
    }
  }
  if (opts?.base) form.append('base', opts.base)
  if (opts?.tag) form.append('tag', opts.tag)
  if (opts?.commit) form.append('commit', opts.commit)
  return request<CreateSessionResponse>('/api/session', {
    method: 'POST',
    body: form,
  })
}

export async function getSession(sessionId: string): Promise<SessionData> {
  return request<SessionData>(`/api/session/${sessionId}`)
}

export async function getFrame(
  sessionId: string,
  frameIndex: number,
): Promise<FrameDetail> {
  return request<FrameDetail>(`/api/frame/${sessionId}/${frameIndex}`)
}

export async function getDisasm(
  sessionId: string,
  frameIndex: number,
  context = 24,
): Promise<{ instructions: Instruction[] }> {
  return request(`/api/disasm/${sessionId}/${frameIndex}?context=${context}`)
}

export async function getSource(
  sessionId: string,
  frameIndex: number,
  context = 5,
): Promise<{ file: string; target_line: number; lines: SourceLine[] }> {
  return request(`/api/source/${sessionId}/${frameIndex}?context=${context}`)
}

export async function resolveAddress(
  sessionId: string,
  address: string,
): Promise<{
  symbol: string
  offset: number
  source_loc?: string
  function?: string
  object_file: string
  is_function: boolean
}> {
  return request(`/api/resolve/${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  })
}


export async function expandVar(
  sessionId: string,
  frameIndex: number,
  addr: number,
  typeOffset: number,
  cuOffset: number,
  offset?: number,
  count?: number,
  varKey?: string,
): Promise<{ fields: ExpandField[]; total_count: number }> {
  let url = `/api/expand/${sessionId}/${frameIndex}?addr=${addr.toString(16)}&type_offset=${typeOffset}&cu_offset=${cuOffset}`
  if (offset !== undefined) url += `&offset=${offset}`
  if (count !== undefined) url += `&count=${count}`
  if (varKey) url += `&var_key=${encodeURIComponent(varKey)}`
  return request(url)
}

export async function switchBackend(
  sessionId: string,
  backend: 'pyelftools' | 'gdb',
): Promise<{ backend: string }> {
  return request(`/api/backend/${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ backend }),
  })
}

export async function getMemory(
  sessionId: string,
  addr: number,
  size = 256,
): Promise<{ address: number; bytes: (number | null)[] }> {
  return request(`/api/memory/${sessionId}?addr=${addr.toString(16)}&size=${size}`)
}

export async function deleteSession(
  sessionId: string,
): Promise<{ deleted: boolean }> {
  return request(`/api/session/${sessionId}`, { method: 'DELETE' })
}
