/**
 * 输出整理：把 IDA 原始的伪代码 / 反汇编 / 符号信息压成「模型读起来省 token、
 * 又能直接拿地址去写注释」的形态。
 *
 * 旧版插件的伪代码每行都带 `/* line: 12, address: 0x401010 *\/`。
 * 原样塞给模型，光装饰就占掉一半预算，所以这里拆成 `地址  代码` 的紧凑格式；
 * 没有地址的行保持缩进，只留代码。
 */

const LINE_RE = /^\s*\/\*\s*line:\s*(\d+)(?:,\s*address:\s*(0x[0-9a-fA-F]+))?\s*\*\/\s?(.*)$/

/**
 * 两种协议的伪代码形态不一样：旧协议直接回一个字符串（每行带注释前缀），
 * 标准 MCP 可能把它包在 {pseudocode: ...} / content 里。统一收口，免得下游各判一次。
 */
export function asPseudocodeText (raw) {
  if (typeof raw === 'string') return raw
  if (!raw || typeof raw !== 'object') return ''
  for (const key of ['pseudocode', 'text', 'decompilation', 'code', 'result']) {
    if (typeof raw[key] === 'string' && raw[key]) return raw[key]
  }
  if (Array.isArray(raw.content)) {
    return raw.content.map((part) => (typeof part === 'string' ? part : part?.text || '')).filter(Boolean).join('\n')
  }
  return ''
}

export function parsePseudocode (raw) {
  const text = String(raw || '')
  const entries = []
  for (const line of text.split(/\r?\n/)) {
    const match = LINE_RE.exec(line)
    if (match) {
      entries.push({ line: Number(match[1]), addr: match[2] ? match[2].toLowerCase() : null, text: match[3] ?? '' })
    } else if (line.trim()) {
      entries.push({ line: null, addr: null, text: line })
    }
  }
  return entries
}

/** 紧凑伪代码：有地址的行带地址，没地址的行保留缩进。 */
export function renderPseudocode (raw, { maxLines = 400 } = {}) {
  const entries = parsePseudocode(raw)
  const addressable = entries.filter((entry) => entry.addr).length
  const kept = entries.slice(0, maxLines)
  const lines = kept.map((entry) => (entry.addr ? `${entry.addr}  ${entry.text}` : `          ${entry.text}`))
  if (entries.length > kept.length) {
    lines.push(`…（还有 ${entries.length - kept.length} 行被截断，需要更多就用 ida_func 加大 maxLines）`)
  }
  return {
    text: lines.join('\n'),
    lineCount: entries.length,
    addressableLines: addressable,
    truncated: entries.length > kept.length,
  }
}

/** 从伪代码里抽出有地址的行，方便模型直接拿去 set_comment。 */
export function addressMap (raw) {
  const map = []
  for (const entry of parsePseudocode(raw)) {
    if (entry.addr) map.push({ addr: entry.addr, code: entry.text.trim() })
  }
  return map
}

export function renderAsm (disassembly, { maxLines = 200 } = {}) {
  const lines = Array.isArray(disassembly?.lines) ? disassembly.lines : []
  const kept = lines.slice(0, maxLines)
  const text = kept
    .map((line) => {
      const comment = Array.isArray(line.comments) && line.comments.length ? `  ; ${line.comments.join(' | ')}` : ''
      return `${String(line.address || '').toLowerCase()}  ${String(line.instruction || '').trim()}${comment}`
    })
    .join('\n')
  return {
    text: lines.length > kept.length ? `${text}\n…（还有 ${lines.length - kept.length} 行被截断）` : text,
    lineCount: lines.length,
    truncated: lines.length > kept.length,
    name: disassembly?.name || null,
    start: disassembly?.start_ea || null,
    prototype: disassembly?.return_type
      ? `${disassembly.return_type} ${disassembly.name}(${(disassembly.arguments || []).map((arg) => `${arg.type} ${arg.name}`).join(', ')})`
      : null,
    stackFrame: Array.isArray(disassembly?.stack_frame)
      ? disassembly.stack_frame.map((slot) => `${slot.offset}  ${slot.type} ${slot.name}`)
      : [],
  }
}

/** 找出 [addr, addr+size) 区间内的反汇编行，用于 patch 前后对比。 */
export function linesAt (disassembly, addr, count = 8) {
  const target = normAddr(addr)
  const lines = Array.isArray(disassembly?.lines) ? disassembly.lines : []
  const startIndex = lines.findIndex((line) => normAddr(line.address) === target)
  if (startIndex < 0) return []
  return lines.slice(startIndex, startIndex + count)
}

export function normAddr (input) {
  if (input === null || input === undefined) return ''
  const raw = String(input).trim()
  if (!raw) return ''
  if (/^0x[0-9a-f]+$/i.test(raw)) return raw.toLowerCase()
  if (/^[0-9a-f]+h$/i.test(raw)) return `0x${raw.slice(0, -1).toLowerCase()}`
  // 纯数字按 16 进制解释：逆向场景里没人会手打十进制地址，而在 IDA 里 401000
  // 就是 0x401000。按十进制转会把 401000 变成 0x61e68，静默跑到错误地址。
  if (/^\d+$/.test(raw)) return `0x${raw.replace(/^0+/, '').toLowerCase() || '0'}`
  return raw
}

export function isAddressLike (input) {
  const raw = String(input ?? '').trim()
  return /^0x[0-9a-f]+$/i.test(raw) || /^[0-9a-f]+h$/i.test(raw) || /^\d+$/.test(raw)
}

export function shortName (text, max = 48) {
  const value = String(text ?? '').replace(/\s+/g, ' ').trim()
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

export function hexToInt (value) {
  const raw = String(value ?? '').trim().toLowerCase()
  if (!raw) return null
  if (raw.startsWith('0x')) return Number.parseInt(raw.slice(2), 16)
  if (/^[0-9a-f]+h$/.test(raw)) return Number.parseInt(raw.slice(0, -1), 16)
  // 和 normAddr 一致：纯数字当 16 进制（IDA 习惯）
  if (/^[0-9a-f]+$/.test(raw)) return Number.parseInt(raw, 16)
  const parsed = Number.parseInt(raw, 10)
  return Number.isFinite(parsed) ? parsed : null
}

export function intToHex (value, pad = 0) {
  if (!Number.isFinite(value)) return null
  return `0x${Math.max(0, Math.trunc(value)).toString(16).padStart(pad, '0')}`
}

/** 简单的 16 进制/ASCII 双栏，用于 patch 前后肉眼对比。 */
export function hexDump (bytes, base) {
  const byteList = String(bytes || '')
    .trim()
    .split(/\s+/)
    .filter((item) => /^[0-9a-fx]{2,4}$/i.test(item))
    .map((item) => Number.parseInt(item.replace(/^0x/i, ''), 16))
  if (!byteList.length) return ''
  const rows = []
  const start = hexToInt(base) ?? 0
  for (let i = 0; i < byteList.length; i += 16) {
    const slice = byteList.slice(i, i + 16)
    const hex = slice.map((byte) => (Number.isFinite(byte) ? byte.toString(16).padStart(2, '0') : '??')).join(' ')
    const ascii = slice
      .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'))
      .join('')
    rows.push(`${intToHex(start + i)}  ${hex.padEnd(47)}  ${ascii}`)
  }
  return rows.join('\n')
}

export function byteString (bytes) {
  return String(bytes || '').trim().replace(/\s+/g, ' ').toLowerCase()
}
