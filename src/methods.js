/**
 * 方法名解析与参数装配。
 *
 * 存在的唯一理由：模型会猜方法名。真实清单里没有 get_bytes / set_name /
 * get_many_bytes，猜三次错三次之后它就开始绕到 IDB 外面自己写 Python 解 PE —— 这正是
 * 我们最不希望发生的事。
 *
 * 所以这里干三件事：
 *   1. 别名表：把常见猜测映射到真实方法名（能映射的映射，映射不了的给出候选）；
 *   2. 模糊匹配：拼错时用编辑距离找最接近的几个，连同签名一起报出来；
 *   3. 具名参数：旧协议其实支持 dict 参数（键必须和签名完全一致），有了清单就不必再
 *      数逗号了；类型在这里顺手做强转，免得 IDA 侧报 "expected int"。
 */

import { LEGACY_METHODS } from './manifest.js'

const BY_NAME = new Map(LEGACY_METHODS.map((method) => [method.name, method]))

/**
 * 常见猜测 → 真实方法。值是数组表示「有歧义，按参数形态再判断」，
 * 无法判断时把候选一起报给模型，而不是随便挑一个。
 */
const ALIASES = {
  get_bytes: ['read_memory_bytes'],
  get_many_bytes: ['read_memory_bytes'],
  read_bytes: ['read_memory_bytes'],
  read_memory: ['read_memory_bytes'],
  set_name: ['rename_function', 'rename_global_variable', 'rename_local_variable'],
  rename: ['rename_function'],
  set_type: ['set_global_variable_type', 'set_local_variable_type'],
  set_function_type: ['set_function_prototype'],
  set_prototype: ['set_function_prototype'],
  get_xrefs: ['get_xrefs_to'],
  xrefs: ['get_xrefs_to'],
  xrefs_to: ['get_xrefs_to'],
  get_structs: ['get_defined_structures'],
  list_structs: ['get_defined_structures'],
  get_struct: ['get_struct_info_simple'],
  get_globals: ['list_globals_filter', 'list_globals'],
  get_strings: ['list_strings_filter', 'list_strings'],
  get_functions: ['list_functions'],
  list_funcs: ['list_functions'],
  decompile: ['decompile_function'],
  disasm: ['disassemble_function'],
  disassemble: ['disassemble_function'],
  get_entry: ['get_entry_points'],
  entry_points: ['get_entry_points'],
  get_imports: ['list_imports'],
  imports: ['list_imports'],
  patch_asm: ['patch_address_assembles'],
  declare_type: ['declare_c_type'],
  get_stack: ['get_stack_frame_variables'],
  stack_frame: ['get_stack_frame_variables'],
  metadata: ['get_metadata'],
  get_meta: ['get_metadata'],
  func_by_name: ['get_function_by_name'],
  func_by_addr: ['get_function_by_address'],
  func: ['get_function_by_address'],
}

export function getMethod (name) {
  return BY_NAME.get(String(name || '')) || null
}

export function methodNames () {
  return LEGACY_METHODS.map((method) => method.name)
}

function editDistance (a, b) {
  const left = a.toLowerCase()
  const right = b.toLowerCase()
  const rows = []
  for (let i = 0; i <= left.length; i += 1) {
    rows[i] = [i]
    for (let j = 1; j <= right.length; j += 1) {
      if (i === 0) { rows[i][j] = j; continue }
      const cost = left[i - 1] === right[j - 1] ? 0 : 1
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
    }
  }
  return rows[left.length][right.length]
}

/** 拼错时给建议：先看别名前缀/包含，再退回编辑距离。 */
export function suggestMethods (name, limit = 5) {
  return rankNames(name, LEGACY_METHODS.map((method) => method.name), limit)
}

/** 任意名字集合的排序（标准 MCP 的工具名也用它）。 */
export function rankNames (name, names, limit = 5) {
  const raw = String(name || '').toLowerCase()
  if (!raw) return []
  const scored = names.map((candidate) => {
    const lower = String(candidate).toLowerCase()
    let score = editDistance(raw, lower)
    if (lower.includes(raw) || raw.includes(lower)) score = Math.min(score, 2)
    const roots = raw.split(/[_\W]+/).filter((token) => token.length >= 3)
    for (const root of roots) {
      if (lower.includes(root)) score -= 1
    }
    return { name: candidate, score }
  })
  return scored.sort((a, b) => a.score - b.score).slice(0, limit).map((item) => item.name)
}

/**
 * 把用户给的方法名解析成真实方法。
 * @returns {{method: object|null, via: string|null, candidates: string[]}}
 */
export function resolveMethodName (input) {
  const raw = String(input || '').trim()
  if (!raw) return { method: null, via: null, candidates: [] }
  const direct = BY_NAME.get(raw)
  if (direct) return { method: direct, via: 'direct', candidates: [] }

  const alias = ALIASES[raw] || ALIASES[raw.toLowerCase()]
  if (alias) {
    const known = alias.filter((name) => BY_NAME.has(name))
    if (known.length === 1) return { method: BY_NAME.get(known[0]), via: `alias:${raw}`, candidates: [] }
    if (known.length > 1) return { method: null, via: `alias:${raw}`, candidates: known }
  }

  // 大小写/连字符变体
  const normalized = raw.toLowerCase().replace(/[-\s]+/g, '_')
  const loose = BY_NAME.get(normalized)
  if (loose) return { method: loose, via: 'normalized', candidates: [] }

  return { method: null, via: null, candidates: suggestMethods(raw) }
}

/** 人读的签名，如 list_globals_filter(offset: int, count: int, filter: str) */
export function formatSignature (method) {
  const params = method.params.map((param) => `${param.name}: ${param.type}${param.optional ? '?' : ''}`).join(', ')
  return `${method.name}(${params})${method.returns ? ` → ${method.returns}` : ''}`
}

function coerce (value, type, name) {
  if (value === null || value === undefined) return value
  const base = String(type || '').replace(/^Optional\[|\]$/g, '')
  if (base === 'int' || base === 'float') {
    if (typeof value === 'number') return value
    const parsed = Number(String(value).trim().replace(/^0x/i, ''))
    if (Number.isFinite(parsed)) {
      // "0x10" 已经被剥掉前缀，得按 16 进制再读一次
      return /^0x/i.test(String(value).trim()) ? Number.parseInt(String(value).trim().slice(2), 16) : parsed
    }
    throw new Error(`参数 ${name} 需要 ${base}，收到 ${JSON.stringify(value)}`)
  }
  if (base === 'bool') {
    if (typeof value === 'boolean') return value
    const lower = String(value).toLowerCase()
    if (['true', '1', 'yes'].includes(lower)) return true
    if (['false', '0', 'no'].includes(lower)) return false
    throw new Error(`参数 ${name} 需要 bool，收到 ${JSON.stringify(value)}`)
  }
  if (base === 'str') return typeof value === 'string' ? value : String(value)
  return value
}

/**
 * 按签名把具名/位置参数装配成旧协议要的形态。
 * 返回 { positional, named, missing, unknown }，调用方决定用哪种（旧协议两种都行）。
 */
export function assembleParams (method, params) {
  const given = Array.isArray(params) ? params : (params && typeof params === 'object' ? params : {})
  const names = method.params.map((param) => param.name)

  if (Array.isArray(given)) {
    const mapped = {}
    method.params.forEach((param, index) => {
      if (index < given.length) mapped[param.name] = coerce(given[index], param.type, param.name)
    })
    return {
      positional: trimTrailing(method.params.map((param) => mapped[param.name])),
      named: mapped,
      missing: method.params.filter((param, index) => !param.optional && index >= given.length).map((p) => p.name),
      unknown: [],
    }
  }

  const unknown = Object.keys(given).filter((key) => !names.includes(key))
  const missing = method.params
    .filter((param) => !param.optional && !(param.name in given))
    .map((param) => param.name)
  const named = {}
  for (const param of method.params) {
    if (param.name in given) named[param.name] = coerce(given[param.name], param.type, param.name)
  }
  return {
    // 末尾的缺省参数要截掉：位置形态里塞 undefined 会被 JSON 变成 null，
    // 旧协议随后 str(None) 得到 'None'，反而把可选参数填脏了。
    positional: trimTrailing(method.params.map((param) => named[param.name])),
    named,
    missing,
    unknown,
  }
}

function trimTrailing (values) {
  let last = values.length - 1
  while (last >= 0 && values[last] === undefined) last -= 1
  return last >= 0 ? values.slice(0, last + 1) : []
}

/** 参数出问题时的报错文案：把期望签名、缺少/多余的键一次说清。 */
export function describeParamProblem (method, problem) {
  const rows = [`${method.name} 的参数对不上。`, `期望：${formatSignature(method)}`]
  if (problem.missing?.length) rows.push(`缺少：${problem.missing.join(', ')}`)
  if (problem.unknown?.length) {
    rows.push(`多余：${problem.unknown.join(', ')}（旧协议的键名必须和签名完全一致，不是随便起的）`)
  }
  const docs = method.params.map((param) => {
    const full = LEGACY_METHODS.find((m) => m.name === method.name)?.params?.find((p) => p.name === param.name)
    return full ? `  ${param.name}: ${param.type}` : null
  }).filter(Boolean)
  if (docs.length) rows.push('参数说明：', ...docs)
  if (method.doc) rows.push(`文档：${method.doc}`)
  return rows.join('\n')
}
