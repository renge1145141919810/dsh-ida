/**
 * dsh-ida —— 把本机 IDA Pro 接到 DSH。
 *
 * 设计取向：小工具表，大工作流。
 *   旧版 ida-pro-mcp 已经能把 59 个 RPC 全部暴露出来，但那对模型不好用——一次函数分析
 *   要来回四五个调用，写注释要一条一条发，patch 改完没有账可查。
 *   这里只做一组工具（11 个），把「读一个函数」「改一批标注」「打一个 patch」各收拢成一次调用，
 *   并且强制执行三件 MCP 做不到的事：写前查权限、写后回读校验、改动留台账。
 *
 * 能力仍由 IDA 完成，插件不解析二进制、不碰 IDA 内部结构。
 */

import { writeFileSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { join, resolve as resolvePath, isAbsolute, extname, dirname } from 'node:path'
import { IdaBridge, BridgeError } from './src/rpc.js'
import { Workspace, baseDir } from './src/store.js'
import { LEGACY_METHODS } from './src/manifest.js'
import {
  resolveMethodName,
  assembleParams,
  describeParamProblem,
  formatSignature,
  suggestMethods,
  rankNames,
} from './src/methods.js'
import {
  normAddr,
  isAddressLike,
  asPseudocodeText,
  renderPseudocode,
  renderAsm,
  addressMap,
  linesAt,
  hexDump,
  byteString,
  hexToInt,
  intToHex,
  shortName,
} from './src/format.js'

export const inject = ['tools']

// 渲染结果统一是 [{type:'text', text}] 这种 part 数组。这里的 guard 不是洁癖：
// asJson() 本身已经返回 part 数组，外面再套一次 text() 就会 String([{...}]) →
// 模型看到的是 "[object Object]"。这个 bug 真发生过（renameGlobal / stack 全是它）。
const text = (value) => (
  Array.isArray(value) && value.length && value.every((part) => part && part.type === 'text')
    ? value
    : [{ type: 'text', text: String(value) }]
)
const asJson = (value) => text(JSON.stringify(value, null, 2))

const runtime = {
  config: null,
  bridge: null,
  workspace: null,
  meta: null,
  globalIndex: null,
}

function resolveConfig (config) {
  const cfg = config && typeof config === 'object' ? config : {}
  const rawAllow = String(cfg.allow || process.env.DSH_IDA_ALLOW || 'annotate').toLowerCase()
  const allow = ['off', 'annotate', 'patch'].includes(rawAllow) ? rawAllow : 'annotate'
  const timeout = Number(cfg.timeoutMs || process.env.DSH_IDA_TIMEOUT || 45000)
  return {
    url: cfg.url || process.env.DSH_IDA_URL || 'http://127.0.0.1:13337/mcp',
    allow,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 45000,
    maxLines: Number(cfg.maxLines) > 0 ? Number(cfg.maxLines) : 400,
    // 工作区默认还在 LOCALAPPDATA；给了 dir 就搬过去（比如想跟项目一起提交）。
    dir: cfg.dir || process.env.DSH_IDA_DIR || null,
    // 导出默认落在会话当前目录，而不是和 IDB 状态挤在 LOCALAPPDATA —— 免得每次导出都要跨盘拷。
    outDir: cfg.outDir || process.env.DSH_IDA_OUT || process.cwd(),
  }
}

function bridge () {
  if (!runtime.bridge) {
    runtime.bridge = new IdaBridge({ url: runtime.config.url, timeoutMs: runtime.config.timeoutMs })
  }
  return runtime.bridge
}

const CONNECT_HINT = [
  '检查顺序：',
  '1. IDA 是否开着，并且已经打开一个 .i64/.idb（关掉 IDA 端口就没了，这是最常见的）。',
  '2. IDA 的 Output 窗口里有没有 “[MCP] Server started at http://localhost:13337”。',
  '3. 端口是不是被别的程序占了：netstat -ano | findstr 13337。',
  '4. 插件版本不同端点也不同：旧版是自定义 JSON-RPC（POST /mcp），新版是标准 MCP（也是 /mcp）。',
  '   本插件两种都认，认不出来会明确报错，不会静默降级。',
].join('\n')

async function context ({ needWorkspace = true } = {}) {
  const b = bridge()
  await b.connect()
  const meta = await b.invoke('meta')
  runtime.meta = meta
  if (needWorkspace) {
    const key = meta && meta.sha256 ? String(meta.sha256) : null
    if (!runtime.workspace || (key && runtime.workspace.state.meta?.sha256 !== key) || !existsSync(runtime.workspace.dir)) {
      runtime.workspace = Workspace.load(meta || {}, { dir: runtime.config.dir })
    }
    runtime.workspace.state.meta = { ...(runtime.workspace.state.meta || {}), ...(meta || {}) }
  }
  return { bridge: b, meta, ws: runtime.workspace }
}

function normalizeFunction (raw) {
  if (!raw || typeof raw !== 'object') {
    throw new BridgeError('IDA 没有返回函数信息（地址可能不在函数里，或者函数还没定义）', { kind: 'client' })
  }
  return {
    address: normAddr(raw.address || raw.start_ea || raw.ea || ''),
    name: raw.name || null,
    prototype: typeof raw.prototype === 'string' ? raw.prototype : null,
    size: raw.size || raw.end_ea || null,
  }
}

async function resolveFunction (b, target) {
  const raw = String(target ?? '').trim()
  if (!raw) throw new BridgeError('缺少 target：需要函数名或地址（如 0x401000 / GetProcAddress）', { kind: 'client' })
  try {
    if (isAddressLike(raw)) {
      return normalizeFunction(await b.invoke('funcByAddr', { addr: normAddr(raw) }))
    }
    return normalizeFunction(await b.invoke('funcByName', { name: raw }))
  } catch (error) {
    if (error.kind === 'ida') {
      throw new BridgeError(`在 IDA 里找不到 ${raw}：${error.message}。名字要区分大小写；不确定就先 ida_find 一下。`, { kind: 'ida' })
    }
    throw error
  }
}

/**
 * 全局变量索引：名字 ↔ 地址。
 *
 * 旧协议没有「按地址取名字」的方法（`rename_global_variable` 只要名字），
 * 而模型手里通常只有地址。所以我们自己扫一遍命名表建索引，缓存两分钟。
 */
async function globalIndex (b, { refresh = false } = {}) {
  if (!refresh && runtime.globalIndex && Date.now() - runtime.globalIndex.at < 120000) return runtime.globalIndex
  const byAddr = new Map()
  const byName = new Map()
  let offset = 0
  let scanned = 0
  for (let page = 0; page < 40; page += 1) {
    const chunk = await b.invoke('globals', { offset, count: 1000, filter: '' })
    const data = chunk?.data || []
    for (const item of data) {
      const addr = normAddr(item.address)
      if (addr) {
        byAddr.set(addr, item.name)
        byName.set(String(item.name).toLowerCase(), addr)
      }
    }
    scanned += data.length
    if (!data.length) break
    if (chunk?.next_offset === null || chunk?.next_offset === undefined) break
    if (chunk.next_offset === offset) break
    offset = chunk.next_offset
  }
  runtime.globalIndex = { at: Date.now(), byAddr, byName, scanned }
  return runtime.globalIndex
}

/**
 * 地址 → 名字。三条路，按代价从低到高：
 *   1. 已建好的全局索引（一次全量扫描，缓存两分钟）
 *   2. 拿地址里的十六进制数字当名字子串问 IDA（byte_403028 必命中）
 *   3. 强制重建索引
 *
 * 之前只有 1 和 3。大 IDB 上索引可能被页数上限截断，于是「明明有名字却查不到」，
 * 而回执里还写着「要按地址查就直接把 0x… 当 pattern」，看起来自相矛盾。第 2 条补上了。
 */
async function lookupGlobalName (b, addr) {
  const target = normAddr(addr)
  if (!target) return { name: null, via: null }

  const index = await globalIndex(b).catch(() => null)
  if (index?.byAddr.has(target)) return { name: index.byAddr.get(target), via: 'index' }

  const digits = target.replace(/^0x/, '')
  if (digits) {
    const shortlist = await scanList(b, 'globals', { offset: 0, limit: 200, matcher: null, text: digits })
      .catch(() => ({ items: [] }))
    const hit = (shortlist.items || []).find((item) => normAddr(item.address) === target)
    if (hit) return { name: hit.name, via: 'filter' }
  }

  const refreshed = await globalIndex(b, { refresh: true }).catch(() => null)
  if (refreshed?.byAddr.has(target)) return { name: refreshed.byAddr.get(target), via: 'refresh' }
  return { name: null, via: null }
}

async function nameAtAddress (b, addr) {
  const found = await lookupGlobalName(b, addr)
  return found.name
}

/** rename_global_variable 只认名字：给了地址就先换成名字。 */
async function resolveGlobalName (b, input) {
  const raw = String(input || '').trim()
  if (!raw) return null
  if (!isAddressLike(raw)) return raw
  return nameAtAddress(b, raw)
}

const FIND_KINDS = {
  func: 'func', funcs: 'func', function: 'func', functions: 'func',
  string: 'string', strings: 'string', str: 'string',
  global: 'global', globals: 'global', data: 'global', name: 'global', names: 'global',
  import: 'import', imports: 'import',
  entry: 'entry', entries: 'entry', entrypoint: 'entry', entrypoints: 'entry',
}

/** 只有写明 0x.. / ..h 才算地址。纯数字（如 4030）当名字子串处理 —— 
 * 之前把它当十进制地址转成了 0xfbe，于是「用 4030 查全局变量返回 0 条」。 */
function isExplicitAddress (input) {
  const raw = String(input || '').trim()
  return /^0x[0-9a-f]+$/i.test(raw) || /^[0-9a-f]+h$/i.test(raw)
}

function normalizeFindKind (input) {
  return FIND_KINDS[String(input || '').trim().toLowerCase()] || null
}

/** 子串（不区分大小写）或 /正则/。旧插件声称支持 /re/，实际只是 TODO。 */
function buildMatcher (pattern) {
  if (!pattern) return () => true
  const match = /^\/(.+)\/([a-z]*)$/i.exec(pattern)
  if (match) {
    try {
      const flags = match[2].includes('i') ? match[2] : `${match[2]}i`
      const rx = new RegExp(match[1], flags)
      return (text) => rx.test(String(text || ''))
    } catch {
      // 正则写错就退回子串，别让整个查找失败
    }
  }
  const needle = pattern.toLowerCase()
  return (text) => String(text || '').toLowerCase().includes(needle)
}

function labelOf (kind, item) {
  if (kind === 'funcs') return item.name
  if (kind === 'globals') return item.name
  return item.string
}

function normalizeFindItem (kind, item) {
  if (kind === 'funcs') return { address: normAddr(item.address), name: item.name, size: item.size }
  if (kind === 'globals') return { address: normAddr(item.address), name: item.name }
  return { address: normAddr(item.address), string: item.string, length: item.length }
}

/**
 * 翻页取列表。
 *   非正则 + 非函数 → 让 IDA 侧过滤（它是子串匹配，够用且省往返）；
 *   正则 / 函数名 → 只能本地过滤，因为旧插件对 functions 没有 filter 参数。
 */
async function scanList (b, kind, { offset = 0, limit = 30, matcher, text = '' }) {
  const isFunc = kind === 'funcs'
  const capName = isFunc ? 'listFuncs' : (kind === 'globals' ? 'globals' : 'strings')
  const regexMode = /^\/.+\/[a-z]*$/i.test(text || '')

  if (!isFunc && !regexMode) {
    const page = await b.invoke(capName, { offset, count: limit, filter: text })
    const data = page?.data || []
    const exhausted = page?.next_offset === null || page?.next_offset === undefined
    return {
      items: data.map((item) => normalizeFindItem(kind, item)),
      total: exhausted ? offset + data.length : null,
      scanned: offset + data.length,
      nextOffset: exhausted ? null : page.next_offset,
    }
  }

  const pageSize = isFunc ? 1000 : 2000
  const items = []
  let cursor = offset
  let scanned = 0
  let total = null
  for (let page = 0; page < 40; page += 1) {
    const args = isFunc ? { offset: cursor, count: pageSize } : { offset: cursor, count: pageSize, filter: '' }
    const chunk = await b.invoke(capName, args)
    const data = chunk?.data || []
    if (!data.length) { total = scanned; break }
    scanned += data.length
    for (const item of data) {
      if (matcher(labelOf(kind, item))) {
        items.push(normalizeFindItem(kind, item))
        if (items.length >= limit) break
      }
    }
    if (items.length >= limit) break
    if (chunk?.next_offset === null || chunk?.next_offset === undefined) { total = scanned; break }
    if (chunk.next_offset === cursor) break
    cursor = chunk.next_offset
  }
  return { items, total, scanned, nextOffset: total === null ? null : null }
}

function gate (level) {
  const allow = runtime.config.allow
  if (allow === 'off') {
    return {
      blocked: true,
      reason: '当前是只读模式（allow=off），任何写 IDB 的操作都会被挡下来。',
      how: '在插件配置里把 allow 改成 annotate（可写注释/改名/类型）或 patch（另外允许 patch 指令），或设环境变量 DSH_IDA_ALLOW。',
    }
  }
  if (level === 'patch' && allow !== 'patch') {
    return {
      blocked: true,
      reason: 'patch 指令会真的改掉字节，当前 allow=annotate 不够。',
      how: '确认要改二进制后，把 allow 设成 patch（或 DSH_IDA_ALLOW=patch）再调。',
    }
  }
  return null
}

async function disasmOf (b, address) {
  const fn = await resolveFunction(b, address)
  const disasm = await b.invoke('disasm', { addr: fn.address })
  return { fn, disasm }
}

export function apply (ctx, config) {
  runtime.config = resolveConfig(config)
  // 重新载入插件（或测试里重复 apply）时，旧连接和旧工作区必须丢掉，
  // 否则改了 url / allow 却还在用上一份状态。
  runtime.bridge = null
  runtime.workspace = null
  runtime.meta = null
  runtime.globalIndex = null
  const log = (...args) => {
    try {
      ctx?.logger?.('dsh-ida')?.info?.(...args)
    } catch {
      // logger 不可用就算了，不能因为打日志拖垮工具
    }
  }
  log('dsh-ida 就绪', runtime.config.url, `allow=${runtime.config.allow}`)

  const tools = []

  // ---------------------------------------------------------------- 连接状态
  tools.push({
    name: 'ida_status',
    description:
      '检查与 IDA 的连接、识别协议、报告当前数据库信息和工作区状态。' +
      '任何 IDA 操作之前先调一次：连不上时它会把排查顺序列出来，而不是让后面的调用一脸懵地失败。',
    parameters: {
      type: 'object',
      properties: {
        refresh: { type: 'boolean', description: '强制重新握手并重新识别协议（IDA 刚重启过就用它）' },
        verbose: { type: 'boolean', description: '附上命名表/注释表的完整内容' },
        probe: {
          type: 'boolean',
          description: '顺便探一下类型层（结构体/本地类型）和栈帧层能不能用。' +
            '老版本 IDA 缺新 SDK 符号时这两层会整块报错，先探一下比逐个试错快。',
        },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderStatus(value)) },
    async execute (args = {}) {
      const b = bridge()
      try {
        await b.connect({ force: args.refresh === true })
      } catch (error) {
        // 连不上也要把本地资产摆出来：工作区是纯本地 JSON，用不到 IDA。
        // 以前这里只报「连不上」，模型以为分析记录也跟着没了，只能重做。
        const known = Workspace.list({ dir: runtime.config.dir })
        return {
          connected: false,
          url: runtime.config.url,
          error: error.message,
          hint: CONNECT_HINT,
          gate: runtime.config.allow,
          workspaces: known,
          offlineHint: known.length
            ? `本地有 ${known.length} 个工作区，不用开 IDA 也能读：ida_workspace({ action: "get", key: "${known[0].key}" })。`
            : '本地还没有工作区记录（%LOCALAPPDATA%\\dsh-ida 是空的）。',
        }
      }
      const payload = { connected: true, bridge: b.state(), gate: runtime.config.allow, allowPatch: runtime.config.allow === 'patch' }
      try {
        const meta = await b.invoke('meta')
        runtime.meta = meta
        const ws = Workspace.load(meta || {}, { dir: runtime.config.dir })
        runtime.workspace = ws
        payload.idb = meta
        payload.workspace = ws.summary()
        if (args.verbose === true) {
          payload.workspace.names = ws.state.names
          payload.workspace.comments = ws.state.comments
          payload.workspace.funcs = ws.state.funcs
        }
        payload.hint = '正常的话下一步用 ida_func 看某个函数，或者 ida_find 先定位。'
        if (args.probe === true) {
          payload.capabilities = await probeCapabilities(b)
          if (payload.capabilities.verdict) payload.hint = payload.capabilities.verdict
        }
      } catch (error) {
        payload.metaError = error.message
        payload.hint = '连上了但拿不到数据库信息：IDA 可能还没打开文件，或者分析还没跑完。'
      }
      return payload
    },
  })

  // ---------------------------------------------------------------- 读一个函数
  tools.push({
    name: 'ida_func',
    description:
      '一次调用拿全一个函数的分析材料：伪代码（带地址，可直接拿去做注释锚点）、可选反汇编、' +
      '交叉引用、调用方/被调方、以及工作区里已有的命名和注释。' +
      '替代分别调用 decompile + xrefs + callees 四五次的做法。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: '函数名（区分大小写）或地址，如 0x401000' },
        asm: { type: 'boolean', description: '是否连反汇编一起返回，默认 false' },
        maxLines: { type: 'number', description: '伪代码最多返回多少行，默认 400' },
        xrefs: { type: 'boolean', description: '是否带上交叉引用，默认 true' },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderFunc(value)) },
    async execute (args = {}) {
      const { bridge: b, ws } = await context()
      const fn = await resolveFunction(b, args.target)
      const maxLines = Number(args.maxLines) > 0 ? Number(args.maxLines) : runtime.config.maxLines
      const raw = asPseudocodeText(await b.invoke('decompile', { addr: fn.address }))
      const pseudo = renderPseudocode(raw, { maxLines })

      const result = {
        function: { ...fn, prototype: fn.prototype || guessPrototype(raw) },
        pseudocode: { text: pseudo.text, lineCount: pseudo.lineCount, truncated: pseudo.truncated },
        anchors: addressMap(raw).slice(0, 60),
        workspace: ws?.overlay(fn.address) || null,
      }
      if (!pseudo.lineCount) {
        result.empty = true
        result.hint = 'IDA 返回了空的伪代码。常见原因：地址不在函数内（用 ida_find 确认）、函数还没反编译成功、' +
          '或 Hex-Rays 对这段代码失败（花指令/不支持的指令）。可以先用 ida_func 加 asm:true 看反汇编。'
      }

      if (args.asm === true) {
        const asm = renderAsm(await b.invoke('disasm', { addr: fn.address }), { maxLines: 200 })
        result.asm = { text: asm.text, lineCount: asm.lineCount, stackFrame: asm.stackFrame }
      }

      if (args.xrefs !== false) {
        const [xrefs, callers, callees] = await Promise.all([
          b.invoke('xrefsTo', { addr: fn.address }).catch(() => []),
          b.invoke('callers', { addr: fn.address }).catch(() => []),
          b.invoke('callees', { addr: fn.address }).catch(() => []),
        ])
        result.xrefsTo = (Array.isArray(xrefs) ? xrefs : []).slice(0, 20).map((item) => ({
          from: normAddr(item.address || item.from || ''),
          type: item.type || null,
          // 旧协议 Xref 自带 function 字段（含 name），省一轮 funcByAddr
          inFunction: item.function?.name || null,
        }))
        result.callers = (Array.isArray(callers) ? callers : []).slice(0, 20).map((item) => ({
          address: normAddr(item.address || item.from || ''),
          name: item.name || null,
        }))
        result.callees = (Array.isArray(callees) ? callees : []).slice(0, 20).map((item) => ({
          address: normAddr(item.address || item.to || ''),
          name: item.name || null,
        }))
      }
      return result
    },
  })

  // ---------------------------------------------------------------- 批量标注
  tools.push({
    name: 'ida_annotate',
    description:
      '一次调用把一批标注写进 IDB：函数改名、设置原型、声明类型、局部变量改名/改类型、按地址写注释。' +
      '每项独立成败，写完全部回读校验（名字重新查、注释回读反汇编），并记进工作区。' +
      '建议一次只处理一个函数：先 ida_func 读懂，再带着地址来写。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: '函数名或地址' },
        rename: { type: 'string', description: '函数的新名字，如 decrypt_config' },
        prototype: { type: 'string', description: '完整函数原型。写 C 类型即可，如 int __cdecl(unsigned char *buf, int len)；不要带函数名，也别用 _BYTE/_DWORD（插件会自动纠正，但仍建议写标准 C）' },
        types: { type: 'array', items: { type: 'string' }, description: '要声明的 C 类型/结构体，如 ["struct cfg { int magic; int len; };"]' },
        locals: {
          type: 'array',
          description: '局部变量改名/改类型',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: '伪代码里的旧名字，如 v3 / a1' },
              newName: { type: 'string', description: '新名字' },
              type: { type: 'string', description: '可选，顺便改类型' },
            },
            required: ['name'],
            additionalProperties: false,
          },
        },
        comments: {
          type: 'array',
          description: '按地址写注释',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string', description: '地址，取 ida_func 返回的 anchors 里的 addr' },
              text: { type: 'string', description: '注释正文' },
            },
            required: ['address', 'text'],
            additionalProperties: false,
          },
        },
        globals: {
          type: 'array',
          description: '全局变量改名/改类型（byte_403028 这类名字就是靠它变可读的）',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: '现在的名字，如 byte_403028；也可以写地址 0x403028' },
              newName: { type: 'string', description: '新名字' },
              type: { type: 'string', description: '可选，顺带改类型，如 unsigned char[13] / cfg_header' },
            },
            required: ['name'],
            additionalProperties: false,
          },
        },
        dryRun: { type: 'boolean', description: '只列出将要执行的操作，不实际写入' },
        note: { type: 'string', description: '写进分析日志的一句话，比如「这个函数是 RC4 初始化」' },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderAnnotate(value)) },
    async execute (args = {}) {
      const blocked = gate('annotate')
      if (blocked) return { ok: false, ...blocked }

      const { bridge: b, ws } = await context()
      const fn = await resolveFunction(b, args.target)
      const ops = []

      for (const declaration of toArray(args.types)) {
        ops.push({ kind: 'declareType', args: { declaration: String(declaration) }, label: `声明类型 ${shortName(declaration, 40)}` })
      }
      if (args.prototype) {
        ops.push({
          kind: 'setProto',
          attempts: prototypeVariants(args.prototype),
          args: { addr: fn.address },
          label: `设置原型 ${shortName(args.prototype, 46)}`,
          failureHint: PROTOTYPE_HINT,
        })
      }
      if (args.rename) {
        ops.push({ kind: 'renameFunc', args: { addr: fn.address, name: String(args.rename) }, label: `函数改名 → ${args.rename}` })
      }
      for (const local of toArray(args.locals)) {
        if (!local?.name) continue
        if (local.newName) {
          ops.push({
            kind: 'renameLocal',
            args: { func: fn.address, from: String(local.name), to: String(local.newName) },
            label: `变量 ${local.name} → ${local.newName}`,
          })
        }
        if (local.type) {
          ops.push({
            kind: 'setLocalType',
            args: { func: fn.address, variable: String(local.newName || local.name), type: String(local.type) },
            label: `变量 ${local.newName || local.name} 类型 → ${local.type}`,
          })
        }
      }
      for (const comment of toArray(args.comments)) {
        if (!comment?.address || !comment?.text) continue
        ops.push({
          kind: 'setComment',
          args: { addr: normAddr(comment.address), text: String(comment.text) },
          label: `注释 ${normAddr(comment.address)}`,
        })
      }
      for (const global of toArray(args.globals)) {
        if (!global?.name) continue
        const oldName = await resolveGlobalName(b, String(global.name))
        if (!oldName) {
          ops.push({ kind: 'renameGlobal', args: { from: String(global.name), to: '' }, label: `全局 ${global.name}（找不到名字，跳过）`, skip: true })
          continue
        }
        if (global.newName) {
          ops.push({ kind: 'renameGlobal', args: { from: oldName, to: String(global.newName) }, label: `全局 ${oldName} → ${global.newName}` })
        }
        if (global.type) {
          ops.push({
            kind: 'setGlobalType',
            args: { variable: String(global.newName || oldName), type: String(global.type) },
            label: `全局 ${global.newName || oldName} 类型 → ${global.type}`,
          })
        }
      }

      if (!ops.length) {
        return { ok: false, reason: '没有任何可执行的操作：rename / prototype / types / locals / comments 至少要给一个。' }
      }
      if (args.dryRun === true) {
        return { ok: true, dryRun: true, function: fn, planned: ops.map((op) => op.label), count: ops.length }
      }

      const applied = []
      for (const op of ops) {
        if (op.skip) {
          applied.push({ op: op.label, ok: false, error: '目标在 IDB 里不存在' })
          continue
        }
        try {
          if (Array.isArray(op.attempts) && op.attempts.length) {
            let used = null
            let lastError = null
            for (const variant of op.attempts) {
              try {
                await b.invoke(op.kind, { ...op.args, prototype: variant })
                used = variant
                break
              } catch (error) {
                lastError = error
              }
            }
            if (!used) {
              throw new Error(`${lastError?.message || '未知错误'}${op.failureHint ? `\n${op.failureHint}` : ''}`)
            }
            applied.push({ op: op.label, ok: true, used, corrected: used !== String(args.prototype).trim().replace(/;$/, '') })
          } else {
            await b.invoke(op.kind, op.args)
            applied.push({ op: op.label, ok: true })
          }
        } catch (error) {
          applied.push({ op: op.label, ok: false, error: error.message })
        }
      }

      const verified = await verifyAnnotations(b, fn, args, applied)
      recordAnnotations(ws, fn, args, applied)

      return {
        ok: applied.every((item) => item.ok),
        function: fn,
        applied,
        verified,
        workspace: ws ? ws.summary() : null,
      }
    },
  })

  // ---------------------------------------------------------------- patch
  tools.push({
    name: 'ida_patch',
    description:
      '按汇编改字节，并且记账：改之前抓原指令和原字节，改之后再抓一遍，写进 ledger.jsonl。' +
      '改错了用 rollback 传台账 id（或 "last"）把原指令重新汇编回去。' +
      '指令串用分号分隔，例如 "mov eax, 1; ret"。真正写入需要 allow=patch。',
    parameters: {
      type: 'object',
      properties: {
        address: { type: 'string', description: '起始地址（函数内任意地址都行）' },
        instructions: { type: 'string', description: '要写入的汇编，分号分隔，如 "xor eax, eax; ret"' },
        note: { type: 'string', description: '为什么改，会写进台账' },
        dryRun: { type: 'boolean', description: '只做改前快照并列出计划，不写入' },
        rollback: { type: 'string', description: '回滚某条台账：传台账 id 或 "last"；此时忽略 instructions' },
      },
      required: ['address'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderPatch(value)) },
    async execute (args = {}) {
      const { bridge: b, ws } = await context()
      const { fn, disasm } = await disasmOf(b, args.address)
      const address = normAddr(args.address)

      if (args.rollback) {
        const blockedRollback = gate('patch')
        if (blockedRollback) return { ok: false, ...blockedRollback }
        const record = ws.findPatch(String(args.rollback))
        if (!record) return { ok: false, reason: `台账里找不到 ${args.rollback}（ledger: ${ws.ledgerFile}）` }
        const before = record.before || {}
        if (!Array.isArray(before.instructions) || !before.instructions.length) {
          return { ok: false, reason: '这条台账没有记录原指令，无法按汇编回滚。' }
        }
        await b.invoke('patchAsm', { addr: record.address, instructions: before.instructions.join(';') })
        const restoredBytes = await b.invoke('readBytes', { addr: record.address, size: before.byteLength || 32 }).catch(() => null)
        const byteExact = restoredBytes ? byteString(restoredBytes) === byteString(before.bytes) : null
        ws.markPatch(record.id, 'rolled-back', { restoreVerified: byteExact })
        ws.note('patch', `回滚 ${record.id} @ ${record.address}`)
        return {
          ok: true,
          rolledBack: record.id,
          address: record.address,
          restoredBytes,
          byteExact,
          hint: byteExact === false
            ? '字节没有完全复原（重新汇编后编码可能不同），但指令语义一致，请用 ida_func 复查。'
            : '已复原。',
        }
      }

      if (!args.instructions) return { ok: false, reason: '缺少 instructions；或者你想回滚就传 rollback。' }
      const instructions = String(args.instructions).split(';').map((item) => item.trim()).filter(Boolean)
      const beforeLines = linesAt(disasm, address, instructions.length + 3)
      const beforeBytes = await b.invoke('readBytes', { addr: address, size: 32 })
      const snapshot = {
        address,
        function: fn.name,
        instructions: beforeLines.map((line) => String(line.instruction || '').trim()),
        lines: beforeLines.map((line) => `${normAddr(line.address)}  ${String(line.instruction || '').trim()}`),
        bytes: byteString(beforeBytes),
        byteLength: 32,
      }

      if (args.dryRun === true) {
        return { ok: true, dryRun: true, address, wouldWrite: instructions.join('; '), before: snapshot, disasmWindow: hexDump(beforeBytes, address) }
      }

      const blocked = gate('patch')
      if (blocked) return { ok: false, ...blocked, before: snapshot }

      await b.invoke('patchAsm', { addr: address, instructions: instructions.join(';') })
      const { disasm: afterDisasm } = await disasmOf(b, address)
      const afterLines = linesAt(afterDisasm, address, instructions.length + 3)
      const afterBytes = await b.invoke('readBytes', { addr: address, size: 32 })

      const record = {
        id: `patch-${Date.now().toString(36)}`,
        ts: new Date().toISOString(),
        address,
        function: fn.name,
        instructions,
        note: args.note || null,
        before: snapshot,
        after: {
          lines: afterLines.map((line) => `${normAddr(line.address)}  ${String(line.instruction || '').trim()}`),
          bytes: byteString(afterBytes),
        },
        status: 'applied',
      }
      ws.appendLedger(record)
      ws.note('patch', `${address} ${instructions.join('; ')}${args.note ? ` — ${args.note}` : ''}`)

      return {
        ok: true,
        id: record.id,
        address,
        before: { disasm: snapshot.lines, bytes: snapshot.bytes },
        after: { disasm: record.after.lines, bytes: record.after.bytes },
        changed: snapshot.bytes !== record.after.bytes,
        rollbackWith: `ida_patch({ address: "${address}", rollback: "${record.id}" })`,
      }
    },
  })

  // ---------------------------------------------------------------- 工作区
  tools.push({
    name: 'ida_workspace',
    description:
      '读写这个 IDB 的分析工作区（%LOCALAPPDATA%\\dsh-ida\\<key>\\）：命名表、注释镜像、函数小结、分析日志。' +
      '会话断了、模型换了，靠它接着做——ida_func 会自动把这里的记录带出来。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['get', 'put', 'note', 'list'],
          description: 'get 读 / put 写结构化记录 / note 追加一条日志 / list 列出磁盘上所有工作区（不需要 IDA）',
        },
        key: { type: 'string', description: '离线时选哪个工作区（目录名，如 Reverse02-16fe332723）；不传则取最近更新的一个' },
        names: {
          type: 'array',
          description: 'put 时写入命名表',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string' },
              name: { type: 'string' },
              note: { type: 'string', description: '为什么叫这个名字' },
            },
            required: ['address', 'name'],
            additionalProperties: false,
          },
        },
        comments: {
          type: 'array',
          description: 'put 时写入注释镜像',
          items: {
            type: 'object',
            properties: { address: { type: 'string' }, text: { type: 'string' }, func: { type: 'string' } },
            required: ['address', 'text'],
            additionalProperties: false,
          },
        },
        funcs: {
          type: 'array',
          description: 'put 时写入函数小结（模型自己的结论，不属于 IDB）',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string' },
              name: { type: 'string' },
              summary: { type: 'string' },
              status: { type: 'string', description: '例如 analyzed / partial / stuck' },
            },
            required: ['address'],
            additionalProperties: false,
          },
        },
        note: { type: 'string', description: 'action=note 时的日志正文，或 put 时的整体备注' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderWorkspace(value)) },
    async execute (args = {}) {
      const key = args.key ? String(args.key) : null
      const all = () => Workspace.list({ dir: runtime.config.dir })

      if (args.action === 'list') {
        let current = null
        let online = false
        try {
          const connected = await context()
          current = connected?.ws?.key || null
          online = true
        } catch { /* IDA 没开也要能列 */ }
        const items = all()
        return {
          ok: true,
          online,
          offline: !online,
          current,
          total: items.length,
          workspaces: items,
          hint: '读某个工作区：ida_workspace({ action: "get", key: "<key>" })。IDA 没开也能读，记录就在本地。',
        }
      }

      let ws = null
      let meta = null
      let offline = false
      let warning = null
      try {
        const connected = await context()
        ws = connected.ws
        meta = connected.meta
      } catch (error) {
        offline = true
        const items = all()
        if (!items.length) {
          return {
            ok: false,
            offline: true,
            reason: '连不上 IDA，本地也没有历史工作区（%LOCALAPPDATA%\\dsh-ida 下没有 state.json）。',
            error: error.message,
            hint: '先开 IDA 并调一次 ida_status，工作区会从那里建出来。',
          }
        }
        let chosen = null
        if (key) {
          chosen = items.find((item) => item.key === key) || null
          if (!chosen) {
            return {
              ok: false,
              offline: true,
              reason: `没有 key=${key} 的工作区。`,
              available: items.map((item) => item.key),
              hint: 'ida_workspace({ action: "list" }) 看全部。',
            }
          }
        } else if (items.length === 1) {
          chosen = items[0]
        } else {
          chosen = items[0]
          warning = `本地有 ${items.length} 个工作区，没指定 key，先读最近更新的 ${chosen.key}；要换就传 key。`
        }
        ws = Workspace.fromDir(chosen.dir)
        meta = chosen.meta || null
      }

      const base = offline
        ? {
            offline: true,
            workspaceDir: ws.dir,
            warning: warning || `IDA 没开，读的是本地记录（${ws.dir}）。写入照样落盘，下次连上 IDA 后 ida_func 会带出来。`,
          }
        : {}

      if (!ws) return { ok: false, reason: '还没有工作区（先 ida_status 建立一次）' }
      if (args.action === 'get') {
        return {
          ok: true,
          ...base,
          summary: ws.summary({ journalLimit: 20 }),
          ledger: ws.readLedger(10),
          idb: meta,
        }
      }
      if (args.action === 'note') {
        if (!args.note) return { ok: false, reason: 'action=note 需要 note 字段' }
        ws.note('manual', String(args.note))
        return { ok: true, ...base, summary: ws.summary() }
      }
      let written = 0
      for (const entry of toArray(args.names)) {
        if (!entry?.address || !entry?.name) continue
        ws.rename(normAddr(entry.address), String(entry.name), { note: entry.note || null })
        written += 1
      }
      for (const entry of toArray(args.comments)) {
        if (!entry?.address || !entry?.text) continue
        ws.comment(normAddr(entry.address), String(entry.text), entry.func || null)
        written += 1
      }
      for (const entry of toArray(args.funcs)) {
        if (!entry?.address) continue
        ws.setFunc(normAddr(entry.address), {
          name: entry.name || null,
          summary: entry.summary || null,
          status: entry.status || null,
        })
        written += 1
      }
      if (args.note) ws.note('put', String(args.note))
      return { ok: written > 0, ...base, written, summary: ws.summary() }
    },
  })

  // ---------------------------------------------------------------- 导出重构稿
  tools.push({
    name: 'ida_export',
    description:
      '把当前分析导出成一份 markdown 重构稿（伪代码 + 地址 + 已有注释 + 工作区命名表）。' +
      '默认落到会话当前目录的 dsh-ida-export/ 下并返回路径；inline:true 时连正文一起返回，' +
      'write:false 则只返回正文不落盘。适合做「算法伪代码优化」：IDA 里的伪代码回写不了，' +
      '但可以在这里产出一份人能读、能 diff 的整理稿。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: '只导出某个函数；不传就导出当前工作区总览' },
        maxLines: { type: 'number', description: '伪代码行数上限，默认 600' },
        write: { type: 'boolean', description: '是否落盘，默认 true；false 等同于 inline:true 且不写文件' },
        inline: { type: 'boolean', description: '把 markdown 正文直接返回（默认在 write:false 时自动为 true）' },
        dir: { type: 'string', description: '输出目录，默认 <当前工作目录>/dsh-ida-export' },
        path: { type: 'string', description: '完整输出路径（.md）或目录，优先级高于 dir' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderExport(value)) },
    async execute (args = {}) {
      const { bridge: b, ws, meta } = await context()
      const lines = []
      lines.push(`# IDA 分析稿 — ${meta?.module || 'unknown'}`)
      lines.push('')
      lines.push(`- 数据库：\`${meta?.path || '?'}\``)
      lines.push(`- 基址：${meta?.base || '?'}　大小：${meta?.size || '?'}　sha256：\`${(meta?.sha256 || '').slice(0, 16)}…\``)
      lines.push(`- 生成时间：${new Date().toISOString()}`)
      lines.push('')

      const names = ws?.state.names || {}
      const nameEntries = Object.entries(names)
      if (nameEntries.length) {
        lines.push('## 命名表')
        lines.push('')
        lines.push('| 地址 | 名字 | 依据 |')
        lines.push('| --- | --- | --- |')
        for (const [addr, info] of nameEntries) {
          lines.push(`| \`${addr}\` | \`${info.name}\` | ${(info.note || '').replace(/\|/g, '\\|')} |`)
        }
        lines.push('')
      }

      const funcs = ws?.state.funcs || {}
      if (Object.keys(funcs).length) {
        lines.push('## 函数结论')
        lines.push('')
        for (const [addr, info] of Object.entries(funcs)) {
          lines.push(`- \`${addr}\` **${info.name || '?'}**${info.status ? ` (${info.status})` : ''}：${info.summary || ''}`)
        }
        lines.push('')
      }

      if (args.target) {
        const fn = await resolveFunction(b, args.target)
        const maxLines = Number(args.maxLines) > 0 ? Number(args.maxLines) : 600
        const pseudo = renderPseudocode(await b.invoke('decompile', { addr: fn.address }), { maxLines })
        const comments = Object.entries(ws?.state.comments || {})
          .filter(([, info]) => !info.func || info.func === fn.name || info.func === fn.address)
        lines.push(`## ${fn.name} @ ${fn.address}`)
        lines.push('')
        if (fn.prototype) {
          lines.push('```c')
          lines.push(fn.prototype)
          lines.push('```')
          lines.push('')
        }
        if (comments.length) {
          lines.push('已知注释：')
          for (const [addr, info] of comments) lines.push(`- \`${addr}\`：${info.text}`)
          lines.push('')
        }
        lines.push('```c')
        lines.push(pseudo.text)
        lines.push('```')
        lines.push('')
      }

      const markdown = lines.join('\n')
      const bytes = Buffer.byteLength(markdown)
      const inline = args.inline === true || args.write === false
      if (args.write === false) {
        return { ok: true, inline: true, markdown, bytes, written: false }
      }
      const target = resolveExportTarget(args)
      writeFileSync(target.file, markdown, 'utf8')
      ws.note('export', target.file)
      return {
        ok: true,
        path: target.file,
        dir: target.dir,
        bytes,
        written: true,
        inline,
        markdown: inline ? markdown : undefined,
      }
    },
  })

  // ---------------------------------------------------------------- 查找
  tools.push({
    name: 'ida_find',
    description:
      '定位用：按名字子串找函数 / 字符串 / 全局变量，或看导入表、入口点。不返回伪代码。' +
      'kind 接受 func|string|global|import|entry（写复数、functions、globals 也认）。' +
      'pattern 支持子串（不区分大小写）、/正则/、以及地址；kind=string 时可带出引用它的函数。',
    parameters: {
      type: 'object',
      properties: {
        kind: { type: 'string', enum: ['func', 'string', 'global', 'import', 'entry'], description: '找什么；单复数都接受' },
        pattern: {
          type: 'string',
          description: '名字子串（不区分大小写）/ 正则（写成 /re/）/ 地址（0x403028）。' +
            '找全局变量时传地址会反查它的名字。',
        },
        limit: { type: 'number', description: '最多返回多少条，默认 30' },
        offset: { type: 'number', description: '分页起点，默认 0' },
        xrefs: { type: 'boolean', description: 'kind=string 时是否带出引用它的函数，默认 true（最多解析 10 条）' },
      },
      required: ['kind'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderFind(value)) },
    async execute (args = {}) {
      const { bridge: b } = await context({ needWorkspace: false })
      const limit = Number(args.limit) > 0 ? Number(args.limit) : 30
      const offset = Number(args.offset) > 0 ? Number(args.offset) : 0
      const pattern = String(args.pattern ?? '').trim()
      const kind = normalizeFindKind(args.kind)
      if (!kind) {
        return {
          ok: false,
          reason: `不认识的 kind：${args.kind}`,
          kinds: ['func', 'string', 'global', 'import', 'entry'],
          hint: '写 funcs / globals / strings 这类复数形式也可以。',
        }
      }

      const matcher = buildMatcher(pattern)

      if (kind === 'entry') {
        const entries = await b.invoke('entryPoints')
        return { ok: true, kind, total: entries?.length ?? 0, items: (entries || []).slice(0, limit) }
      }

      if (kind === 'import') {
        const page = await b.invoke('imports', { offset: 0, count: 4000 })
        const items = (page?.data || []).filter((item) => matcher(String(item.imported_name || item.name || '')))
        return { ok: true, kind, total: items.length, items: items.slice(offset, offset + limit) }
      }

      if (kind === 'string') {
        const page = await scanList(b, 'strings', { offset, limit, matcher, text: pattern })
        const items = page.items
        const wantXrefs = args.xrefs !== false && items.length <= 10
        if (wantXrefs) {
          for (const item of items) {
            try {
              const xrefs = await b.invoke('xrefsTo', { addr: item.address })
              const names = [...new Set((Array.isArray(xrefs) ? xrefs : [])
                .map((xref) => xref.function?.name || null)
                .filter(Boolean))]
              if (names.length) item.referencedBy = names.slice(0, 6)
              item.xrefCount = Array.isArray(xrefs) ? xrefs.length : 0
            } catch {
              // 引用查不到不影响主结果
            }
          }
        }
        return { ok: true, kind, total: page.total, items, scanned: page.scanned, nextOffset: page.nextOffset }
      }

      if (kind === 'global') {
        // 传地址就反查名字：这是最常被问的一句「0x403028 到底叫什么」
        if (isExplicitAddress(pattern)) {
          const addr = normAddr(pattern)
          const found = await lookupGlobalName(b, addr)
          return {
            ok: true,
            kind,
            address: addr,
            total: found.name ? 1 : 0,
            items: found.name ? [{ address: addr, name: found.name }] : [],
            via: found.via,
            hint: found.name
              ? null
              : `${addr} 确实没有名字（未命名数据，或落在某个数据项中间）。` +
                `要读它的内容用 ida_data({ action: "read", address: "${addr}" })；` +
                `如果记得名字的一部分，用 ida_find({ kind: "global", pattern: "<名字片段>" }) 反而更快。`,
          }
        }
        const page = await scanList(b, 'globals', { offset, limit, matcher, text: pattern })
        return {
          ok: true,
          kind,
          total: page.total,
          items: page.items,
          scanned: page.scanned,
          nextOffset: page.nextOffset,
          hint: page.items.length
            ? null
            : `没有名字包含「${pattern}」的全局变量。` +
              '这里做的是名字子串匹配（不区分大小写），不认地址：要按地址查请直接传 0x403028 这种写法。' +
              '如果确定它存在，试试更短的片段（如 403028 里的 4030）。',
        }
      }

      // func：显式地址直接查；否则先按名字扫，零命中再退回地址（4030 这种手写数值也认）
      if (isExplicitAddress(pattern)) {
        const fn = await resolveFunction(b, pattern)
        return { ok: true, kind: 'func', total: 1, items: [fn] }
      }
      const page = await scanList(b, 'funcs', { offset, limit, matcher, text: pattern })
      if (!page.items.length && isAddressLike(pattern)) {
        try {
          const fn = await resolveFunction(b, pattern)
          return { ok: true, kind: 'func', total: 1, items: [fn], hint: `没有函数名包含 ${pattern}，按地址解析成了 ${fn.name}。` }
        } catch {
          // 名字和地址都不是，就返回空结果
        }
      }
      return { ok: true, kind: 'func', total: page.total, items: page.items, scanned: page.scanned, nextOffset: page.nextOffset }
    },
  })

  // ---------------------------------------------------------------- 地址换算
  tools.push({
    name: 'ida_addr',
    description:
      'IDA 静态地址与运行时地址互换。IDA 里看到的是文件基址视角，Cheat Engine / 调试器里看到的是' +
      '模块实际加载基址视角，patch 前先用它对齐，别把断点下错地方。',
    parameters: {
      type: 'object',
      properties: {
        addresses: { type: 'array', items: { type: 'string' }, description: '要换算的地址列表' },
        runtimeBase: { type: 'string', description: '目标进程里该模块的实际基址，如 0x7ff6a1230000' },
        toIda: { type: 'boolean', description: '反向：把运行时地址换算回 IDA 地址' },
      },
      required: ['addresses'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderAddr(value)) },
    async execute (args = {}) {
      const { meta } = await context({ needWorkspace: false })
      const idbBase = hexToInt(meta?.base)
      const targetBase = hexToInt(args.runtimeBase)
      const delta = targetBase !== null && idbBase !== null ? targetBase - idbBase : 0
      const items = toArray(args.addresses).map((input) => {
        const value = hexToInt(input)
        if (value === null) return { input: String(input), ok: false, reason: '不是合法地址' }
        const mapped = args.toIda === true ? value - delta : value + delta
        return {
          ida: intToHex(args.toIda === true ? mapped : value),
          runtime: intToHex(args.toIda === true ? value : mapped),
          offset: idbBase !== null ? intToHex(value - idbBase) : null,
        }
      })
      return {
        ok: true,
        module: meta?.module || null,
        idbBase: meta?.base || null,
        runtimeBase: args.runtimeBase ? normAddr(args.runtimeBase) : null,
        delta: delta ? intToHex(delta) : null,
        items,
        hint: args.runtimeBase ? null : '没给 runtimeBase，返回的是「模块内偏移」视角；要换算成实际运行时地址请补上目标进程的模块基址。',
      }
    },
  })

  // ---------------------------------------------------------------- 数据层
  tools.push({
    name: 'ida_data',
    description:
      '数据层操作：读内存字节、全局变量（取值/改名/改类型）、结构体（列表/详情/某地址字段值）、' +
      '栈帧变量（列表/改名/新建/改类型/删除）、本地类型表。' +
      '这些能力不补的话，模型连读 13 个字节都得跑出 IDB 自己解 PE 头。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'read', 'globalValue', 'renameGlobal', 'setGlobalType', 'declareType',
            'structs', 'struct', 'structAt', 'localTypes',
            'stack', 'renameStack', 'createStack', 'setStackType', 'deleteStack',
          ],
          description: 'read=读字节 / globalValue=全局变量取值 / renameGlobal=全局改名 / setGlobalType=全局改类型 / ' +
            'declareType=声明或重定义结构体（改成员名也走它）/ ' +
            'structs=结构体列表 / struct=结构体详情 / structAt=某地址上的结构体字段值 / localTypes=本地类型表 / ' +
            'stack=栈帧变量 / renameStack / createStack / setStackType / deleteStack',
        },
        address: { type: 'string', description: 'read / structAt / renameGlobal / stack 等需要的地址' },
        size: { type: 'number', description: 'read 时读多少字节，默认 16；structAt 忽略' },
        name: { type: 'string', description: '全局变量名（如 byte_403028）或结构体名；给地址也行，会自动反查名字' },
        newName: { type: 'string', description: 'renameGlobal 的新名字' },
        type: { type: 'string', description: 'setGlobalType / createStack / setStackType 的类型，如 unsigned char[13]、DWORD、cfg_header' },
        struct: { type: 'string', description: 'structAt 的结构体名' },
        func: { type: 'string', description: 'stack 类操作用的函数（名字或地址）；也可以直接用 address' },
        variable: { type: 'string', description: '栈帧变量名（renameStack 的旧名 / createStack 的新名 / setStackType、deleteStack 的目标）' },
        offset: { type: 'string', description: 'createStack 的栈偏移，如 -0x18' },
        filter: { type: 'string', description: 'structs 时的名字过滤，子串或 /正则/' },
        limit: { type: 'number', description: '最多返回多少条，默认 30' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => (value?.dump ? text(renderDataDump(value)) : asJson(trimPayload(value))),
    },
    async execute (args = {}) {
      const { bridge: b } = await context({ needWorkspace: false })
      const action = String(args.action || '').trim()
      const limit = Number(args.limit) > 0 ? Number(args.limit) : 30
      const matcher = buildMatcher(String(args.filter || ''))

      const needGate = ['renameGlobal', 'setGlobalType', 'declareType', 'renameStack', 'createStack', 'setStackType', 'deleteStack']
      if (needGate.includes(action)) {
        const blocked = gate('annotate')
        if (blocked) return { ok: false, action, ...blocked }
      }

      if (action === 'read') {
        const address = normAddr(args.address)
        if (!address) return { ok: false, action, reason: 'read 需要 address' }
        const size = Number(args.size) > 0 ? Math.min(Number(args.size), 4096) : 16
        const bytes = await b.invoke('readBytes', { addr: address, size })
        const name = await nameAtAddress(b, address).catch(() => null)
        let globalValue = null
        try { globalValue = await b.invoke('globalAt', { addr: address }) } catch { /* 不是命名数据就算了 */ }
        return {
          ok: true,
          action,
          address,
          size,
          name,
          bytes: byteString(bytes),
          globalValue,
          dump: hexDump(bytes, address),
        }
      }

      if (action === 'globalValue') {
        if (args.address) {
          const address = normAddr(args.address)
          const name = await nameAtAddress(b, address).catch(() => null)
          let value = null
          let via = 'address'
          let error = null
          try {
            value = await b.invoke('globalAt', { addr: address })
          } catch (err) {
            error = err.message
            // 0x403018 这种地址，服务端「按地址」取类型会失败，但同一个变量
            // 「按名字」是能取到的（IDA 里两条路走的不是同一段代码）。别在第一步就放弃。
            if (name) {
              try {
                value = await b.invoke('globalByName', { variable: name })
                via = 'name'
                error = null
              } catch (second) {
                error = `${error}；按名字 ${name} 再取也失败：${second.message}`
              }
            }
          }
          if (error) {
            // 最后退一步：直接读字节，至少让模型知道这里有什么
            let fallback = null
            try {
              fallback = byteString(await b.invoke('readBytes', { addr: address, size: 8 }))
            } catch { /* 读不了就算了，把原始错误带回去 */ }
            return {
              ok: true,
              action,
              address,
              name,
              value: null,
              via: null,
              error,
              fallbackBytes: fallback,
              hint: fallback
                ? '取不到声明类型的值，fallbackBytes 是按地址原样读的 8 字节（小端）。'
                : '取不到值。先用 ida_data({ action: "read" }) 看原始字节，或者确认这个地址确实是数据的起始位置。',
            }
          }
          return { ok: true, action, address, name, value, via }
        }
        if (!args.name) return { ok: false, action, reason: 'globalValue 需要 name 或 address' }
        const name = await resolveGlobalName(b, args.name)
        return { ok: true, action, name, value: await b.invoke('globalByName', { variable: name }) }
      }

      if (action === 'renameGlobal') {
        if (!args.newName) return { ok: false, action, reason: 'renameGlobal 需要 newName' }
        const oldName = await resolveGlobalName(b, args.name || args.address)
        if (!oldName) return { ok: false, action, reason: `${args.name || args.address} 在 IDA 命名表里不存在（未命名的数据没法按名字改）` }
        await b.invoke('renameGlobal', { from: oldName, to: String(args.newName) })
        runtime.globalIndex = null
        // 回读：新名字能被解析到地址才算真的写进去了
        let verified = null
        try {
          const addr = await nameAtAddress(b, String(args.name && isAddressLike(args.name) ? args.name : ''))
          verified = addr
        } catch { /* 忽略 */ }
        try {
          runtime.workspace?.note('data', `${oldName} → ${args.newName}`)
        } catch { /* 工作区没准备好 */ }
        return { ok: true, action, from: oldName, name: String(args.newName), verifiedAddress: verified }
      }

      if (action === 'setGlobalType') {
        if (!args.type) return { ok: false, action, reason: 'setGlobalType 需要 type' }
        const name = await resolveGlobalName(b, args.name || args.address)
        if (!name) return { ok: false, action, reason: `${args.name || args.address} 不存在` }
        await b.invoke('setGlobalType', { variable: name, type: String(args.type) })
        return { ok: true, action, name, type: String(args.type) }
      }

      if (action === 'declareType') {
        const declaration = String(args.type || args.name || '').trim()
        if (!declaration) return { ok: false, action, reason: 'declareType 需要 type：完整的 C 声明，如 struct cfg { int magic; unsigned short ver; };' }
        const message = await b.invoke('declareType', { declaration })
        return {
          ok: true,
          action,
          declaration,
          message: typeof message === 'string' ? message : 'success',
          hint: '同名重定义会覆盖本地类型；改结构体成员名就是这条路（IDA 没有单独 rename member 的方法）。改完用 ida_data({action:"struct"}) 复核。',
        }
      }

      if (action === 'structs') {
        const all = await b.invoke('structs')
        const list = Array.isArray(all) ? all : []
        const items = list.filter((item) => matcher(item.name)).slice(0, limit).map((item) => ({
          name: item.name,
          size: item.size,
          members: Array.isArray(item.members) ? item.members.length : null,
        }))
        return { ok: true, action, total: list.length, items }
      }

      if (action === 'struct') {
        if (!args.name) return { ok: false, action, reason: 'struct 需要 name' }
        return {
          ok: true,
          action,
          name: String(args.name),
          detail: await b.invoke('structDetail', { name: String(args.name) }),
          hint: '要改成员名：用 ida_data({ action: "declareType", type: "struct <同名> { ... };" }) 重定义，IDA 会覆盖本地类型。',
        }
      }

      if (action === 'structAt') {
        if (!args.address || !(args.struct || args.name)) return { ok: false, action, reason: 'structAt 需要 address 和 struct' }
        return {
          ok: true,
          action,
          address: normAddr(args.address),
          struct: String(args.struct || args.name),
          detail: await b.invoke('structAt', { addr: normAddr(args.address), name: String(args.struct || args.name) }),
        }
      }

      if (action === 'localTypes') {
        const all = await b.invoke('localTypes')
        const list = Array.isArray(all) ? all : []
        return { ok: true, action, total: list.length, items: list.slice(0, limit) }
      }

      // 栈帧相关：都先解析函数
      const target = args.func || args.address
      if (!target) return { ok: false, action, reason: `${action} 需要 func（函数名或地址）` }
      const fn = await resolveFunction(b, target)

      if (action === 'stack') {
        const vars = await b.invoke('stackFrame', { addr: fn.address })
        return { ok: true, action, function: fn, total: Array.isArray(vars) ? vars.length : 0, items: (vars || []).slice(0, limit) }
      }
      if (action === 'renameStack') {
        if (!args.variable || !args.newName) return { ok: false, action, reason: 'renameStack 需要 variable 和 newName' }
        await b.invoke('renameStack', { func: fn.address, from: String(args.variable), to: String(args.newName) })
        return { ok: true, action, function: fn, from: String(args.variable), name: String(args.newName) }
      }
      if (action === 'createStack') {
        if (!args.offset || !args.variable || !args.type) return { ok: false, action, reason: 'createStack 需要 offset、variable、type' }
        await b.invoke('createStack', { func: fn.address, offset: normAddr(args.offset), variable: String(args.variable), type: String(args.type) })
        return { ok: true, action, function: fn, offset: normAddr(args.offset), variable: String(args.variable), type: String(args.type) }
      }
      if (action === 'setStackType') {
        if (!args.variable || !args.type) return { ok: false, action, reason: 'setStackType 需要 variable 和 type' }
        await b.invoke('setStackType', { func: fn.address, variable: String(args.variable), type: String(args.type) })
        return { ok: true, action, function: fn, variable: String(args.variable), type: String(args.type) }
      }
      if (action === 'deleteStack') {
        if (!args.variable) return { ok: false, action, reason: 'deleteStack 需要 variable' }
        await b.invoke('deleteStack', { func: fn.address, variable: String(args.variable) })
        return { ok: true, action, function: fn, deleted: String(args.variable) }
      }

      return {
        ok: false,
        action,
        reason: `不认识的 action：${action}`,
        actions: ['read', 'globalValue', 'renameGlobal', 'setGlobalType', 'structs', 'struct', 'structAt', 'localTypes', 'stack', 'renameStack', 'createStack', 'setStackType', 'deleteStack'],
      }
    },
  })

  // ---------------------------------------------------------------- 能力自曝
  tools.push({
    name: 'ida_methods',
    description:
      '列出 IDA 侧真实可用的方法及其签名，用来替代「猜方法名」。' +
      '旧协议 59 个方法全部列出（标注可写/unsafe），标准 MCP 则列出 tools/list 的结果。' +
      '找数据层能力、调试能力、类型能力之前先调它，比试错三次快。',
    parameters: {
      type: 'object',
      properties: {
        filter: { type: 'string', description: '按名字过滤，子串或 /正则/，如 byte、struct、dbg' },
        write: { type: 'boolean', description: '只看会写库的方法' },
        unsafe: { type: 'boolean', description: '只看被作者标成 unsafe 的方法（调试器类）' },
        limit: { type: 'number', description: '最多返回多少条，默认 80' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => text(renderMethods(value)) },
    async execute (args = {}) {
      const b = bridge()
      let mode = null
      let toolNames = null
      try {
        await b.connect()
        mode = b.mode
        toolNames = b.toolNames
      } catch (error) {
        return { ok: false, reason: `连不上 IDA：${error.message}`, hint: CONNECT_HINT }
      }
      const limit = Number(args.limit) > 0 ? Number(args.limit) : 80
      const filter = String(args.filter || '')
      const matcher = buildMatcher(filter)

      if (mode === 'mcp' && Array.isArray(toolNames)) {
        const items = toolNames
          .filter((name) => matcher(name))
          .slice(0, limit)
          .map((name) => ({ name }))
        return { ok: true, mode, total: toolNames.length, items, hint: '标准 MCP 只有工具名，没有参数签名；参数形态用 tools/list 的结果或直接试。' }
      }

      const items = LEGACY_METHODS
        .filter((method) => (args.write === true ? method.write : true))
        .filter((method) => (args.unsafe === true ? method.unsafe : true))
        .filter((method) => matcher(method.name) || matcher(method.doc))
        .slice(0, limit)
        .map((method) => ({
          name: method.name,
          signature: formatSignature(method),
          write: method.write,
          unsafe: method.unsafe,
          doc: method.doc,
        }))
      return {
        ok: true,
        mode,
        total: LEGACY_METHODS.length,
        items,
        hint: items.length ? '这些都能用 ida_raw({ method, params }) 直接调，params 可以传对象（键名照签名）或数组。' : '没匹配到。去掉 filter 看全表。',
      }
    },
  })

  // ---------------------------------------------------------------- 逃生舱
  tools.push({
    name: 'ida_raw',
    description:
      '直接调 IDA 侧的原始方法，覆盖 ida_func / ida_annotate / ida_data 没包的能力。' +
      'params 可以传对象（键名照签名，推荐）或数组（按位置）。' +
      '方法名拼错会给出最接近的候选，不确定就先调 ida_methods。' +
      'unsafe 方法（dbg_*）需要 allow=patch。',
    parameters: {
      type: 'object',
      properties: {
        method: { type: 'string', description: '方法名，如 get_stack_frame_variables；常见别名（get_bytes / set_name / get_structs）会自动纠正' },
        params: { description: '参数：对象（按签名键名）或数组（按位置）' },
        timeoutMs: { type: 'number', description: '超时，默认用全局设置' },
      },
      required: ['method'],
      additionalProperties: false,
    },
    output: { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => asJson(trimPayload(value)) },
    async execute (args = {}) {
      const b = bridge()
      await b.connect()
      const options = Number(args.timeoutMs) > 0 ? { timeoutMs: Number(args.timeoutMs) } : {}
      const input = String(args.method || '').trim()

      if (b.mode !== 'legacy') {
        // 标准 MCP：直接 tools/call，方法名错了就报错并给候选
        const argsObject = Array.isArray(args.params) ? arrayToObject(args.params) : (args.params || {})
        if (Array.isArray(b.toolNames) && !b.toolNames.includes(input)) {
          const suggestion = suggestFrom(input, b.toolNames)
          return {
            ok: false,
            method: input,
            reason: `这个 MCP 服务器没有 ${input}`,
            candidates: suggestion,
            hint: `调 ida_methods 看全部 ${b.toolNames.length} 个工具。`,
          }
        }
        const result = await b.callTool(input, argsObject, options)
        try { runtime.workspace?.note('raw', input) } catch { /* 工作区没准备好不影响结果 */ }
        return { ok: true, method: input, mode: b.mode, result: wrapScalar(jsonSafe(result)) }
      }

      const resolved = resolveMethodName(input)
      if (!resolved.method) {
        return {
          ok: false,
          method: input,
          reason: resolved.candidates.length
            ? `没有 ${input} 这个方法。最接近的：${resolved.candidates.join(', ')}`
            : `没有 ${input} 这个方法。`,
          candidates: resolved.candidates.map((name) => {
            const method = LEGACY_METHODS.find((item) => item.name === name)
            return method ? formatSignature(method) : name
          }),
          hint: '调 ida_methods（不传 filter）看全部 59 个方法。',
        }
      }

      const method = resolved.method
      if (method.unsafe) {
        const blocked = gate('patch')
        if (blocked) {
          return {
            ok: false,
            method: method.name,
            reason: `${method.name} 被插件作者标成 unsafe（调试器/进程控制），当前 allow=${runtime.config.allow} 不够。`,
            how: blocked.how,
          }
        }
      }

      const problem = assembleParams(method, args.params)
      if (problem.missing.length) {
        return {
          ok: false,
          method: method.name,
          reason: describeParamProblem(method, problem),
          expected: formatSignature(method),
        }
      }

      const named = args.params && !Array.isArray(args.params)
      const payload = named ? problem.named : problem.positional
      let result
      try {
        result = await b.rpc(method.name, payload, options)
      } catch (error) {
        if (error.code === -32601) {
          const suggestion = suggestMethods(input)
          return {
            ok: false,
            method: input,
            reason: error.message,
            candidates: suggestion,
            hint: '这个插件版本可能没有该方法；调 ida_methods 确认真实名字。',
          }
        }
        // 参数个数/键名的问题：换另一种形态再试一次。旧协议对 dict 的键集合卡得很死，
        // 但我们两种都发得起，成功率高不少。
        const alternate = named ? problem.positional : problem.named
        if (error.code === -32602 && alternate) {
          try {
            result = await b.rpc(method.name, alternate, options)
          } catch (second) {
            return {
              ok: false,
              method: method.name,
              reason: second.message,
              expected: formatSignature(method),
              hint: '旧协议要求参数个数（或键集合）和签名完全一致。照 expected 检查一次。',
            }
          }
        } else {
          return {
            ok: false,
            method: method.name,
            reason: error.message,
            expected: formatSignature(method),
            data: error.data ?? null,
          }
        }
      }

      try { runtime.workspace?.note('raw', method.name) } catch { /* 同上 */ }
      return {
        ok: true,
        method: method.name,
        via: resolved.via,
        signature: formatSignature(method),
        ignored: problem.unknown.length ? problem.unknown : undefined,
        mode: b.mode,
        result: wrapScalar(jsonSafe(result)),
      }
    },
  })

  for (const tool of tools) ctx.effect(() => ctx.tools.register(tool))
}

// ------------------------------------------------------------------ 内部工具

function toArray (value) {
  if (Array.isArray(value)) return value
  if (value === null || value === undefined || value === '') return []
  return [value]
}

/** 标准 MCP 的工具名纠错。 */
function suggestFrom (input, names) {
  return rankNames(input, names || [], 5)
}

function arrayToObject (params) {
  const out = {}
  params.forEach((value, index) => {
    out[`arg${index}`] = value
  })
  return out
}

/**
 * 导出位置：显式 path > dir 参数 > 配置 outDir。
 * 不再默认写进 LOCALAPPDATA —— 那里和会话工作区是两个世界，每次导出都得跨盘拷。
 */
function resolveExportTarget (args = {}) {
  const base = runtime.config.outDir || process.cwd()
  let dir = base
  let file = null

  const explicit = args.path ? String(args.path) : ''
  const dirArg = args.dir ? String(args.dir) : ''

  if (explicit) {
    const abs = isAbsolute(explicit) ? explicit : resolvePath(base, explicit)
    const looksLikeDir = extname(abs).toLowerCase() !== '.md' && (() => {
      try { return statSync(abs).isDirectory() } catch { return true }
    })()
    if (looksLikeDir) dir = abs
    else { file = abs; dir = dirname(abs) }
  } else if (dirArg) {
    dir = isAbsolute(dirArg) ? dirArg : resolvePath(base, dirArg)
  } else {
    dir = join(base, 'dsh-ida-export')
  }

  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  if (!file) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    const name = String(args.target || 'workspace').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40) || 'workspace'
    file = join(dir, `${name}-${stamp}.md`)
  }
  return { dir, file }
}

async function verifyAnnotations (b, fn, args, applied) {
  const verified = { name: null, comments: [] }
  if (!applied.some((item) => item.ok)) return verified
  try {
    const after = normalizeFunction(await b.invoke('funcByAddr', { addr: fn.address }))
    verified.name = after.name
    if (args.rename && after.name !== args.rename) {
      verified.nameMismatch = `期望 ${args.rename}，实际 ${after.name}`
    }
  } catch (error) {
    verified.nameError = error.message
  }
  if (args.prototype) {
    try {
      const asm = renderAsm(await b.invoke('disasm', { addr: fn.address }))
      if (asm.prototype) {
        verified.prototype = asm.prototype
        const wantedParams = prototypeParams(args.prototype)
        const actualParams = prototypeParams(asm.prototype)
        if (wantedParams && actualParams && wantedParams !== actualParams) {
          verified.prototypeMismatch = `期望参数 (${wantedParams})，反汇编读回 (${actualParams})`
        }
      }
    } catch (error) {
      verified.prototypeError = error.message
    }
  }
  const wanted = toArray(args.comments).filter((item) => item?.address && item?.text)
  if (wanted.length) {
    try {
      const disasm = await b.invoke('disasm', { addr: fn.address })
      const byAddr = new Map()
      for (const line of disasm?.lines || []) byAddr.set(normAddr(line.address), line)
      for (const item of wanted) {
        const addr = normAddr(item.address)
        const line = byAddr.get(addr)
        const existing = Array.isArray(line?.comments) ? line.comments.map(String) : []
        const needle = String(item.text).slice(0, 16)
        verified.comments.push({
          address: addr,
          found: existing.some((entry) => entry.includes(needle)),
          comments: existing,
        })
      }
    } catch (error) {
      verified.commentError = error.message
    }
  }
  return verified
}

/** 旧插件的 Function 结构只有 address/name/size，原型得从伪代码首行猜。 */
function guessPrototype (raw) {
  for (const entry of addressMap(raw).slice(0, 3)) {
    const code = entry.code
    if (code.includes('(') && code.includes(')') && !code.includes('=') && !code.includes(';')) return code
  }
  return null
}

/**
 * Hex-Rays 伪代码里的类型名不是 C 类型名。
 * `_BYTE` / `_DWORD` 只存在于反编译器的伪代码输出里，IDA 的 tinfo_t 解析器不认，
 * 于是 set_function_prototype 会把一整句判成「解析失败」。这是原型 100% 失败的主因之一。
 */
const HEXRAYS_TYPE_NAMES = {
  _BYTE: 'unsigned char',
  _WORD: 'unsigned short',
  _DWORD: 'unsigned int',
  _QWORD: 'unsigned __int64',
  _OWORD: 'unsigned __int128',
  _UNKNOWN: 'void',
  _BOOL1: 'unsigned char',
  _BOOL2: 'unsigned short',
  _BOOL4: 'int',
  _BOOL8: 'unsigned __int64',
}

const CALLING_CONVENTIONS = new Set([
  '__cdecl', '__stdcall', '__fastcall', '__thiscall', '__usercall', '__vectorcall', '__pascal', '__hidden',
])

function normalizeTypeNames (text) {
  let out = String(text)
  for (const [from, to] of Object.entries(HEXRAYS_TYPE_NAMES)) {
    out = out.replace(new RegExp(`\\b${from}\\b`, 'g'), to)
  }
  return out
}

/** `int __cdecl f(char *x)` → `int __cdecl (char *x)`；tinfo_t 要的是类型，不是带名字的声明。 */
function stripFunctionName (proto) {
  const open = proto.indexOf('(')
  if (open < 0) return proto
  const prefix = proto.slice(0, open).trim()
  const tokens = prefix.split(/\s+/)
  if (tokens.length < 2) return proto
  const last = tokens[tokens.length - 1]
  if (CALLING_CONVENTIONS.has(last)) return proto
  if (last.endsWith('*')) return proto                      // 函数指针，名字在中间，别乱动
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(last)) return proto
  return `${tokens.slice(0, -1).join(' ')} ${proto.slice(open)}`.trim()
}

/**
 * 生成一串候选写法，从「最接近用户原话」到「最保守」依次试。
 * 顺序有讲究：先原样，再改类型名，再拆名字 —— 这样成功的那条能反推出
 * 用户到底踩了哪个坑，回执里可以明确告诉他。
 */
function prototypeVariants (input) {
  const original = String(input || '').trim().replace(/;$/, '')
  const normalized = normalizeTypeNames(original)
  const strippedNormalized = stripFunctionName(normalized)
  const strippedOriginal = stripFunctionName(original)
  return [...new Set([original, normalized, strippedNormalized, strippedOriginal])].filter(Boolean)
}

/**
 * 只比参数类型，不比参数名 —— 反汇编读回的参数名是 IDA 自己起的（arg_0 / a1），
 * 和要求里写的名字必然不同，比名字只会制造假警报。
 */
function prototypeParams (proto) {
  const text = String(proto || '')
  const open = text.indexOf('(')
  const close = text.lastIndexOf(')')
  if (open < 0 || close <= open) return ''
  return text
    .slice(open + 1, close)
    .split(',')
    .map((piece) => {
      const tokens = normalizeTypeNames(piece)
        .replace(/\*+/g, ' * ')
        .trim()
        .replace(/\s+/g, ' ')
        .split(' ')
        .filter(Boolean)
      if (tokens.length > 1) {
        const last = tokens[tokens.length - 1]
        if (last.startsWith('*')) tokens[tokens.length - 1] = '*'
        else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(last)) tokens.pop()
      }
      return tokens.join(' ').replace(/\s*\*\s*/g, '*').trim()
    })
    .filter(Boolean)
    .join(',')
}

const PROTOTYPE_HINT = [
  'prototype 的写法 IDA 解析不了。它只吃标准 C 类型声明，常见坑：',
  '1. 不要带函数名：`int __cdecl f(char *x)` → 写成 `int __cdecl(char *x)`（插件已自动尝试去名）。',
  '2. `_BYTE`/`_DWORD`/`_QWORD` 是 Hex-Rays 伪代码里的类型名，不是 C 类型：换成 unsigned char / unsigned int / unsigned __int64。',
  '3. `HWND`/`INT_PTR`/`DWORD` 这类 Windows 别名要 IDA 加载了 mssdk 类型库才认；不确定就改成 `void *` / `unsigned int`，或者先用 types 参数 declare_c_type 定义。',
  '4. 数组参数写指针：`char *buf`。',
  '5. 参数个数要和调用点吻合，`__thiscall` 的第一个参数是 this。',
].join('\n')

function recordAnnotations (ws, fn, args, applied) {
  if (!ws) return
  const ok = applied.filter((item) => item.ok)
  if (!ok.length) return
  const funcName = args.rename ? String(args.rename) : fn.name
  if (args.rename) ws.rename(fn.address, funcName, { kind: 'func', note: args.note || null })
  for (const comment of toArray(args.comments)) {
    // func 字段记的是改名后的名字：以前记 fn.name，批量改名时注释索引指向旧符号，
    // 按函数聚合注释就会对不上。
    if (comment?.address && comment?.text) ws.comment(normAddr(comment.address), String(comment.text), funcName)
  }
  ws.setFunc(fn.address, {
    name: String(args.rename || fn.name || ''),
    summary: args.note || undefined,
    status: args.note ? 'analyzed' : undefined,
  })
  for (const global of toArray(args.globals)) {
    if (!global?.name || !global.newName) continue
    const raw = String(global.name)
    const addr = isAddressLike(raw)
      ? normAddr(raw)
      : (runtime.globalIndex?.byName.get(raw.toLowerCase()) || null)
    if (addr) ws.rename(addr, String(global.newName), { kind: 'global', note: global.type ? `类型 ${global.type}` : null })
  }
  // 名字改过之后索引就过期了，下次按地址查名字要重新扫。
  if (toArray(args.globals).some((item) => item?.newName)) runtime.globalIndex = null
  ws.note('annotate', `${fn.name || fn.address}：${ok.map((item) => item.op).join('、')}`)
}

/** 原始返回可能很大（list_functions 一次几千条），渲染时截断，结构化值仍然完整。 */
/**
 * 把任意返回值弄成可无损 JSON 化的形态。
 *
 * 上游有些方法返回的是 Python 侧的裸值（1、null、字符串）。DSH 那层对
 * 「顶层是裸标量」的返回值校验很严，会报 not lossless JSON —— 是它的锅，
 * 但把标量包成 {type, value} 就能绕过去，代价只是多一层。
 * 顺手处理 NaN / Infinity / undefined：它们 stringify 之后就丢了。
 */
function jsonSafe (value, depth = 0) {
  if (depth > 12) return '[depth limit]'
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value)
  if (typeof value === 'bigint') return value.toString()
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') return undefined
  if (Array.isArray(value)) {
    return value.map((item) => {
      const safe = jsonSafe(item, depth + 1)
      return safe === undefined ? null : safe
    })
  }
  const out = {}
  for (const [key, item] of Object.entries(value)) {
    const safe = jsonSafe(item, depth + 1)
    if (safe !== undefined) out[key] = safe
  }
  return out
}

/** 裸标量包成显式对象，避免 harness 的「顶层必须是对象」校验。 */
function wrapScalar (value) {
  if (value === null || typeof value === 'object') return value
  return { type: typeof value, value }
}

function trimPayload (value) {
  if (!value) return value
  const json = JSON.stringify(value, null, 2)
  if (json.length <= 24000) return value
  const next = {
    ...value,
    truncated: true,
    _note: `原始返回 ${json.length} 字符，已截断显示；完整内容请用 ida_methods / ida_find 分页取。`,
  }
  if (typeof value.result === 'string') {
    next.result = `${value.result.slice(0, 16000)}…`
  } else if (value.result && typeof value.result === 'object' && typeof value.result.text === 'string') {
    next.result = { ...value.result, text: `${value.result.text.slice(0, 16000)}…` }
  } else if (value.result !== undefined) {
    next.result = `${json.slice(0, 16000)}…`
  }
  return next
}

// ------------------------------------------------------------------ 人类可读的渲染

/**
 * 探一下「这台 IDA 上哪些层是死的」。
 *
 * 起因：上游插件按 IDA 9.x 的 SDK 写，8.x 上 PT_EMPTY / get_ordinal_limit 不存在，
 * 于是结构体、类型声明、栈帧变量全报 Internal error。逐个试错很费往返，
 * 一次探完就知道该打补丁还是该怀疑别的东西。
 */
async function probeCapabilities (b) {
  const out = {}
  try {
    const structs = await b.invoke('structs')
    out.structures = { ok: true, count: Array.isArray(structs) ? structs.length : 0 }
  } catch (error) {
    out.structures = { ok: false, error: error.message }
  }
  try {
    const types = await b.invoke('localTypes')
    out.localTypes = { ok: true, count: Array.isArray(types) ? types.length : 0 }
  } catch (error) {
    out.localTypes = { ok: false, error: error.message }
  }
  try {
    const entries = await b.invoke('entryPoints')
    const first = Array.isArray(entries) && entries[0] ? (entries[0].address || entries[0].start_ea) : null
    if (!first) throw new Error('没有入口点可用（文件可能还没分析完）')
    const frame = await b.invoke('stackFrame', { addr: normAddr(first) })
    out.stackFrame = { ok: true, function: normAddr(first), count: Array.isArray(frame) ? frame.length : 0 }
  } catch (error) {
    out.stackFrame = { ok: false, error: error.message }
  }

  const broken = Object.entries(out).filter(([, item]) => !item.ok).map(([key]) => key)
  const sdkIssue = broken.some((key) => /no attribute|Internal error|not supported/i.test(String(out[key].error || '')))
  out.verdict = broken.length === 0
    ? '类型层与栈帧层都可用。'
    : `这些能力在这台 IDA 上不可用：${broken.join('、')}。` +
      (sdkIssue
        ? '看着是 SDK 版本不匹配（上游按 IDA 9.x 写的）。跑 node _dev/patch-ida-plugin.mjs 打兼容补丁，然后重启 IDA。'
        : '先看具体报错；不是 SDK 问题的话，可能只是这个文件里没有结构体/入口点。')
  return out
}

function renderStatus (value) {
  if (!value?.connected) {
    return [
      `IDA 未连接 · ${value?.url || ''}`,
      value?.error ? `原因：${value.error}` : '',
      '',
      value?.hint || '',
    ].filter(Boolean).join('\n')
  }
  const bridge = value.bridge || {}
  const idb = value.idb || {}
  const ws = value.workspace || {}
  const rows = [
    `IDA 已连接 · ${bridge.mode === 'mcp' ? '标准 MCP' : '旧版 JSON-RPC'} · ${bridge.latencyMs ?? '?'}ms`,
    idb.module ? `  目标：${idb.module}　基址 ${idb.base}　大小 ${idb.size}` : '  （还没打开数据库）',
    idb.path ? `  路径：${idb.path}` : '',
    ws.key ? `  工作区：${ws.key} — ${ws.names} 个命名 / ${ws.comments} 条注释 / ${ws.funcs} 个函数结论` : '',
    ws.dir ? `  工作区目录：${ws.dir}` : '',
    `  写入权限：${value.gate}${value.allowPatch ? '（含 patch）' : ''}`,
  ]
  if (value.capabilities) {
    const caps = value.capabilities
    for (const [key, item] of Object.entries(caps)) {
      if (key === 'verdict') continue
      rows.push(item.ok
        ? `  ${key}：可用（${item.count} 项）`
        : `  ${key}：不可用 — ${item.error}`)
    }
    if (caps.verdict) rows.push(`  结论：${caps.verdict}`)
  }
  return rows.filter(Boolean).join('\n')
}

function renderFunc (value) {
  if (!value || typeof value !== 'object') return String(value ?? '')
  const fn = value.function || {}
  const pseudo = value.pseudocode || {}
  const out = []

  out.push(`${fn.name || '?'} @ ${fn.address || '?'}${fn.size ? `　size ${fn.size}` : ''}`)
  if (fn.prototype) out.push(`原型：${fn.prototype}`)

  if (value.workspace?.name || value.workspace?.note || value.workspace?.func?.summary) {
    const notes = []
    if (value.workspace.name) notes.push(`上次命名为 ${value.workspace.name}`)
    if (value.workspace.note) notes.push(value.workspace.note)
    if (value.workspace.func?.summary) notes.push(value.workspace.func.summary)
    out.push(`工作区记录：${notes.join('；')}`)
  }

  out.push('')
  out.push(`【伪代码】${pseudo.lineCount ?? 0} 行${pseudo.truncated ? '（已截断，需要全部请调大 maxLines）' : ''}　每行前缀就是该行地址，可直接作为注释锚点`)
  out.push('```c')
  out.push(pseudo.text && String(pseudo.text).trim()
    ? pseudo.text
    : '（IDA 没有返回伪代码正文。先确认地址在函数内；再用 asm:true 看反汇编。）')
  out.push('```')

  if (value.asm?.text) {
    out.push('')
    out.push(`【反汇编】${value.asm.lineCount ?? 0} 行`)
    out.push('```asm')
    out.push(value.asm.text)
    out.push('```')
  }
  if (Array.isArray(value.asm?.stackFrame) && value.asm.stackFrame.length) {
    out.push('')
    out.push('【栈帧】')
    for (const slot of value.asm.stackFrame) out.push(`  ${slot}`)
  }

  const xrefs = value.xrefsTo || []
  const callers = value.callers || []
  const callees = value.callees || []
  if (xrefs.length || callers.length || callees.length) {
    out.push('')
    out.push(`【引用】to ${xrefs.length} · 调用方 ${callers.length} · 被调 ${callees.length}`)
    if (callers.length) out.push(`  调用方：${callers.map((item) => `${item.name || '?'}(${item.address})`).join('、')}`)
    if (callees.length) out.push(`  调用了：${callees.map((item) => `${item.name || '?'}(${item.address})`).join('、')}`)
    if (xrefs.length) {
      out.push(`  引用位置：${xrefs.slice(0, 12).map((item) => `${item.from}${item.inFunction ? `@${item.inFunction}` : ''}`).join('、')}`)
    }
  }

  if (value.hint) {
    out.push('')
    out.push(value.hint)
  }
  return out.join('\n')
}

function renderAnnotate (value) {
  if (value?.blocked) return [`被拦下：${value.reason}`, value.how].join('\n')
  if (value?.dryRun) return `试运行：将执行 ${value.count} 项\n${(value.planned || []).map((item) => `  · ${item}`).join('\n')}`
  const applied = value?.applied || []
  const failed = applied.filter((item) => !item.ok)
  const rows = [
    `${value?.ok ? '写入完成' : '部分失败'}：${applied.length - failed.length}/${applied.length}`,
    ...applied.map((item) => `  ${item.ok ? '✓' : '✗'} ${item.op}${item.error ? ` — ${item.error}` : ''}`),
  ]
  if (value?.verified?.name) rows.push(`  回读函数名：${value.verified.name}`)
  if (value?.verified?.nameMismatch) rows.push(`  ⚠ ${value.verified.nameMismatch}`)
  const protoOp = applied.find((item) => item.used)
  if (protoOp) rows.push(`  实际写入原型：${protoOp.used}${protoOp.corrected ? '（原写法不被 IDA 接受，已自动纠正）' : ''}`)
  if (value?.verified?.prototype) rows.push(`  回读原型：${value.verified.prototype}`)
  if (value?.verified?.prototypeMismatch) rows.push(`  ⚠ ${value.verified.prototypeMismatch}`)
  const comments = value?.verified?.comments || []
  if (comments.length) rows.push(`  回读注释：${comments.filter((item) => item.found).length}/${comments.length} 命中`)
  return rows.join('\n')
}

function renderPatch (value) {
  if (value?.blocked) return [`被拦下：${value.reason}`, value.how].join('\n')
  if (value?.rolledBack) return `已回滚 ${value.rolledBack} @ ${value.address}${value.byteExact === false ? '（字节未完全复原，语义一致）' : ''}`
  if (value?.dryRun) {
    return [`试运行：${value.address} ← ${value.wouldWrite}`, '改前：', ...(value.before?.lines || []).map((line) => `  ${line}`), '', value.disasmWindow || ''].join('\n')
  }
  if (!value?.ok) return value?.reason || 'patch 失败'
  return [
    `已 patch ${value.address}（台账 ${value.id}）`,
    '改前：', ...(value.before?.disasm || []).map((line) => `  ${line}`),
    '改后：', ...(value.after?.disasm || []).map((line) => `  ${line}`),
    value.changed ? '' : '⚠ 字节没有变化，检查指令是否写到了预期位置',
  ].filter(Boolean).join('\n')
}

function renderWorkspace (value) {
  if (!value?.ok && value?.reason) {
    return [
      value.reason,
      value.hint,
      Array.isArray(value.available) && value.available.length ? `可选：${value.available.join(', ')}` : '',
    ].filter(Boolean).join('\n')
  }
  if (Array.isArray(value?.workspaces)) {
    const rows = [`本地工作区 ${value.total} 个${value.online ? '' : '（IDA 未连接，离线列举）'}`]
    for (const item of value.workspaces) {
      const label = item.meta?.module || item.meta?.path || '未知模块'
      rows.push(`  · ${item.key}　${label}　${item.names} 命名 / ${item.comments} 注释 / ${item.funcs} 结论${item.updatedAt ? `　${item.updatedAt}` : ''}${value.current === item.key ? '  ← 当前' : ''}`)
    }
    if (value.hint) rows.push(value.hint)
    return rows.join('\n')
  }
  const summary = value?.summary || value || {}
  const banner = value?.offline ? ['【离线】IDA 没开，下面是磁盘上的记录；写入照样落盘。', value.warning || ''].filter(Boolean).join(' ') : ''
  return [
    banner,
    `工作区 ${summary.key || ''}　${summary.names ?? 0} 命名 / ${summary.comments ?? 0} 注释 / ${summary.funcs ?? 0} 函数结论 / ${summary.types ?? 0} 类型`,
    summary.updatedAt ? `  更新于 ${summary.updatedAt}` : '',
    ...(summary.journal || []).map((item) => `  · ${item.action}：${item.text}`),
  ].filter(Boolean).join('\n')
}

function renderExport (value) {
  if (!value?.ok) return value?.reason || '导出失败'
  const head = value.path
    ? `已导出：${value.path}（${value.bytes} 字节）`
    : `未落盘（${value.bytes} 字节），正文如下`
  if (!value.markdown) return head
  return `${head}\n\n${value.markdown}`
}

function renderDataDump (value) {
  const rows = [`读 ${value.address}（${value.size} 字节）${value.name ? `　命名：${value.name}` : ''}`]
  if (value.globalValue !== null && value.globalValue !== undefined) rows.push(`全局值：${value.globalValue}`)
  rows.push('```')
  rows.push(value.dump)
  rows.push('```')
  if (value.name) {
    rows.push(`要改它的名字：ida_data({ action: "renameGlobal", name: "${value.name}", newName: "..." })`)
  }
  return rows.join('\n')
}

function renderMethods (value) {
  if (!value?.ok) return [value?.reason, value?.hint].filter(Boolean).join('\n')
  const rows = [`${value.mode === 'mcp' ? '标准 MCP 工具' : '旧协议方法'}　共 ${value.total} 个，显示 ${value.items.length} 个`]
  for (const item of value.items) {
    const tags = `${item.write ? '  [写]' : ''}${item.unsafe ? '  [unsafe]' : ''}`
    rows.push(`  ${item.signature || item.name}${tags}`)
    if (item.doc) rows.push(`      ${item.doc}`)
  }
  if (value.hint) rows.push(value.hint)
  return rows.join('\n')
}

function renderFind (value) {
  if (!value?.ok) {
    return [
      value?.reason || '查找失败',
      Array.isArray(value?.kinds) ? `可用 kind：${value.kinds.join(' / ')}` : '',
      value?.hint || '',
    ].filter(Boolean).join('\n')
  }
  const items = value.items || []
  const totalText = value.total === null || value.total === undefined
    ? `已扫 ${value.scanned ?? '?'} 条（没扫完，可能还有）`
    : `命中 ${value.total} 条`
  const lines = [`${value.kind} ${totalText}`]
  for (const item of items.slice(0, 15)) {
    const label = item.name || item.string || item.imported_name || ''
    const refs = Array.isArray(item.referencedBy) && item.referencedBy.length
      ? `　← ${item.referencedBy.join('、')}`
      : ''
    lines.push(`  ${item.address || ''} ${shortName(label, 70)}${refs}`.trim())
  }
  if (items.length > 15) lines.push(`  …还有 ${items.length - 15} 条（加大 limit 或用 /正则/ 收窄）`)
  if (value.nextOffset !== null && value.nextOffset !== undefined) lines.push(`  下一页：offset=${value.nextOffset}`)
  if (value.hint) lines.push(value.hint)
  return lines.join('\n')
}

function renderAddr (value) {
  const rows = [`模块 ${value?.module || '?'}　基址 ${value?.idbBase || '?'}${value?.runtimeBase ? `　运行时 ${value.runtimeBase}` : ''}`]
  for (const item of value?.items || []) {
    rows.push(`  ${item.ida} ↔ ${item.runtime}${item.offset ? `（模块内 ${item.offset}）` : ''}`)
  }
  if (value?.hint) rows.push(value.hint)
  return rows.join('\n')
}

export { baseDir }
