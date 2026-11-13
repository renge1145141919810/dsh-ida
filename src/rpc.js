/**
 * 与 IDA Pro 侧的 mcp-plugin 通信的最小客户端。
 *
 * 为什么不用 @modelcontextprotocol/sdk：
 *   本机装的 ida-pro-mcp 是作者早期的单文件插件（mcp-plugin.py），它并不是标准 MCP
 *   服务，而是一个自定义 JSON-RPC：POST /mcp，method 直接是函数名（get_metadata /
 *   decompile_function / set_comment ...），没有 initialize、tools/list、tools/call。
 *   新版 ida-pro-mcp 才改成标准 MCP（streamable-http + tools/call）。
 *   两种都在真实世界里存在，所以这里做双模自适应：先按标准 MCP 握手，失败再退回落
 *   旧协议，之后所有调用都由 caps 表翻译成对应形态。
 *
 * 零依赖：只用 Node 18+ 自带的 fetch。
 */

const VERSION = '0.1.0'
const PROTOCOL_VERSION = '2025-06-18'

let seq = 0
const nextId = () => ++seq

export class BridgeError extends Error {
  constructor (message, extra = {}) {
    super(message)
    this.name = 'BridgeError'
    this.kind = extra.kind || 'rpc'
    this.code = extra.code ?? null
    this.data = extra.data ?? null
  }
}

function parseJson (raw) {
  const trimmed = String(raw || '').trim()
  if (!trimmed) return null
  try {
    return JSON.parse(trimmed)
  } catch (error) {
    throw new BridgeError(`服务返回的不是合法 JSON：${trimmed.slice(0, 160)}`, { kind: 'http' })
  }
}

/** streamable-http 的响应可能是 SSE，取 id 对得上的那一条 data。 */
function pickFromSse (raw, wantId) {
  const chunks = []
  for (const block of String(raw).split(/\r?\n\r?\n/)) {
    const dataLines = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
    if (!dataLines.length) continue
    const payload = dataLines.join('\n')
    try {
      chunks.push(JSON.parse(payload))
    } catch {
      // 忽略非 JSON 的心跳/日志行
    }
  }
  if (!chunks.length) return null
  if (wantId === undefined) return chunks[chunks.length - 1]
  return chunks.find((item) => item && item.id === wantId) || chunks[chunks.length - 1]
}

function describeNetworkError (error, url) {
  const cause = error?.cause?.code || error?.code || ''
  if (cause === 'ECONNREFUSED' || /fetch failed/i.test(String(error?.message))) {
    return new BridgeError(
      `连不上 ${url}（连接被拒绝）。通常是没有开 IDA，或 IDA 里没有加载 mcp-plugin。`,
      { kind: 'net' }
    )
  }
  if (error?.name === 'TimeoutError' || cause === 'UND_ERR_CONNECT_TIMEOUT') {
    return new BridgeError(
      `${url} 响应超时。IDA 可能被模态对话框挡住（插件跑在主线程上），或者正在分析大函数。`,
      { kind: 'timeout' }
    )
  }
  return new BridgeError(`请求 ${url} 失败：${error?.message || error}`, { kind: 'net' })
}

export class IdaBridge {
  constructor (options = {}) {
    this.url = normalizeUrl(options.url)
    this.timeoutMs = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : 45000
    this.mode = null            // 'legacy' | 'mcp'
    this.sessionId = null
    this.serverInfo = null
    this.toolNames = null
    this.lastLatencyMs = null
    this.lastError = null
  }

  reset () {
    this.mode = null
    this.sessionId = null
    this.serverInfo = null
    this.toolNames = null
    this.lastError = null
  }

  state () {
    return {
      url: this.url,
      mode: this.mode,
      serverInfo: this.serverInfo,
      toolCount: Array.isArray(this.toolNames) ? this.toolNames.length : null,
      latencyMs: this.lastLatencyMs,
    }
  }

  async post (payload, { timeoutMs } = {}) {
    const started = Date.now()
    const headers = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    }
    if (this.sessionId) headers['mcp-session-id'] = this.sessionId
    if (this.mode === 'mcp') headers['mcp-protocol-version'] = PROTOCOL_VERSION

    let response
    try {
      response = await fetch(this.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs || this.timeoutMs),
      })
    } catch (error) {
      throw describeNetworkError(error, this.url)
    }

    this.lastLatencyMs = Date.now() - started
    const sessionId = response.headers.get('mcp-session-id')
    if (sessionId) this.sessionId = sessionId

    const raw = await response.text()
    if (!response.ok) {
      if (response.status === 404) {
        throw new BridgeError(
          `${this.url} 返回 404。旧版插件的端点必须正好是 /mcp；新版标准 MCP 也要带 /mcp 路径。`,
          { kind: 'http', code: 404 }
        )
      }
      throw new BridgeError(`HTTP ${response.status} ${response.statusText}：${raw.slice(0, 200)}`, {
        kind: 'http',
        code: response.status,
      })
    }

    const contentType = response.headers.get('content-type') || ''
    if (contentType.includes('text/event-stream')) return pickFromSse(raw, payload?.id)
    return parseJson(raw)
  }

  /** 单次 JSON-RPC（旧协议形态）。 */
  async rpc (method, params = [], { timeoutMs } = {}) {
    const id = nextId()
    const envelope = await this.post({ jsonrpc: '2.0', id, method, params }, { timeoutMs })
    if (!envelope) throw new BridgeError(`${method} 没有返回内容（服务可能已关闭）`, { kind: 'rpc' })
    if (envelope.error) {
      throw new BridgeError(envelope.error.message || `${method} 调用失败`, {
        kind: 'ida',
        code: envelope.error.code,
        data: envelope.error.data,
      })
    }
    return envelope.result
  }

  async notify (method, params = {}) {
    try {
      await this.post({ jsonrpc: '2.0', method, params })
    } catch {
      // 通知失败不影响后续调用
    }
  }

  /**
   * 探测协议。返回 state 而不是抛异常，让 ida_status 能把诊断讲清楚。
   */
  async connect ({ force = false } = {}) {
    if (this.mode && !force) return this.state()
    this.reset()

    let mcpError = null
    try {
      const id = nextId()
      const envelope = await this.post({
        jsonrpc: '2.0',
        id,
        method: 'initialize',
        params: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: 'dsh-ida', version: VERSION },
        },
      })
      const result = envelope?.result
      if (result && (result.protocolVersion || result.serverInfo || result.capabilities)) {
        this.mode = 'mcp'
        this.serverInfo = result.serverInfo || null
        await this.notify('notifications/initialized')
        try {
          const listed = await this.post({ jsonrpc: '2.0', id: nextId(), method: 'tools/list', params: {} })
          const tools = listed?.result?.tools
          if (Array.isArray(tools)) this.toolNames = tools.map((tool) => tool.name)
        } catch {
          this.toolNames = null
        }
        return this.state()
      }
      if (envelope?.error) mcpError = envelope.error.message
    } catch (error) {
      mcpError = error.message
      if (error.kind === 'net' || error.kind === 'timeout') {
        this.lastError = error
        throw error
      }
    }

    try {
      const meta = await this.rpc('get_metadata', [])
      if (meta && (meta.path !== undefined || meta.module !== undefined || meta.base !== undefined)) {
        this.mode = 'legacy'
        this.serverInfo = { name: 'ida-pro-mcp (legacy jsonrpc)', version: null }
        return this.state()
      }
    } catch (error) {
      if (error.kind === 'net' || error.kind === 'timeout') {
        this.lastError = error
        throw error
      }
      throw new BridgeError(
        `${this.url} 上有一个 JSON-RPC 服务，但既不是标准 MCP 也不是 ida-pro-mcp 旧协议。` +
          `（initialize: ${mcpError || '无响应'}；get_metadata: ${error.message}）` +
          `确认 13337 端口没被别的程序占用。`,
        { kind: 'rpc' }
      )
    }
    throw new BridgeError(
      `没认出 ${this.url} 的协议。initialize: ${mcpError || '无响应'}。` +
        `确认装的是 ida-pro-mcp，且 IDA 已经打开一个数据库。`,
      { kind: 'rpc' }
    )
  }

  /** 保证连上并且是想要的协议。 */
  async ready (capabilities) {
    await this.connect()
    return this.mode
  }

  /**
   * 通过能力名调用。capabilities 见 src/caps.js。
   */
  async invoke (capName, args = {}, options = {}) {
    const { CAPS } = await import('./caps.js')
    const cap = CAPS[capName]
    if (!cap) throw new BridgeError(`插件内部缺少能力定义：${capName}`, { kind: 'client' })
    await this.connect()

    if (this.mode === 'legacy') {
      const spec = cap.legacy
      if (!spec) throw new BridgeError(`旧协议不支持能力 ${capName}`, { kind: 'client' })
      return this.rpc(spec.method, spec.build(args), options)
    }

    const candidates = cap.mcp?.candidates || []
    const name = this.pickTool(candidates)
    if (!name) {
      throw new BridgeError(
        `服务器没有提供 ${capName} 需要的工具（候选：${candidates.join(', ') || '无'}）。` +
          `已探测到的工具：${(this.toolNames || []).slice(0, 20).join(', ') || '（tools/list 未返回）'}`,
        { kind: 'client' }
      )
    }
    return this.callTool(name, cap.mcp.build(args), options)
  }

  /** 标准 MCP 的 tools/call + 结果解包（新协议的统一出口）。 */
  async callTool (name, argsObject = {}, options = {}) {
    await this.connect()
    if (this.mode === 'legacy') {
      // 旧协议没有 tools/call，落到 ida_raw 时由调用方决定传什么
      return this.rpc(name, Array.isArray(argsObject) ? argsObject : [], options)
    }
    const envelope = await this.post(
      {
        jsonrpc: '2.0',
        id: nextId(),
        method: 'tools/call',
        params: { name, arguments: argsObject },
      },
      options
    )
    if (envelope?.error) {
      throw new BridgeError(envelope.error.message || `${name} 调用失败`, {
        kind: 'ida',
        code: envelope.error.code,
        data: envelope.error.data,
      })
    }
    const result = envelope?.result
    if (result?.isError) {
      const text = (result.content || []).map((part) => part.text).filter(Boolean).join('\n')
      throw new BridgeError(text || `${name} 返回错误`, { kind: 'ida' })
    }
    if (result?.structuredContent !== undefined) return result.structuredContent
    const text = (result?.content || []).map((part) => part.text).filter(Boolean).join('\n')
    if (text) {
      try {
        return JSON.parse(text)
      } catch {
        return text
      }
    }
    return null
  }

  pickTool (candidates) {
    if (!candidates.length) return null
    if (!Array.isArray(this.toolNames)) return candidates[0]
    for (const candidate of candidates) {
      if (this.toolNames.includes(candidate)) return candidate
    }
    return null
  }
}

function normalizeUrl (input) {
  const raw = String(input || '').trim() || 'http://127.0.0.1:13337/mcp'
  let url = raw
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`
  if (!/\/mcp\/?$/i.test(url)) url = `${url.replace(/\/+$/, '')}/mcp`
  // localhost 在某些 Windows 解析下会先试 ::1，统一成 127.0.0.1 更稳
  return url.replace(/^(https?:\/\/)localhost/i, '$1127.0.0.1')
}

export { VERSION }
