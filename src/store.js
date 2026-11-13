/**
 * 分析工作区 + patch 台账。
 *
 * 中心问题：IDA 的 RPC 是无状态的，每个调用只认地址，会话一关，模型对「这个函数我
 * 叫过什么名字、哪几行我注释过、上次改到哪」全忘了。而且 IDB 里的改动是真实写入的，
 * 出了错没有东西能对账。
 *
 * 所以这里落两个文件：
 *   state.json    —— 命名表 / 注释表 / 函数小结 / 分析日志，跨会话可恢复
 *   ledger.jsonl  —— 每次 patch 的原样、改后、理由，只追加，用来回滚和对账
 *
 * 位置：%LOCALAPPDATA%\dsh-ida\<模块名>-<哈希>\，一个 IDB 一个目录。
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, appendFileSync, readdirSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { homedir } from 'node:os'

export function baseDir (custom) {
  if (custom) return String(custom)
  if (process.env.DSH_IDA_DIR) return process.env.DSH_IDA_DIR
  const local = process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
  return join(local, 'dsh-ida')
}

function slug (value) {
  return String(value || 'unknown')
    .replace(/\.[A-Za-z0-9]{1,5}$/, '')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .slice(0, 40) || 'unknown'
}

export function workspaceKey (meta = {}) {
  const identity = meta.sha256 || meta.md5 || meta.path || meta.module || 'unknown'
  const digest = createHash('sha1').update(String(identity)).digest('hex').slice(0, 10)
  return `${slug(meta.module || meta.path)}-${digest}`
}

function readJson (file, fallback) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return fallback
  }
}

function writeJsonAtomic (file, value) {
  const tmp = `${file}.${randomBytes(4).toString('hex')}.tmp`
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  renameSync(tmp, file)
}

const EMPTY_STATE = () => ({
  version: 1,
  meta: {},
  names: {},
  comments: {},
  funcs: {},
  types: {},
  journal: [],
  updatedAt: null,
})

/** 名字 → 类型。以前一律写死 'func'，结果 g_state_x 这种数据也记成函数，
 *  按 kind 聚合的时候就错位。这里按 IDA 的默认命名习惯推一下，显式传入优先。 */
function inferKind (name) {
  const text = String(name || '').trim().toLowerCase()
  if (!text) return 'func'
  if (/^(g_|byte_|word_|dword_|qword_|unk_|off_|asc_|str_|flt_|dbl_|xmmword_)/.test(text)) return 'data'
  if (/^(sub_|loc_|func_|unknown_libname_|nullsub_|j_)/.test(text)) return 'func'
  return 'func'
}

export class Workspace {
  constructor (dir, state) {
    this.dir = dir
    this.state = state
  }

  static load (meta = {}, { dir: customDir } = {}) {
    const key = workspaceKey(meta)
    const dir = join(baseDir(customDir), key)
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    const file = join(dir, 'state.json')
    const state = { ...EMPTY_STATE(), ...readJson(file, {}) }
    const workspace = new Workspace(dir, state)
    workspace.state.meta = { ...(state.meta || {}), ...pickMeta(meta) }
    return workspace
  }

  get key () {
    return this.dir.split(/[\\/]/).pop()
  }

  /**
   * 枚举磁盘上已有的工作区（不碰 IDA）。
   * 工作区本来就是纯本地 JSON，IDA 关掉不代表这些结论读不了 —— 之前
   * ida_workspace 一律先 context() 连 IDA，连不上就整块报错，把最该
   * 留得住的资产一起锁死了。这个静态方法就是给离线路径兜底的。
   */
  static list ({ dir: customDir } = {}) {
    const root = baseDir(customDir)
    let entries = []
    try {
      entries = readdirSync(root, { withFileTypes: true })
    } catch {
      return []
    }
    const out = []
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const dir = join(root, entry.name)
      const file = join(dir, 'state.json')
      if (!existsSync(file)) continue
      const state = readJson(file, null)
      if (!state) continue
      out.push({
        key: entry.name,
        dir,
        meta: state.meta || {},
        names: Object.keys(state.names || {}).length,
        comments: Object.keys(state.comments || {}).length,
        funcs: Object.keys(state.funcs || {}).length,
        types: Object.keys(state.types || {}).length,
        updatedAt: state.updatedAt || null,
      })
    }
    return out.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')))
  }

  /** 不经 IDA，直接按目录打开一个工作区。 */
  static fromDir (dir) {
    const file = join(dir, 'state.json')
    const state = { ...EMPTY_STATE(), ...readJson(file, {}) }
    return new Workspace(dir, state)
  }

  get ledgerFile () {
    return join(this.dir, 'ledger.jsonl')
  }

  get outDir () {
    const dir = join(this.dir, 'out')
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    return dir
  }

  save () {
    this.state.updatedAt = new Date().toISOString()
    writeJsonAtomic(join(this.dir, 'state.json'), this.state)
    return this
  }

  rename (addr, name, extra = {}) {
    this.state.names[String(addr).toLowerCase()] = {
      name,
      kind: extra.kind || inferKind(name),
      note: extra.note || null,
      ts: Date.now(),
    }
    this.save()
  }

  comment (addr, text, func = null) {
    this.state.comments[String(addr).toLowerCase()] = { text, func, ts: Date.now() }
    this.save()
  }

  setFunc (addr, data = {}) {
    const key = String(addr).toLowerCase()
    this.state.funcs[key] = { ...(this.state.funcs[key] || {}), ...data, ts: Date.now() }
    this.save()
  }

  setType (name, declaration) {
    this.state.types[name] = { declaration, ts: Date.now() }
    this.save()
  }

  note (action, text) {
    this.state.journal.push({ ts: Date.now(), action, text })
    if (this.state.journal.length > 300) this.state.journal = this.state.journal.slice(-300)
    this.save()
  }

  summary ({ journalLimit = 8 } = {}) {
    return {
      dir: this.dir,
      key: this.key,
      meta: this.state.meta,
      names: Object.keys(this.state.names).length,
      comments: Object.keys(this.state.comments).length,
      funcs: Object.keys(this.state.funcs).length,
      types: Object.keys(this.state.types).length,
      updatedAt: this.state.updatedAt,
      journal: this.state.journal.slice(-journalLimit),
    }
  }

  overlay (addr) {
    const key = String(addr).toLowerCase()
    return {
      name: this.state.names[key]?.name || null,
      note: this.state.names[key]?.note || null,
      func: this.state.funcs[key] || null,
    }
  }

  appendLedger (record) {
    appendFileSync(this.ledgerFile, `${JSON.stringify(record)}\n`, 'utf8')
    return record
  }

  readLedger (limit = 20) {
    try {
      const lines = readFileSync(this.ledgerFile, 'utf8').split(/\r?\n/).filter(Boolean)
      return lines.slice(-limit).map((line) => {
        try {
          return JSON.parse(line)
        } catch {
          return null
        }
      }).filter(Boolean)
    } catch {
      return []
    }
  }

  findPatch (selector) {
    const records = this.readLedger(500)
    if (!records.length) return null
    if (!selector || selector === 'last') {
      for (let i = records.length - 1; i >= 0; i -= 1) {
        if (records[i].status === 'applied') return records[i]
      }
      return null
    }
    const hit = records.find((record) => record.id === selector)
    return hit || null
  }

  markPatch (id, status, extra = {}) {
    const records = this.readLedger(500)
    const target = records.find((record) => record.id === id)
    if (!target) return null
    const updated = { ...target, status, ...extra, resolvedAt: new Date().toISOString() }
    this.appendLedger(updated)
    return updated
  }

  exportFile (name, targetDir) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    const dir = targetDir || this.outDir
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    return join(dir, `${slug(name)}-${stamp}.md`)
  }
}

function pickMeta (meta = {}) {
  const keep = ['path', 'module', 'base', 'size', 'md5', 'sha256', 'crc32', 'filesize']
  const out = {}
  for (const key of keep) {
    if (meta[key] !== undefined && meta[key] !== null && meta[key] !== '') out[key] = meta[key]
  }
  return out
}
