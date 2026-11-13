/**
 * 离线工作区自测：故意连一个关着的端口，验证
 *   1) ida_workspace({action:'list'}) 不碰 IDA 也能列出磁盘上的工作区
 *   2) ida_workspace({action:'get'}) 离线能读出历史命名/注释/结论
 *   3) 指定不存在的 key 时给出可选列表
 *   4) ida_status 断连时把本地工作区摆出来
 *   5) store.rename 会按名字推断 kind（g_* → data）
 *
 * 跑法：node _dev/offline-workspace.mjs <临时工作区根目录>
 */

import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { apply } from '../index.js'
import { Workspace } from '../src/store.js'

const root = process.argv[2]
if (!root) {
  console.error('用法：node _dev/offline-workspace.mjs <dir>')
  process.exit(2)
}

rmSync(root, { recursive: true, force: true })
const seed = join(root, 'Reverse02-16fe332723')
mkdirSync(seed, { recursive: true })
writeFileSync(join(seed, 'state.json'), JSON.stringify({
  version: 1,
  meta: { module: 'Reverse02.exe', sha256: 'deadbeef', path: '/samples/Reverse02.exe' },
  names: {
    '0x401070': { name: 'verify_password', kind: 'func', note: null },
    '0x403018': { name: 'g_state_x', kind: 'data', note: null },
  },
  comments: { '0x4010c2': { text: '第一组 XOR 7', func: 'verify_password' } },
  funcs: { '0x401070': { name: 'verify_password', summary: '校验 13 字节', status: 'analyzed' } },
  types: {},
  journal: [{ ts: 1, action: 'annotate', text: 'seed' }],
  updatedAt: '2026-11-10T09:00:00.000Z',
}, null, 2))

let pass = 0
let fail = 0
function check (label, cond, extra) {
  if (cond) { pass += 1; console.log(`  ✓ ${label}`) } else { fail += 1; console.log(`  ✗ ${label}` + (extra === undefined ? '' : `\n      实际：${JSON.stringify(extra)}`)) }
}

function mount (config) {
  const tools = new Map()
  const ctx = {
    get tools () { return { register: (tool) => tools.set(tool.name, tool) } },
    effect (fn) { fn(); return () => {} },
    inject () {},
    logger () { return { info () {}, warn () {}, error () {} } },
  }
  apply(ctx, config)
  return {
    call: async (name, args) => ({ value: await tools.get(name).execute(args || {}) }),
    render: async (name, args) => {
      const tool = tools.get(name)
      const value = await tool.execute(args || {})
      return { value, text: tool.output.render(args || {}, value).map((p) => p.text).join('\n') }
    },
  }
}

const offline = mount({
  url: 'http://127.0.0.1:59998/mcp', // 必然连接被拒
  allow: 'annotate',
  timeoutMs: 3000,
  dir: root,
})

console.log('离线：列出工作区')
{
  const { value, text } = await offline.render('ida_workspace', { action: 'list' })
  check('list 返回 ok', value.ok === true)
  check('list 标了 offline', value.offline === true)
  check('list 找到 1 个工作区', value.total === 1, value)
  check('渲染里有 key', text.includes('Reverse02-16fe332723'), text)
  check('渲染里标了离线', text.includes('离线'))
}

console.log('离线：读工作区（不传 key，单工作区自动选中）')
{
  const { value } = await offline.call('ida_workspace', { action: 'get' })
  check('get 返回 ok', value.ok === true)
  check('get 标了 offline', value.offline === true)
  check('命名 2 条', value.summary.names === 2, value.summary)
  check('注释 1 条', value.summary.comments === 1, value.summary)
  check('函数结论 1 条', value.summary.funcs === 1, value.summary)
  check('idb 元信息来自磁盘', value.idb?.module === 'Reverse02.exe', value.idb)
}

console.log('离线：指定不存在的 key')
{
  const { value } = await offline.call('ida_workspace', { action: 'get', key: 'nope-000' })
  check('报错并给可选列表', value.ok === false && Array.isArray(value.available), value)
  check('可选列表里有正确答案', (value.available || []).includes('Reverse02-16fe332723'), value.available)
}

console.log('离线：按 key 读取')
{
  const { value } = await offline.call('ida_workspace', { action: 'get', key: 'Reverse02-16fe332723' })
  check('按 key 命中', value.ok === true && value.offline === true)
}

console.log('离线：ida_status 报断连并把工作区摆出来')
{
  const { value } = await offline.call('ida_status', {})
  check('connected=false', value.connected === false)
  check('带 workspaces 列表', Array.isArray(value.workspaces) && value.workspaces.length === 1, value.workspaces)
  check('带离线提示', typeof value.offlineHint === 'string' && value.offlineHint.includes('ida_workspace'), value.offlineHint)
}

console.log('kind 推断')
{
  const ws = Workspace.load({ sha256: 'kindtest', module: 'kindtest' }, { dir: root })
  ws.rename('0x403018', 'g_state_x')
  ws.rename('0x401000', 'sub_401000')
  ws.rename('0x403028', 'byte_403028')
  const kinds = {
    g_state_x: ws.state.names['0x403018'].kind,
    sub_401000: ws.state.names['0x401000'].kind,
    byte_403028: ws.state.names['0x403028'].kind,
  }
  check('g_* → data', kinds.g_state_x === 'data', kinds)
  check('sub_* → func', kinds.sub_401000 === 'func', kinds)
  check('byte_* → data', kinds.byte_403028 === 'data', kinds)
}

rmSync(root, { recursive: true, force: true })
console.log(`\n${pass} 通过，${fail} 失败`)
process.exit(fail ? 1 : 0)