/**
 * 自检：不开 IDA，直接对着假 IDA 跑一遍全部工具。
 *
 *   node _dev/selftest.mjs
 *
 * 覆盖：协议识别、函数读取（含「正文必须出现在渲染结果里」）、批量标注 + 回读校验、
 *       原型自动纠正、patch 台账 + 回滚、数据层（字节/全局/结构体/栈帧）、
 *       方法自曝与拼写纠正、工作区持久化、导出（含 inline）、查找、地址换算、
 *       权限闸门、连不上时的诊断，以及标准 MCP 通道。
 *
 * 每条断言尽量打在「模型真正看到的东西」上：工具返回值和 output.render() 的文本都查。
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startMock } from './mock-ida.mjs'
import { apply } from '../index.js'

let pass = 0
let fail = 0

function check (label, condition, extra) {
  if (condition) {
    pass += 1
    console.log(`  ✓ ${label}`)
  } else {
    fail += 1
    console.log(`  ✗ ${label}${extra === undefined ? '' : `\n      实际：${JSON.stringify(extra)}`}`)
  }
}

function makeCtx () {
  const tools = new Map()
  const ctx = {
    get tools () {
      return { register: (tool) => tools.set(tool.name, tool) }
    },
    effect (fn) {
      fn()
      return () => {}
    },
    inject () {},
    logger () {
      return { info () {}, warn () {}, error () {} }
    },
  }
  return { ctx, tools }
}

function mount (config) {
  const { ctx, tools } = makeCtx()
  apply(ctx, config)
  const call = (name, args) => {
    const tool = tools.get(name)
    if (!tool) throw new Error(`工具不存在：${name}`)
    return tool.execute(args || {})
  }
  /** 模型实际读到的文本 —— 上一次的 P0 就出在这里：值里有正文，渲染时丢了。 */
  const render = async (name, args) => {
    const tool = tools.get(name)
    const value = await tool.execute(args || {})
    const parts = tool.output.render(args || {}, value)
    return { value, text: parts.map((part) => part.text).join('\n') }
  }
  return { tools, call, render }
}

const outDir = mkdtempSync(join(tmpdir(), 'dsh-ida-test-'))

console.log('dsh-ida 自检\n')

const legacy = await startMock({ port: 13338 })
const mcpMock = await startMock({ port: 13339, mcp: true })

try {
  // ---------------------------------------------------------------- 旧协议
  console.log('旧版 JSON-RPC（本机 mcp-plugin.py 的形态）')
  let session = mount({ url: 'http://127.0.0.1:13338/mcp', allow: 'patch', outDir })

  check('注册了 11 个工具', session.tools.size === 11, [...session.tools.keys()])

  const status = await session.call('ida_status')
  check('识别为旧协议', status.connected === true && status.bridge.mode === 'legacy', status.bridge?.mode)
  check('读到 IDB 元数据', status.idb?.module === 'crackme.exe', status.idb)
  check('建立工作区', Boolean(status.workspace?.key), status.workspace)

  const func = await session.call('ida_func', { target: 'main' })
  check('伪代码带地址锚点', func.pseudocode.text.includes('0x401000') && func.anchors.length > 0, func.anchors.slice(0, 2))
  check('原型从伪代码首行推断', String(func.function.prototype || '').includes('main('), func.function.prototype)
  check('带交叉引用', Array.isArray(func.xrefsTo) && func.xrefsTo.length > 0, func.xrefsTo)
  check('带调用关系', func.callees.length > 0, func.callees)

  // P0：正文必须真的出现在模型读到的文本里
  const funcRendered = await session.render('ida_func', { target: 'main' })
  check('渲染结果包含伪代码正文', funcRendered.text.includes('check_password(v3)'), funcRendered.text.slice(0, 200))
  check('渲染结果包含地址前缀', funcRendered.text.includes('0x40100f'), funcRendered.text)
  check('渲染结果不含占位提示', !funcRendered.text.includes('IDA 没有返回伪代码正文'), funcRendered.text.slice(0, 120))

  const byAddr = await session.call('ida_func', { target: '0x401120' })
  check('按地址定位函数', byAddr.function.name === 'check_password', byAddr.function)

  // ---------------------------------------------------------------- 查找
  console.log('\n查找')
  const found = await session.call('ida_find', { kind: 'func', pattern: 'password' })
  check('按名字搜函数', found.items.length === 1 && found.items[0].name === 'check_password', found.items)

  const strings = await session.call('ida_find', { kind: 'string', pattern: 'pass' })
  check('搜字符串', strings.items.length === 2, strings.items)
  check('字符串带出引用函数', Array.isArray(strings.items[0]?.referencedBy), strings.items[0])

  const imports = await session.call('ida_find', { kind: 'import', pattern: 'str' })
  check('看导入表', imports.items.length === 1 && imports.items[0].imported_name === 'strcmp', imports.items)

  const globalsByText = await session.call('ida_find', { kind: 'globals', pattern: '4030' })
  check('复数 kind 也认，且能按名字子串命中', globalsByText.ok === true && globalsByText.items.length >= 2, globalsByText)

  const globalsByAddr = await session.call('ida_find', { kind: 'global', pattern: '0x403028' })
  check('传地址反查全局名', globalsByAddr.items[0]?.name === 'byte_403028', globalsByAddr)

  const badKind = await session.call('ida_find', { kind: 'symbol', pattern: 'x' })
  check('不认识的 kind 给出可用列表', badKind.ok === false && badKind.kinds.includes('global'), badKind)

  const regex = await session.call('ida_find', { kind: 'string', pattern: '/^wrong/' })
  check('支持 /正则/', regex.items.length === 1 && regex.items[0].string === 'wrong password', regex.items)

  const bareHex = await session.call('ida_func', { target: '401120' })
  check('不带 0x 的地址按 16 进制解析', bareHex.function.name === 'check_password', bareHex.function)

  const addr = await session.call('ida_addr', { addresses: ['0x401120'], runtimeBase: '0x140000000' })
  check('地址换算（模块偏移不变）', addr.items[0].runtime === '0x140001120' && addr.items[0].offset === '0x1120', addr.items[0])

  // ---------------------------------------------------------------- 能力自曝
  console.log('\n方法清单与原始调用')
  const methods = await session.call('ida_methods', { filter: 'bytes' })
  check('列出方法清单', methods.ok === true && methods.total === 59, methods.total)
  check('filter 命中 read_memory_bytes', methods.items.some((item) => item.name === 'read_memory_bytes'), methods.items)

  const methodsRendered = await session.render('ida_methods', { filter: 'struct' })
  check('渲染带签名', methodsRendered.text.includes('get_defined_structures('), methodsRendered.text.slice(0, 200))

  const aliasRaw = await session.call('ida_raw', { method: 'get_bytes', params: { memory_address: '0x40301c', size: 4 } })
  check('别名 get_bytes → read_memory_bytes', aliasRaw.ok === true && aliasRaw.method === 'read_memory_bytes', aliasRaw)

  const namedRaw = await session.call('ida_raw', { method: 'read_memory_bytes', params: { memory_address: '0x40301c', size: 4 } })
  // ida_raw 的 result 现在统一过 wrapScalar：字符串会变成 { type: 'string', value: '...' }
  check('具名参数可用', namedRaw.ok === true && String(namedRaw.result?.value ?? namedRaw.result).startsWith('0x4d'), namedRaw)

  const typoRaw = await session.call('ida_raw', { method: 'get_bytez', params: {} })
  check('拼错时给候选', typoRaw.ok === false && typoRaw.candidates.length > 0, typoRaw)

  const unknownRaw = await session.call('ida_raw', { method: 'totally_made_up' })
  check('完全不存在的方法有候选', unknownRaw.ok === false && Array.isArray(unknownRaw.candidates), unknownRaw)

  // ---------------------------------------------------------------- 数据层
  console.log('\n数据层（字节 / 全局 / 结构体 / 栈帧）')
  const read = await session.render('ida_data', { action: 'read', address: '0x40301c', size: 13 })
  check('读出 13 字节', read.value.bytes.split(' ').length === 13, read.value.bytes)
  check('带 hexdump', read.text.includes('4d 5a 90'), read.text)
  check('识别出该地址的名字', read.value.name === 'byte_40301C', read.value.name)

  const globalValue = await session.call('ida_data', { action: 'globalValue', name: 'byte_403028' })
  check('按名字取全局值', globalValue.value === '0x1A2B', globalValue)

  const renamed = await session.call('ida_data', { action: 'renameGlobal', name: 'byte_403028', newName: 'g_magic' })
  check('全局变量改名', renamed.ok === true && renamed.from === 'byte_403028' && renamed.name === 'g_magic', renamed)
  const afterGlobalRename = await session.call('ida_find', { kind: 'global', pattern: '0x403028' })
  check('改名后按地址能查到新名字', afterGlobalRename.items[0]?.name === 'g_magic', afterGlobalRename)

  const declared = await session.call('ida_data', { action: 'declareType', type: 'struct cfg_header { unsigned int magic; unsigned short ver; };' })
  check('不带函数也能声明类型', declared.ok === true && declared.declaration.includes('cfg_header'), declared)

  const typedGlobal = await session.call('ida_data', { action: 'setGlobalType', name: 'g_magic', type: 'unsigned int' })
  check('全局变量改类型', typedGlobal.ok === true, typedGlobal)

  const structs = await session.call('ida_data', { action: 'structs' })
  check('列出结构体', structs.items.some((item) => item.name === 'cfg_header'), structs)
  const structDetail = await session.call('ida_data', { action: 'struct', name: 'cfg_header' })
  check('结构体详情', structDetail.detail.members.length === 3, structDetail)
  const structAt = await session.call('ida_data', { action: 'structAt', address: '0x403000', struct: 'cfg_header' })
  check('某地址上的结构体字段值', structAt.detail.members.length === 3, structAt)

  const stack = await session.call('ida_data', { action: 'stack', func: 'main' })
  check('列出栈帧变量', stack.items.some((item) => item.name === 'var_8'), stack)
  const stackRenamed = await session.call('ida_data', { action: 'renameStack', func: 'main', variable: 'var_8', newName: 'saved_rbp' })
  check('栈帧变量改名', stackRenamed.ok === true, stackRenamed)

  // ---------------------------------------------------------------- 渲染与回退（DSH v0.2 实测反馈）
  console.log('\n渲染层与回退路径')

  // asJson() 已经返回 part 数组，外面再套一层 text() 就会 String([{...}]) → [object Object]
  const renameRendered = await session.render('ida_data', { action: 'renameGlobal', name: 'byte_40301C', newName: 'g_hdr_magic' })
  check('renameGlobal 的渲染不是 [object Object]',
    !renameRendered.text.includes('[object Object]'), renameRendered.text.slice(0, 120))
  check('renameGlobal 的渲染是合法 JSON',
    (() => { try { JSON.parse(renameRendered.text); return true } catch { return false } })(),
    renameRendered.text.slice(0, 80))

  const stackRendered = await session.render('ida_data', { action: 'stack', func: 'main' })
  check('stack 的渲染不是 [object Object]', !stackRendered.text.includes('[object Object]'), stackRendered.text.slice(0, 120))

  const typeRendered = await session.render('ida_data', { action: 'setGlobalType', name: 'g_hdr_magic', type: 'unsigned int' })
  check('setGlobalType 的渲染不是 [object Object]', !typeRendered.text.includes('[object Object]'), typeRendered.text.slice(0, 120))

  // 服务端「按地址取全局值」会失败，但按名字能取到 —— 别在第一步就放弃
  const valueByAddr = await session.render('ida_data', { action: 'globalValue', address: '0x403018' })
  check('按地址取不到时回退到按名字', valueByAddr.value.value === '0x1A2B' && valueByAddr.value.via === 'name', valueByAddr.value)
  check('回执里写明走了哪条路', valueByAddr.text.includes('"via": "name"'), valueByAddr.text.slice(0, 160))

  // 全局索引被页数上限截断时，地址反查要能靠「名字里的地址片段」兜底
  legacy.mock.state.globalListBroken = true
  await session.call('ida_data', { action: 'renameGlobal', name: 'g_checksum', newName: 'g_sum' }) // 顺带清空索引缓存
  const foundByFilter = await session.call('ida_find', { kind: 'global', pattern: '0x403040' })
  check('索引被截断时仍能按地址反查名字', foundByFilter.items[0]?.name === 'byte_403040', foundByFilter)
  check('命中的是 filter 兜底路径', foundByFilter.via === 'filter', foundByFilter.via)
  legacy.mock.state.globalListBroken = false
  await session.call('ida_data', { action: 'renameGlobal', name: 'g_sum', newName: 'g_checksum' })

  // 真的查不到时，提示不能自相矛盾
  const missing = await session.call('ida_find', { kind: 'global', pattern: '0x999999' })
  check('查不到时不再给「把 0x 当 pattern」这种废话',
    missing.total === 0 && !String(missing.hint).includes('就直接把 0x'), missing.hint)
  check('查不到时给出可执行的下一步', String(missing.hint).includes('ida_data'), missing.hint)

  // ida_raw 的裸标量返回值：包成 {type,value}，否则 harness 会说 not lossless JSON
  const rawScalar = await session.render('ida_raw', { method: 'declare_c_type', params: { c_declaration: 'typedef int foo_t;' } })
  check('ida_raw 的裸标量被包成 {type,value}',
    rawScalar.value.result?.type === 'string' && typeof rawScalar.value.result.value === 'string',
    rawScalar.value.result)
  check('ida_raw 渲染是合法 JSON',
    (() => { try { JSON.parse(rawScalar.text); return true } catch { return false } })(),
    rawScalar.text.slice(0, 80))
  const rawNull = await session.call('ida_raw', { method: 'rename_function', params: { function_address: '0x401000', new_name: 'main' } })
  check('返回 null 时不破坏 JSON（保持 null）', rawNull.result === null, rawNull.result)

  // ---------------------------------------------------------------- 能力探测
  console.log('\n能力探测（类型层 / 栈帧层）')
  const probed = await session.render('ida_status', { probe: true })
  check('探测报告三层都可用',
    probed.value.capabilities?.structures?.ok === true &&
    probed.value.capabilities?.localTypes?.ok === true &&
    probed.value.capabilities?.stackFrame?.ok === true, probed.value.capabilities)
  check('探测结论出现在渲染文本里', probed.text.includes('都可用'), probed.text)

  legacy.mock.state.structsBroken = true
  const probedBroken = await session.render('ida_status', { probe: true })
  check('类型层挂掉时探测能报出来',
    probedBroken.value.capabilities?.structures?.ok === false, probedBroken.value.capabilities)
  check('SDK 版本不匹配时指向兼容补丁',
    String(probedBroken.value.capabilities?.verdict).includes('patch-ida-plugin'), probedBroken.value.capabilities?.verdict)
  legacy.mock.state.structsBroken = false

  const blockedData = await mount({ url: 'http://127.0.0.1:13338/mcp', allow: 'off' })
  const blockedRename = await blockedData.call('ida_data', { action: 'renameGlobal', name: 'g_magic', newName: 'nope' })
  check('allow=off 时数据层写操作被拦', blockedRename.blocked === true, blockedRename)

  // ---------------------------------------------------------------- 闸门
  console.log('\n写入闸门')
  let offSession = mount({ url: 'http://127.0.0.1:13338/mcp', allow: 'off', outDir })
  const blockedAnnotate = await offSession.call('ida_annotate', { target: 'main', rename: 'should_not_happen' })
  check('allow=off 时拒绝写注释/改名', blockedAnnotate.blocked === true && blockedAnnotate.reason.includes('只读'), blockedAnnotate)
  const blockedPatch = await offSession.call('ida_patch', { address: '0x401200', instructions: 'retn' })
  check('allow=off 时拒绝 patch', blockedPatch.blocked === true, blockedPatch)

  session = mount({ url: 'http://127.0.0.1:13338/mcp', allow: 'annotate', outDir })
  const annotateOnlyPatch = await session.call('ida_patch', { address: '0x401200', instructions: 'retn' })
  check('allow=annotate 时拒绝 patch', annotateOnlyPatch.blocked === true && annotateOnlyPatch.reason.includes('patch'), annotateOnlyPatch)
  const unsafeRaw = await session.call('ida_raw', { method: 'dbg_get_registers' })
  check('allow=annotate 时拒绝 unsafe 方法', unsafeRaw.ok === false && unsafeRaw.reason.includes('unsafe'), unsafeRaw)

  // ---------------------------------------------------------------- 批量标注
  console.log('\n批量标注 + 回读校验')
  session = mount({ url: 'http://127.0.0.1:13338/mcp', allow: 'patch', outDir })

  const dry = await session.call('ida_annotate', {
    target: 'check_password',
    rename: 'verify_checksum',
    comments: [{ address: '0x40112b', text: 'sum bytes' }],
    dryRun: true,
  })
  check('dryRun 只列计划不写', dry.dryRun === true && dry.count === 2, dry)

  const stillOld = await session.call('ida_func', { target: 'check_password' })
  check('dryRun 确实没改动', stillOld.function.name === 'check_password', stillOld.function.name)

  // 故意用 Hex-Rays 的伪代码类型名 + 带函数名，这是之前 100% 失败的真实写法
  const applied = await session.call('ida_annotate', {
    target: 'check_password',
    rename: 'verify_checksum',
    prototype: 'int __cdecl verify_checksum(_BYTE *src)',
    types: ['struct cfg { int magic; int len; };'],
    locals: [{ name: 'v1', newName: 'checksum' }, { name: 'v2', newName: 'index', type: 'int' }],
    comments: [
      { address: '0x40112b', text: 'sum every 4th byte' },
      { address: '0x401134', text: 'compare against magic 0x1A2B' },
    ],
    note: '把密码校验认成累加校验',
  })
  check('全部操作成功（原型自动纠正）', applied.ok === true, applied.applied)
  const protoOp = applied.applied.find((item) => item.used)
  check('原型被纠正成可解析的写法', Boolean(protoOp) && !protoOp.used.includes('_BYTE') && !protoOp.used.includes('verify_checksum'), protoOp)
  check('回读函数名已变', applied.verified.name === 'verify_checksum', applied.verified)
  check('没有名字回读告警', !applied.verified.nameMismatch, applied.verified.nameMismatch)
  check('注释回读命中', applied.verified.comments.filter((item) => item.found).length === 2, applied.verified.comments)
  check('回读到原型', Boolean(applied.verified.prototype), applied.verified)

  const annotateRendered = await session.render('ida_annotate', {
    target: 'verify_checksum',
    prototype: 'int __cdecl verify_checksum(_BYTE *src)',
    comments: [{ address: '0x401134', text: 'magic compare' }],
  })
  check('渲染说明原型被纠正', annotateRendered.text.includes('自动纠正') || annotateRendered.text.includes('实际写入原型'), annotateRendered.text)

  const badProto = await session.call('ida_annotate', {
    target: 'verify_checksum',
    prototype: 'INT_PTR __stdcall handler(HWND hWnd, UINT msg)',
  })
  check('无法解析的原型给出语法指引', badProto.ok === false && badProto.applied[0].error.includes('标准 C 类型声明'), badProto.applied)

  const afterRename = await session.call('ida_func', { target: 'verify_checksum' })
  check('按新名字能查到', afterRename.function.name === 'verify_checksum', afterRename.function)
  check('工作区带出命名记录', afterRename.workspace?.name === 'verify_checksum', afterRename.workspace)

  const badLocal = await session.call('ida_annotate', {
    target: 'verify_checksum',
    locals: [{ name: 'not_a_real_var', newName: 'x' }],
  })
  check('单条失败不影响整体返回结构', badLocal.applied.length === 1 && badLocal.applied[0].ok === false, badLocal.applied)

  // ---------------------------------------------------------------- patch
  console.log('\npatch 台账 + 回滚')
  const patchDry = await session.call('ida_patch', { address: '0x401124', instructions: 'xor eax, eax; retn', dryRun: true })
  check('patch 试运行抓到改前指令', patchDry.before.instructions.length >= 2, patchDry.before)

  const before = patchDry.before.bytes
  const patched = await session.call('ida_patch', {
    address: '0x401124',
    instructions: 'mov eax, 1; retn',
    note: '强制返回真',
  })
  check('patch 写入成功并拿到台账 id', patched.ok === true && Boolean(patched.id), patched)
  check('字节确实变了', patched.changed === true, patched)

  const workspace = await session.call('ida_workspace', { action: 'get' })
  check('台账里有这次 patch', workspace.ledger.some((item) => item.id === patched.id), workspace.ledger)
  check('日志记下了操作', workspace.summary.journal.some((item) => item.action === 'patch'), workspace.summary.journal)

  const rolledBack = await session.call('ida_patch', { address: '0x401124', rollback: patched.id })
  check('回滚成功', rolledBack.ok === true && rolledBack.byteExact === true, rolledBack)

  const afterRollback = await session.call('ida_raw', { method: 'read_memory_bytes', params: ['0x401124', 32] })
  const afterBytes = afterRollback.result?.value ?? afterRollback.result
  check('回滚后字节复原', afterBytes === before, { now: afterBytes, before })

  // ---------------------------------------------------------------- 导出
  console.log('\n导出与工作区')
  const exported = await session.call('ida_export', { target: 'verify_checksum' })
  check('导出 markdown 落盘', exported.ok === true && exported.bytes > 200 && Boolean(exported.path), exported)
  check('默认写进 outDir', String(exported.path).startsWith(outDir), exported.path)

  const inline = await session.call('ida_export', { target: 'verify_checksum', write: false })
  check('write=false 返回正文', inline.ok === true && inline.written === false && typeof inline.markdown === 'string' && inline.markdown.includes('```c'), Object.keys(inline))
  const inlineRendered = await session.render('ida_export', { target: 'verify_checksum', write: false })
  check('write=false 的正文出现在渲染里', inlineRendered.text.includes('verify_checksum') && inlineRendered.text.includes('```c'), inlineRendered.text.slice(0, 200))

  const inlineTrue = await session.call('ida_export', { target: 'verify_checksum', inline: true })
  check('inline=true 既落盘又给正文', inlineTrue.written === true && typeof inlineTrue.markdown === 'string', Object.keys(inlineTrue))

  const noteResult = await session.call('ida_workspace', { action: 'note', note: '下一轮看 sub_401200' })
  check('写分析日志', noteResult.summary.journal.length > 0, noteResult.summary)

  // ---------------------------------------------------------------- 标准 MCP
  console.log('\n标准 MCP（新版 ida-pro-mcp / 官方 HexRays 服务）')
  const mcpSession = mount({ url: 'http://127.0.0.1:13339/mcp', allow: 'patch', outDir })
  const mcpStatus = await mcpSession.call('ida_status')
  check('识别为标准 MCP', mcpStatus.connected === true && mcpStatus.bridge.mode === 'mcp', mcpStatus.bridge)
  check('tools/list 拿到工具数', mcpStatus.bridge.toolCount > 5, mcpStatus.bridge.toolCount)
  const mcpFunc = await mcpSession.call('ida_func', { target: 'main' })
  check('MCP 通道能反编译', mcpFunc.pseudocode.text.includes('0x401000'), mcpFunc.pseudocode.text?.slice(0, 80))
  const mcpAnnotate = await mcpSession.call('ida_annotate', {
    target: 'main',
    comments: [{ address: '0x40100f', text: 'calls the verifier' }],
  })
  check('MCP 通道能写注释', mcpAnnotate.ok === true, mcpAnnotate)
  const mcpMethods = await mcpSession.call('ida_methods')
  check('MCP 通道能列工具名', mcpMethods.ok === true && mcpMethods.mode === 'mcp', mcpMethods)

  // ---------------------------------------------------------------- 连不上
  console.log('\n连不上时的表现')
  const deadSession = mount({ url: 'http://127.0.0.1:13399/mcp', allow: 'annotate', outDir })
  const dead = await deadSession.call('ida_status')
  check('status 不抛异常而是给诊断', dead.connected === false && String(dead.hint).includes('检查顺序'), dead)
  let threw = null
  try {
    await deadSession.call('ida_func', { target: 'main' })
  } catch (error) {
    threw = error
  }
  check('业务工具抛明确错误', Boolean(threw) && threw.message.includes('连不上'), threw?.message)
} finally {
  await legacy.close()
  await mcpMock.close()
  rmSync(outDir, { recursive: true, force: true })
}

console.log(`\n${pass} 通过，${fail} 失败`)
process.exit(fail === 0 ? 0 : 1)
