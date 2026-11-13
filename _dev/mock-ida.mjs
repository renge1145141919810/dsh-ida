/**
 * 假 IDA：一个只在内存里的 mcp-plugin 仿制品，用来在没开 IDA 的情况下验证插件。
 *
 * 刻意模仿真实插件的两个坑，好让测试真的能抓到 bug：
 *   1. 参数按位置传，数量必须和签名完全一致，多一个少一个都报 -32602。
 *   2. 错误以 {error:{code,message}} 返回，HTTP 状态码永远是 200。
 *
 * 另外它维护内存状态（名字/注释/指令），所以「写完之后回读校验」和「patch 后回滚」
 * 这两条链路是真的被验证过的，不是看日志猜的。
 *
 * 用法：
 *   node _dev/mock-ida.mjs             # 旧协议，13338
 *   node _dev/mock-ida.mjs --mcp       # 标准 MCP，13339
 */

import http from 'node:http'
import { createHash } from 'node:crypto'

const FUNCS = [
  { address: '0x401000', name: 'main', size: '0x120' },
  { address: '0x401120', name: 'check_password', size: '0xe0' },
  { address: '0x401200', name: 'sub_401200', size: '0x60' },
]

const DISASM = {
  main: [
    ['0x401000', 'push    rbp'],
    ['0x401001', 'mov     rbp, rsp'],
    ['0x401004', 'sub     rsp, 20h'],
    ['0x401008', 'lea     rdi, aPassword'],
    ['0x40100f', 'call    check_password'],
    ['0x401014', 'test    eax, eax'],
    ['0x401016', 'jz      short loc_401020'],
    ['0x401018', 'mov     eax, 1'],
    ['0x40101d', 'retn'],
  ],
  check_password: [
    ['0x401120', 'push    rbp'],
    ['0x401121', 'mov     rbp, rsp'],
    ['0x401124', 'xor     eax, eax'],
    ['0x401126', 'mov     ecx, 8'],
    ['0x40112b', 'add     eax, [rdi+rcx*4]'],
    ['0x40112f', 'sub     ecx, 1'],
    ['0x401132', 'jnz     short loc_40112B'],
    ['0x401134', 'retn'],
  ],
  sub_401200: [
    ['0x401200', 'xor     eax, eax'],
    ['0x401202', 'retn'],
  ],
}

const PSEUDO = {
  main: [
    [0, '0x401000', 'int __cdecl main(int argc, const char **argv, const char **envp)'],
    [1, null, '{'],
    [2, '0x401008', '  const char *v3; // rdi'],
    [3, '0x40100f', '  v3 = "password";'],
    [4, '0x40100f', '  if ( (unsigned __int8)check_password(v3) )'],
    [5, null, '  {'],
    [6, '0x401018', '    return 1;'],
    [7, null, '  }'],
    [8, '0x40101d', '  return 0;'],
    [9, null, '}'],
  ],
  check_password: [
    [0, '0x401120', 'int __cdecl check_password(const char *a1)'],
    [1, null, '{'],
    [2, '0x401124', '  int v1; // eax'],
    [3, '0x401126', '  int v2; // ecx'],
    [4, '0x40112b', '  v1 = 0;'],
    [5, '0x40112b', '  v2 = 8;'],
    [6, '0x40112b', '  do { v1 += a1[v2]; --v2; } while ( v2 );'],
    [7, '0x401134', '  return v1 == 0x1A2B;'],
    [8, null, '}'],
  ],
  sub_401200: [
    [0, '0x401200', 'int __cdecl sub_401200()'],
    [1, null, '{'],
    [2, '0x401202', '  return 0;'],
    [3, null, '}'],
  ],
}

export function createMock () {
  const state = {
    names: new Map(FUNCS.map((fn) => [fn.address, fn.name])),
    comments: new Map(),
    lines: new Map(Object.entries(DISASM).map(([key, rows]) => [key, rows.map(([address, instruction]) => ({ address, instruction }))])),
    prototypes: new Map(),
  }

  const meta = () => ({
    path: 'C:\\work\\crackme.exe',
    module: 'crackme.exe',
    base: '0x400000',
    size: '0x1f000',
    md5: 'a'.repeat(32),
    sha256: 'b'.repeat(64),
    crc32: '0xdeadbeef',
    filesize: '0x20000',
  })

  const findFunc = (address) => {
    const value = Number.parseInt(String(address).replace(/^0x/i, ''), 16)
    return FUNCS.find((fn) => {
      const start = Number.parseInt(fn.address.replace(/^0x/i, ''), 16)
      const size = Number.parseInt(fn.size.replace(/^0x/i, ''), 16)
      return value >= start && value < start + size
    })
  }

  const funcOf = (fn) => ({ address: fn.address, name: state.names.get(fn.address) || fn.name, size: fn.size })

  const insnBytes = (instruction) =>
    Array.from(createHash('sha1').update(String(instruction)).digest().subarray(0, 4))

  const bytesFor = (address, size) => {
    const key = String(address).toLowerCase()
    if (DATA[key]) {
      const out = [...DATA[key]]
      while (out.length < size) out.push(0)
      return out.slice(0, size).map((byte) => `0x${byte.toString(16).padStart(2, '0')}`).join(' ')
    }
    const fn = findFunc(address)
    if (!fn) throw idaError(`Failed to read memory at ${address}`)
    const rows = state.lines.get(fn.name) || []
    const start = Number.parseInt(String(address).replace(/^0x/i, ''), 16)
    const out = []
    for (const row of rows) {
      const at = Number.parseInt(row.address.replace(/^0x/i, ''), 16)
      if (at < start) continue
      for (const byte of insnBytes(row.instruction)) {
        if (out.length >= size) break
        out.push(byte)
      }
      if (out.length >= size) break
    }
    while (out.length < size) out.push(0)
    return out.slice(0, size).map((byte) => `0x${byte.toString(16).padStart(2, '0')}`).join(' ')
  }

  const pseudoOf = (address) => {
    const fn = findFunc(address)
    if (!fn) throw idaError(`No function found at address ${address}`)
    const rows = PSEUDO[fn.name]
    if (!rows) throw idaError('Decompiler license is not available')
    return rows
      .map(([line, addr, code]) => (addr ? `/* line: ${line}, address: ${addr} */ ${code}` : `/* line: ${line} */ ${code}`))
      .join('\n')
  }

  const disasmOf = (address) => {
    const fn = findFunc(address)
    if (!fn) throw idaError(`No function found at address ${address}`)
    const rows = state.lines.get(fn.name) || []
    return {
      name: state.names.get(fn.address) || fn.name,
      start_ea: fn.address,
      return_type: 'int',
      arguments: [{ name: 'a1', type: 'const char *' }],
      stack_frame: [{ name: 'var_8', offset: '-0x8', size: '0x8', type: 'int' }],
      lines: rows.map((row) => {
        const comments = state.comments.get(row.address)
        return {
          address: row.address,
          instruction: row.instruction,
          ...(comments && comments.length ? { comments: [...comments] } : {}),
        }
      }),
    }
  }

  const page = (data, offset, count) => {
    const from = Number(offset) || 0
    const take = Number(count) || 0
    const slice = take > 0 ? data.slice(from, from + take) : data.slice(from)
    const next = take > 0 && from + take < data.length ? from + take : null
    return { data: slice, next_offset: next }
  }

  // 数据段：让「按地址读字节」有东西可读，而不用编造成函数内部
  const DATA = {
    '0x40301c': [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff],
    '0x403028': [0xde, 0xad, 0xbe, 0xef],
    '0x403000': [0x2a, 0x00, 0x00, 0x00],
  }

  state.globals = new Map([
    ['0x403000', 'g_checksum'],
    ['0x403018', 'g_state_x'],
    ['0x40301c', 'byte_40301C'],
    ['0x403028', 'byte_403028'],
    // 留给「索引截断时靠名字里的地址片段兜底」的样本，别在别的测试里改名
    ['0x403040', 'byte_403040'],
  ])

  // 真机上的一个具体毛病：0x403018 「按地址」取类型失败，但「按名字」能取到。
  // 这里如实复现，用来测插件的回退逻辑。
  state.addressValueBroken = new Set(['0x403018'])
  // 索引被页数上限截断（大 IDB 上万命名时的表现）：不带 filter 的枚举返回空，
  // 但带 filter 的查询仍然正常 —— 用它测 ida_find 的第二条路。
  state.globalListBroken = false
  // 结构体层整块挂掉（老 SDK 上 get_ordinal_limit 缺失时的表现）
  state.structsBroken = false

  state.stack = new Map([
    ['var_8', { name: 'var_8', offset: '-0x8', size: '0x8', type: 'int' }],
  ])

  state.structs = new Map([
    ['cfg_header', {
      name: 'cfg_header',
      size: '0x20',
      members: [
        { name: 'magic', offset: '0x0', size: '0x4', type: 'unsigned int' },
        { name: 'ver', offset: '0x4', size: '0x2', type: 'unsigned short' },
        { name: 'len', offset: '0x8', size: '0x4', type: 'unsigned int' },
      ],
    }],
  ])

  const methods = {
    get_metadata: { params: [], run: () => meta() },
    get_function_by_name: {
      params: ['name'],
      run: ([name]) => {
        const fn = FUNCS.find((item) => (state.names.get(item.address) || item.name) === name || item.name === name)
        if (!fn) throw idaError(`No function found with name ${name}`)
        return funcOf(fn)
      },
    },
    get_function_by_address: {
      params: ['address'],
      run: ([address]) => {
        const fn = findFunc(address)
        if (!fn) throw idaError(`No function found at address ${address}`)
        return funcOf(fn)
      },
    },
    list_functions: { params: ['offset', 'count'], run: ([offset, count]) => page(FUNCS.map(funcOf), offset, count) },
    decompile_function: { params: ['address'], run: ([address]) => pseudoOf(address) },
    disassemble_function: { params: ['start_address'], run: ([address]) => disasmOf(address) },
    get_xrefs_to: {
      params: ['address'],
      run: ([address]) => [{ address: '0x40100f', type: 'Code(3)', function: funcOf(FUNCS[0]) }],
    },
    get_callers: { params: ['function_address'], run: () => [funcOf(FUNCS[0])] },
    get_callees: { params: ['function_address'], run: () => [{ address: '0x401120', name: 'check_password' }] },
    set_comment: {
      params: ['address', 'comment'],
      run: ([address, comment]) => {
        const key = String(address).toLowerCase()
        const list = state.comments.get(key) || []
        state.comments.set(key, [...list.filter((item) => item !== comment), comment])
        return null
      },
    },
    rename_function: {
      params: ['function_address', 'new_name'],
      run: ([address, newName]) => {
        const fn = findFunc(address)
        if (!fn) throw idaError(`No function found at address ${address}`)
        state.names.set(fn.address, newName)
        return null
      },
    },
    set_function_prototype: {
      params: ['function_address', 'prototype'],
      run: ([address, prototype]) => {
        const fn = findFunc(address)
        if (!fn) throw idaError(`No function found at address ${address}`)
        const text = String(prototype)
        if (!text.includes('(') || !text.includes(')')) {
          throw idaError(`Failed to parse prototype string: ${prototype}`)
        }
        // 真实 IDA 的两个雷区，这里如实复现：
        //   1. Hex-Rays 伪代码类型名（_BYTE/_DWORD）不是 C 类型，解析必失败；
        //   2. 带函数名的声明不是「函数类型」，apply_tinfo 会拒绝。
        if (/_BYTE|_DWORD|_QWORD|_OWORD/.test(text)) {
          throw idaError(`Failed to parse prototype string: ${prototype}`)
        }
        const open = text.indexOf('(')
        const prefix = text.slice(0, open).trim().split(/\s+/)
        const last = prefix[prefix.length - 1]
        if (prefix.length >= 2 && /^[A-Za-z_][A-Za-z0-9_]*$/.test(last) && !/^__(cdecl|stdcall|fastcall|thiscall)$/.test(last)) {
          throw idaError(`Parsed declaration is not a function type`)
        }
        if (/HWND|INT_PTR/.test(text)) throw idaError(`Failed to parse prototype string: ${prototype}`)
        state.prototypes.set(fn.address, text)
        return null
      },
    },
    rename_local_variable: {
      params: ['function_address', 'old_name', 'new_name'],
      run: ([address, from, to]) => {
        if (!findFunc(address)) throw idaError(`No function found at address ${address}`)
        if (!['v1', 'v2', 'v3', 'a1', 'a2', 'argc', 'argv'].includes(from)) {
          throw idaError(`Failed to rename local variable ${from}`)
        }
        return null
      },
    },
    set_local_variable_type: { params: ['function_address', 'variable_name', 'new_type'], run: () => null },
    declare_c_type: { params: ['c_declaration'], run: ([decl]) => `success\n\nInfo:/nparsed ${decl}` },
    patch_address_assembles: {
      params: ['address', 'instructions'],
      run: ([address, instructions]) => {
        const fn = findFunc(address)
        if (!fn) throw idaError(`No function found at address ${address}`)
        const list = String(instructions).split(';').map((item) => item.trim()).filter(Boolean)
        const rows = state.lines.get(fn.name) || []
        const index = rows.findIndex((row) => row.address.toLowerCase() === String(address).toLowerCase())
        if (index < 0) throw idaError(`Failed to patch bytes at address ${address}: not an instruction boundary`)
        const patched = list.map((instruction, offset) => ({
          address: `0x${(Number.parseInt(String(address).replace(/^0x/i, ''), 16) + offset * 4).toString(16)}`,
          instruction,
        }))
        state.lines.set(fn.name, [...rows.slice(0, index), ...patched, ...rows.slice(index + list.length)])
        return `Patched ${list.length} instructions`
      },
    },
    read_memory_bytes: {
      params: ['memory_address', 'size'],
      run: ([address, size]) => bytesFor(address, Number(size) || 16),
    },
    list_strings_filter: {
      params: ['offset', 'count', 'filter'],
      run: ([offset, count, filter]) => {
        const strings = [
          { address: '0x402000', length: 9, string: 'password' },
          { address: '0x402010', length: 14, string: 'wrong password' },
          { address: '0x402020', length: 7, string: 'correct' },
        ].filter((item) => !filter || item.string.toLowerCase().includes(String(filter).toLowerCase()))
        return page(strings, offset, count)
      },
    },
    list_globals_filter: {
      params: ['offset', 'count', 'filter'],
      run: ([offset, count, filter]) => {
        if (state.globalListBroken && !filter) return { data: [], next_offset: null }
        const globals = [...state.globals].map(([address, name]) => ({ address, name }))
          .filter((item) => !filter || item.name.toLowerCase().includes(String(filter).toLowerCase()))
        return page(globals, offset, count)
      },
    },
    list_globals: {
      params: ['offset', 'count'],
      run: ([offset, count]) => methods.list_globals_filter.run([offset, count, '']),
    },
    rename_global_variable: {
      params: ['old_name', 'new_name'],
      run: ([oldName, newName]) => {
        for (const [address, name] of state.globals) {
          if (name === oldName) {
            state.globals.set(address, newName)
            return null
          }
        }
        throw idaError(`Failed to rename global variable ${oldName} to ${newName}`)
      },
    },
    set_global_variable_type: {
      params: ['variable_name', 'new_type'],
      run: ([variable]) => {
        if (![...state.globals.values()].includes(variable)) throw idaError('Parsed declaration is not a variable type')
        return null
      },
    },
    get_global_variable_value_by_name: {
      params: ['variable_name'],
      run: ([variable]) => {
        const entry = [...state.globals].find(([, name]) => name === variable)
        if (!entry) throw idaError(`Global variable ${variable} not found`)
        return '0x1A2B'
      },
    },
    get_global_variable_value_at_address: {
      params: ['address'],
      run: ([address]) => {
        const key = String(address).toLowerCase()
        if (!state.globals.has(key)) throw idaError(`No global variable at ${address}`)
        if (state.addressValueBroken.has(key)) throw idaError(`Failed to get type information for variable at ${address}`)
        return '0x1A2B'
      },
    },
    get_defined_structures: {
      params: [],
      run: () => {
        if (state.structsBroken) throw idaError("module 'ida_typeinf' has no attribute 'get_ordinal_limit'")
        return [...state.structs.values()]
      },
    },
    analyze_struct_detailed: {
      params: ['name'],
      run: ([name]) => {
        const struct = state.structs.get(name)
        if (!struct) throw idaError(`Structure '${name}' not found`)
        return { name: struct.name, size: struct.size, members: struct.members }
      },
    },
    get_struct_at_address: {
      params: ['address', 'struct_name'],
      run: ([address, name]) => ({
        struct_name: name,
        address: String(address),
        members: (state.structs.get(name)?.members || []).map((member) => ({ ...member, value: '0x0' })),
      }),
    },
    search_structures: {
      params: ['filter'],
      run: ([filter]) => [...state.structs.values()].filter((item) => !filter || item.name.includes(String(filter))),
    },
    list_local_types: { params: [], run: () => [{ name: 'cfg_header', ordinal: 1 }] },
    get_stack_frame_variables: {
      params: ['function_address'],
      run: () => [...state.stack.values()],
    },
    rename_stack_frame_variable: {
      params: ['function_address', 'old_name', 'new_name'],
      run: ([address, from, to]) => {
        const slot = state.stack.get(from)
        if (!slot) throw idaError(`${from} not found`)
        state.stack.delete(from)
        state.stack.set(to, { ...slot, name: to })
        return null
      },
    },
    set_stack_frame_variable_type: {
      params: ['function_address', 'variable_name', 'type_name'],
      run: ([address, variable, type]) => {
        const slot = state.stack.get(variable)
        if (!slot) throw idaError(`${variable} not found.`)
        state.stack.set(variable, { ...slot, type })
        return null
      },
    },
    create_stack_frame_variable: {
      params: ['function_address', 'offset', 'variable_name', 'type_name'],
      run: ([address, offset, variable, type]) => {
        state.stack.set(variable, { name: variable, offset: String(offset), size: '0x4', type })
        return null
      },
    },
    delete_stack_frame_variable: {
      params: ['function_address', 'variable_name'],
      run: ([address, variable]) => {
        if (!state.stack.delete(variable)) throw idaError('failed to delete stack frame variable')
        return null
      },
    },
    list_imports: {
      params: ['offset', 'count'],
      run: ([offset, count]) =>
        page(
          [
            { address: '0x402100', imported_name: 'printf', module: 'msvcrt' },
            { address: '0x402108', imported_name: 'strcmp', module: 'msvcrt' },
          ],
          offset,
          count
        ),
    },
    get_entry_points: { params: [], run: () => [funcOf(FUNCS[0])] },
    dbg_get_registers: { params: [], unsafe: true, run: () => [] },
  }

  // ---------------------------------------------------------------- MCP 形态
  const MCP_TOOLS = {
    get_metadata: () => meta(),
    lookup_funcs: ({ queries }) => {
      const key = String(queries)
      if (/^0x[0-9a-f]+$/i.test(key) || /^\d+$/.test(key)) return methods.get_function_by_address.run([key])
      return methods.get_function_by_name.run([key])
    },
    list_funcs: ({ offset = 0, count = 100 }) => methods.list_functions.run([offset, count]),
    decompile: ({ addr }) => methods.decompile_function.run([addr]),
    disasm: ({ addr }) => methods.disassemble_function.run([addr]),
    xrefs_to: ({ addrs }) => methods.get_xrefs_to.run([addrs]),
    callees: () => methods.get_callees.run([]),
    set_comments: ({ items = [] }) => {
      for (const item of items) methods.set_comment.run([item.addr, item.comment])
      return { ok: true }
    },
    rename: ({ batch = {} }) => {
      for (const item of batch.func || []) methods.rename_function.run([item.addr, item.name])
      return { ok: true }
    },
    set_type: ({ edits = [] }) => {
      for (const item of edits) {
        if (item.type) methods.set_function_prototype.run([item.addr, item.type])
      }
      return { ok: true }
    },
    patch_asm: ({ patches = [] }) => {
      for (const item of patches) methods.patch_address_assembles.run([item.addr, item.asm])
      return { ok: true }
    },
    get_bytes: ({ addrs, size = 16 }) => methods.read_memory_bytes.run([addrs, size]),
    list_globals: ({ offset = 0, count = 100, filter = '' }) => methods.list_globals_filter.run([offset, count, filter]),
    imports: ({ offset = 0, count = 100 }) => methods.list_imports.run([offset, count]),
    find_regex: ({ queries }) => methods.list_strings_filter.run([0, 50, queries]),
    entry_points: () => methods.get_entry_points.run([]),
    stack_frame: ({ addrs }) => methods.get_stack_frame_variables.run([addrs]),
    get_defined_structures: () => methods.get_defined_structures.run([]),
    list_local_types: () => methods.list_local_types.run([]),
  }

  return { state, methods, meta, bytesFor, MCP_TOOLS }
}

function idaError (message) {
  const error = new Error(message)
  error.ida = true
  return error
}

function dispatch (mock, method, params) {
  const entry = mock.methods[method]
  if (!entry) return { error: { code: -32601, message: `Method '${method}' not found` } }
  const names = entry.params

  let args = []
  if (Array.isArray(params)) {
    if (params.length !== names.length) {
      return { error: { code: -32602, message: `Invalid params: expected ${names.length} arguments, got ${params.length}` } }
    }
    args = params
  } else if (params && typeof params === 'object') {
    // 真实插件要求键集合和签名完全一致，多一个少一个都 -32602
    const given = Object.keys(params)
    const missing = names.filter((name) => !given.includes(name))
    const extra = given.filter((name) => !names.includes(name))
    if (missing.length || extra.length) {
      return { error: { code: -32602, message: `Invalid params: expected ${JSON.stringify(names)}` } }
    }
    args = names.map((name) => params[name])
  } else {
    return { error: { code: -32600, message: 'Invalid Request: params must be array or object' } }
  }

  try {
    return { result: entry.run(args) }
  } catch (error) {
    return { error: { code: error.ida ? -32000 : -32603, message: error.message } }
  }
}

export function startMock ({ port = 13338, mcp = false } = {}) {
  const mock = createMock()
  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405).end()
      return
    }
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
    })
    req.on('end', () => {
      let request
      try {
        request = JSON.parse(raw)
      } catch {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } }))
        return
      }

      if (request.id === undefined) {
        // notifications/initialized 之类
        res.writeHead(202).end()
        return
      }

      const envelope = { jsonrpc: '2.0', id: request.id }
      if (mcp) {
        if (request.method === 'initialize') {
          envelope.result = {
            protocolVersion: '2025-06-18',
            capabilities: { tools: {} },
            serverInfo: { name: 'mock-ida', version: '9.0-mock' },
          }
        } else if (request.method === 'tools/list') {
          envelope.result = { tools: Object.keys(mock.MCP_TOOLS).map((name) => ({ name, inputSchema: { type: 'object' } })) }
        } else if (request.method === 'tools/call') {
          const tool = mock.MCP_TOOLS[request.params?.name]
          if (!tool) {
            envelope.error = { code: -32601, message: `Unknown tool ${request.params?.name}` }
          } else {
            try {
              envelope.result = {
                content: [{ type: 'text', text: JSON.stringify(tool(request.params?.arguments || {})) }],
              }
            } catch (error) {
              envelope.result = { isError: true, content: [{ type: 'text', text: error.message }] }
            }
          }
        } else {
          envelope.error = { code: -32601, message: 'not found' }
        }
      } else {
        Object.assign(envelope, dispatch(mock, request.method, request.params))
      }

      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(envelope))
    })
  })

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      resolve({ mock, server, port, close: () => new Promise((done) => server.close(done)) })
    })
  })
}

const isMain = process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('_dev/mock-ida.mjs')
if (isMain) {
  const mcp = process.argv.includes('--mcp')
  const port = mcp ? 13339 : 13338
  const { close } = await startMock({ port, mcp })
  console.log(`假 IDA 已启动${mcp ? '（标准 MCP）' : '（旧版 JSON-RPC）'} → http://127.0.0.1:${port}/mcp`)
  process.on('SIGINT', () => {
    close().then(() => process.exit(0))
  })
}
