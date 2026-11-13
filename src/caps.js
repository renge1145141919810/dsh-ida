/**
 * 能力表：把「我想做的事」翻译成两种协议各自的调用形态。
 *
 * legacy —— 本机 mcp-plugin.py（自定义 JSON-RPC，method 就是函数名，参数按位置顺序，
 *            数量必须与函数签名完全一致，少一个多一个都会报 -32602）。
 * mcp    —— 新版 ida-pro-mcp / 官方 HexRays MCP（标准 MCP，tools/call + 具名参数）。
 *
 * 加新能力只需要在这里补一条，index.js 里不用关心协议差异。
 */

export const CAPS = {
  meta: {
    legacy: { method: 'get_metadata', build: () => [] },
    mcp: { candidates: ['get_metadata', 'metadata'], build: () => ({}) },
  },
  funcByName: {
    legacy: { method: 'get_function_by_name', build: ({ name }) => [name] },
    mcp: { candidates: ['lookup_funcs'], build: ({ name }) => ({ queries: name }) },
  },
  funcByAddr: {
    legacy: { method: 'get_function_by_address', build: ({ addr }) => [addr] },
    mcp: { candidates: ['lookup_funcs'], build: ({ addr }) => ({ queries: addr }) },
  },
  currentFunction: {
    legacy: { method: 'get_current_function', build: () => [] },
    mcp: { candidates: [], build: () => ({}) },
  },
  currentAddress: {
    legacy: { method: 'get_current_address', build: () => [] },
    mcp: { candidates: [], build: () => ({}) },
  },
  listFuncs: {
    legacy: { method: 'list_functions', build: ({ offset = 0, count = 100 }) => [offset, count] },
    mcp: { candidates: ['list_funcs'], build: ({ offset = 0, count = 100 }) => ({ offset, count }) },
  },
  decompile: {
    legacy: { method: 'decompile_function', build: ({ addr }) => [addr] },
    mcp: { candidates: ['decompile'], build: ({ addr }) => ({ addr }) },
  },
  disasm: {
    legacy: { method: 'disassemble_function', build: ({ addr }) => [addr] },
    mcp: { candidates: ['disasm'], build: ({ addr }) => ({ addr }) },
  },
  xrefsTo: {
    legacy: { method: 'get_xrefs_to', build: ({ addr }) => [addr] },
    mcp: { candidates: ['xrefs_to'], build: ({ addr }) => ({ addrs: addr }) },
  },
  callers: {
    legacy: { method: 'get_callers', build: ({ addr }) => [addr] },
    // 新版没有 callers，语义上等于对函数入口做 xrefs_to（需要调用方自己过滤）
    mcp: { candidates: ['xrefs_to', 'callers'], build: ({ addr }) => ({ addrs: addr }) },
  },
  callees: {
    legacy: { method: 'get_callees', build: ({ addr }) => [addr] },
    mcp: { candidates: ['callees'], build: ({ addr }) => ({ addrs: addr }) },
  },
  setComment: {
    legacy: { method: 'set_comment', build: ({ addr, text }) => [addr, text] },
    mcp: { candidates: ['set_comments'], build: ({ addr, text }) => ({ items: [{ addr, comment: text }] }) },
  },
  renameFunc: {
    legacy: { method: 'rename_function', build: ({ addr, name }) => [addr, name] },
    mcp: { candidates: ['rename'], build: ({ addr, name }) => ({ batch: { func: [{ addr, name }] } }) },
  },
  setProto: {
    legacy: { method: 'set_function_prototype', build: ({ addr, prototype }) => [addr, prototype] },
    mcp: { candidates: ['set_type', 'set_function_prototype'], build: ({ addr, prototype }) => ({ edits: [{ addr, type: prototype }] }) },
  },
  renameLocal: {
    legacy: { method: 'rename_local_variable', build: ({ func, from, to }) => [func, from, to] },
    mcp: { candidates: ['rename'], build: ({ func, from, to }) => ({ batch: { local: [{ func, old: from, name: to }] } }) },
  },
  setLocalType: {
    legacy: { method: 'set_local_variable_type', build: ({ func, variable, type }) => [func, variable, type] },
    mcp: { candidates: ['set_type'], build: ({ func, variable, type }) => ({ edits: [{ func, var: variable, type }] }) },
  },
  declareType: {
    legacy: { method: 'declare_c_type', build: ({ declaration }) => [declaration] },
    mcp: { candidates: ['declare_type'], build: ({ declaration }) => ({ decls: [declaration] }) },
  },
  patchAsm: {
    legacy: { method: 'patch_address_assembles', build: ({ addr, instructions }) => [addr, instructions] },
    mcp: { candidates: ['patch_asm'], build: ({ addr, instructions }) => ({ patches: [{ addr, asm: instructions }] }) },
  },
  readBytes: {
    legacy: { method: 'read_memory_bytes', build: ({ addr, size }) => [addr, size] },
    mcp: { candidates: ['get_bytes'], build: ({ addr, size }) => ({ addrs: addr, size }) },
  },
  // ---- 数据层：全局变量 / 结构体 / 栈帧。逆向里命名的价值有一半在这些东西上，
  // 之前只有函数能改名，byte_403028 这种名字就烂在库里了。
  renameGlobal: {
    legacy: { method: 'rename_global_variable', build: ({ from, to }) => [from, to] },
    mcp: { candidates: ['rename'], build: ({ from, to }) => ({ batch: { global: [{ old: from, name: to }] } }) },
  },
  setGlobalType: {
    legacy: { method: 'set_global_variable_type', build: ({ variable, type }) => [variable, type] },
    mcp: { candidates: ['set_type'], build: ({ variable, type }) => ({ edits: [{ var: variable, type }] }) },
  },
  globalByName: {
    legacy: { method: 'get_global_variable_value_by_name', build: ({ variable }) => [variable] },
    mcp: { candidates: ['get_global_value'], build: ({ variable }) => ({ name: variable }) },
  },
  globalAt: {
    legacy: { method: 'get_global_variable_value_at_address', build: ({ addr }) => [addr] },
    mcp: { candidates: ['get_global_value'], build: ({ addr }) => ({ addr }) },
  },
  structs: {
    legacy: { method: 'get_defined_structures', build: () => [] },
    mcp: { candidates: ['get_structs', 'list_structs'], build: () => ({}) },
  },
  structDetail: {
    legacy: { method: 'analyze_struct_detailed', build: ({ name }) => [name] },
    mcp: { candidates: ['get_struct_info'], build: ({ name }) => ({ name }) },
  },
  structAt: {
    legacy: { method: 'get_struct_at_address', build: ({ addr, name }) => [addr, name] },
    mcp: { candidates: ['get_struct_at_address'], build: ({ addr, name }) => ({ addr, name }) },
  },
  searchStructs: {
    legacy: { method: 'search_structures', build: ({ filter }) => [filter] },
    mcp: { candidates: ['search_structs'], build: ({ filter }) => ({ filter }) },
  },
  localTypes: {
    legacy: { method: 'list_local_types', build: () => [] },
    mcp: { candidates: ['list_local_types'], build: () => ({}) },
  },
  renameStack: {
    legacy: { method: 'rename_stack_frame_variable', build: ({ func, from, to }) => [func, from, to] },
    mcp: { candidates: ['rename'], build: ({ func, from, to }) => ({ batch: { stack: [{ func, old: from, name: to }] } }) },
  },
  setStackType: {
    legacy: { method: 'set_stack_frame_variable_type', build: ({ func, variable, type }) => [func, variable, type] },
    mcp: { candidates: ['set_type'], build: ({ func, variable, type }) => ({ edits: [{ func, var: variable, type }] }) },
  },
  createStack: {
    legacy: { method: 'create_stack_frame_variable', build: ({ func, offset, variable, type }) => [func, offset, variable, type] },
    mcp: { candidates: ['create_stack_var'], build: ({ func, offset, variable, type }) => ({ func, offset, name: variable, type }) },
  },
  deleteStack: {
    legacy: { method: 'delete_stack_frame_variable', build: ({ func, variable }) => [func, variable] },
    mcp: { candidates: ['delete_stack_var'], build: ({ func, variable }) => ({ func, name: variable }) },
  },
  strings: {
    legacy: { method: 'list_strings_filter', build: ({ offset = 0, count = 100, filter = '' }) => [offset, count, filter] },
    mcp: { candidates: ['find_regex', 'list_strings'], build: ({ filter = '' }) => ({ queries: filter }) },
  },
  globals: {
    legacy: { method: 'list_globals_filter', build: ({ offset = 0, count = 100, filter = '' }) => [offset, count, filter] },
    mcp: { candidates: ['list_globals'], build: ({ offset = 0, count = 100, filter = '' }) => ({ offset, count, filter }) },
  },
  imports: {
    legacy: { method: 'list_imports', build: ({ offset = 0, count = 200 }) => [offset, count] },
    mcp: { candidates: ['imports'], build: ({ offset = 0, count = 200 }) => ({ offset, count }) },
  },
  stackFrame: {
    legacy: { method: 'get_stack_frame_variables', build: ({ addr }) => [addr] },
    mcp: { candidates: ['stack_frame'], build: ({ addr }) => ({ addrs: addr }) },
  },
  entryPoints: {
    legacy: { method: 'get_entry_points', build: () => [] },
    mcp: { candidates: ['entry_points'], build: () => ({}) },
  },
}

/** 旧协议里被作者标成 unsafe 的方法（只用 ida_raw 才会碰到）。 */
export const UNSAFE_METHODS = new Set([
  'dbg_get_registers',
  'dbg_get_call_stack',
  'dbg_list_breakpoints',
  'dbg_start_process',
  'dbg_exit_process',
  'dbg_continue_process',
  'dbg_run_to',
  'dbg_set_breakpoint',
  'dbg_step_into',
  'dbg_step_over',
  'dbg_delete_breakpoint',
  'dbg_enable_breakpoint',
])
