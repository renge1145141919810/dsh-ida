# Changelog

## 0.3.0 — 2026-11-13

老 SDK（IDA 8.x）上失效的层全部修回来，并补上离线工作区。

### 修复

- `declare_c_type` / `list_local_types` / `structs` 在 8.x 上因 `PT_EMPTY`、`get_ordinal_limit` 缺失整块报错
- `set_function_prototype` 100% 失败：改用 `parse_decl` 降级，失败时保留原始报错
- 全局变量改名后伪代码不刷新：按 xref 找到引用函数并 `mark_cfunc_dirty`
- 按地址取全局值失败，按名字可用：统一回退到 item head + item size
- 栈帧层恒为空（`ida_major < 9` 直接 return）：8.x 走 `ida_frame.get_func_frame`
- `renameGlobal` / `stack` 渲染成 `[object Object]`
- `ida_find global` 按地址查不到，提示自相矛盾

### 新增

- **工作区离线读取**：`ida_workspace` 新增 `list` 动作与 `key` 参数，IDA 未连接时直接读本地 `state.json`
- `ida_status` 断连时列出本地工作区，并提示离线读取方式
- 命名表按名字推断 `kind`（`g_*` / `byte_*` → data）
- 注释的 `func` 字段回填改名后的名字
- `_dev/offline-workspace.mjs` 离线路径专项测试

## 0.2.0 — 2026-11-10

第一轮实测反馈的修复。

- `ida_func` 只回标题不回正文 → 重写渲染，伪代码整段输出并带逐行地址
- `ida_export(write=false)` 只回执 → 新增 `inline`，`write:false` 内联正文
- 方法名猜错 → 新增 `ida_methods` 自曝 59 个签名；`ida_raw` 加别名表与编辑距离纠错
- 原型设置失败 → 四种写法依次尝试，全失败给语法指引
- `ida_find global` 把 `4030` 当十进制地址 → 只有 `0x..` / `..h` 才算地址
- 导出默认写到 `%LOCALAPPDATA%` → 默认落会话目录，支持 `dir` / `path`
- `ida_raw` 支持对象参数（键名照签名）

## 0.1.0 — 2026-11-09

首个可用版本。

- 11 个工具（status / func / annotate / patch / data / find / methods / raw / workspace / export / addr）
- 工作区持久化与 patch 台账
- IDA 8.x 兼容层脚本（`_dev/patch-ida-plugin.mjs`）
