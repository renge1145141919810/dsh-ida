# dsh-ida

把本机 **IDA Pro** 接进 [DSH](https://github.com/deepseek-ai) 的插件。

目标不是把 IDA 的 59 个 RPC 原样暴露给模型，而是让模型**留在 IDB 里**完成逆向：读伪代码、写注释、改函数名和类型、打补丁并留账，跨会话还能接着做。

```
模型 → dsh-ida → mcp-plugin.py（IDA 内）→ IDB
```

## 特性

- **一次调用拿全一个函数**：伪代码（逐行地址）、可选反汇编、交叉引用、调用方/被调方、工作区里已有的命名和注释
- **地址锚定 + 回读校验**：注释必须挂在具体地址上，写完回读，防止“说写了其实没写”
- **批量标注**：改名 / 原型 / 局部变量 / 注释 / 全局变量 / 类型，一次调用逐项成败
- **patch 台账**：改字节前抓原指令，记 `ledger.jsonl`，支持按 id 回滚
- **持久工作区**：命名表、注释镜像、函数结论存本地 JSON，**IDA 关掉也能读**
- **IDA 8.x 兼容层**：上游插件按 9.x SDK 写，8.x 上类型/结构体/栈帧整块失效，这里补回来

## 环境要求

- IDA Pro **8.3+**（8.x 需要打兼容补丁，见下）
- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的 `mcp-plugin.py` 已装进 IDA，服务默认监听 `127.0.0.1:13337`
- DSH（DeepSeek Harness） Desktop
- Node.js 18+

## 安装

**1. IDA 侧**

把 `mcp-plugin.py` 放进 IDA 的插件目录，在 IDA 里 `Edit → Plugins → MCP` 启动服务，Output 出现：

```
[MCP] Server started at http://localhost:13337
```

**2. DSH 侧**

```bash
cd ~/.dsh/profiles/desktop
git clone https://github.com/<your-name>/dsh-ida.git node_modules/dsh-ida
```

在 `~/.dsh/profiles/desktop/package.json` 里登记：

```jsonc
{
  "dependencies": {
    "dsh-ida": "file:./node_modules/dsh-ida"
  },
  "dsh": {
    "profile": {
      "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app", "dsh-ida"]
    }
  }
}
```

**3. 重启 DSH**，然后让模型调一次 `ida_status`。

## 配置

`cordis.patch.yml` 或 profile 里：

```yaml
- insert:
    - id: dsh-ida
      name: dsh-ida
      config:
        url: http://127.0.0.1:13337/mcp
        allow: annotate
```

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `url` | `http://127.0.0.1:13337/mcp` | IDA MCP 端点；新旧两种协议都认 |
| `allow` | `annotate` | `off` 只读 / `annotate` 可写注释改名 / `patch` 另允许改字节 |
| `timeoutMs` | `45000` | 单次 RPC 超时 |
| `maxLines` | `400` | 伪代码默认返回行数 |
| `dir` | `%LOCALAPPDATA%\dsh-ida` | 工作区根目录，可搬到项目里一起提交 |
| `outDir` | 会话当前目录 | `ida_export` 默认输出目录 |

环境变量：`DSH_IDA_URL`、`DSH_IDA_ALLOW`、`DSH_IDA_TIMEOUT`、`DSH_IDA_DIR`、`DSH_IDA_OUT`。

## 工具

| 工具 | 用途 |
| --- | --- |
| `ida_status` | 连接诊断、协议识别、IDB 信息、工作区概况；断连时列出本地工作区 |
| `ida_func` | 一次拿全：伪代码 + 反汇编 + 交叉引用 + 调用关系 + 工作区记录 |
| `ida_annotate` | 批量写：函数改名 / 原型 / 类型声明 / 局部变量 / 注释 / 全局变量 |
| `ida_patch` | 汇编级 patch，带改前快照与台账，支持回滚 |
| `ida_data` | 数据层：读字节、全局值、改名改类型、结构体、栈帧 |
| `ida_find` | 找函数 / 字符串 / 全局 / 导入 / 入口，支持正则 |
| `ida_methods` | 列出真实方法签名（旧协议 59 个），标 `[写]` / `[unsafe]` |
| `ida_raw` | 原始方法直通，别名纠正、拼错给候选 |
| `ida_workspace` | 工作区读写（`get` / `put` / `note` / `list`），IDA 关着也能用 |
| `ida_export` | 导出 markdown 重构稿，可内联返回 |
| `ida_addr` | IDA 静态地址 ↔ 运行时地址换算（配 Cheat Engine） |

## 权限模型

| `allow` | 能做什么 |
| --- | --- |
| `off` | 只读：读伪代码、字节、引用 |
| `annotate` | 另可改名、写注释、改类型、建结构体 |
| `patch` | 另可 `ida_patch` 改指令、调试器类 `unsafe` 方法 |

写操作都会回读校验并记入工作区日志；patch 额外落 `ledger.jsonl`，可 `rollback: "last"`。

## IDA 8.x 兼容补丁

上游 `mcp-plugin.py` 按 IDA 9.x SDK 写，8.x 上会缺 `PT_EMPTY`、`get_ordinal_limit` 等符号，表现为：

- `declare_c_type` / `structs` / `declareType` 整块 Internal error
- `set_function_prototype` 100% 失败
- 全局改名后伪代码不刷新
- 栈帧层恒为空

补丁**不改原文件**，只往 `mcp-plugin.py` 末尾追加一层兼容实现并重新绑定方法：

```bash
node _dev/patch-ida-plugin.mjs            # 打补丁（自动备份 .bak-dshida + 语法检查）
node _dev/patch-ida-plugin.mjs --check    # 查看状态
node _dev/patch-ida-plugin.mjs --revert   # 回滚
```

重开 IDA，Output 里应出现：

```
[dsh-ida] compat layer v1.1 active on IDA 8.3 (11 methods rebound)
```

> 注意：上游方法都套着 `idawrite` / `idaread` 装饰器，那是把调用调度到 IDA 主线程的，不是日志装饰器。替换时必须重新套上，否则会在 HTTP 线程里直接调 IDA API。

## 工作区

```
%LOCALAPPDATA%\dsh-ida\<模块名>-<哈希>\
  state.json     命名表 / 注释镜像 / 函数结论 / 分析日志
  ledger.jsonl   每次 patch 的原指令、改后、理由
  out/           导出稿
```

- 纯 JSON，可读、可 diff、可提交
- `ida_workspace({ action: "list" })` 列全部；指定 `key` 读取
- IDA 没开也能读历史记录，写入照常落盘

## 开发

不需要开 IDA，仓库自带 mock：

```bash
node _dev/selftest.mjs                        # 全量自测（97 项）
node _dev/offline-workspace.mjs <tmp-dir>     # 离线工作区专项（20 项）
node _dev/gen-manifest.mjs                    # 从 mcp-plugin.py 重新生成方法表
```

## 目录

```
index.js            工具定义与编排
src/rpc.js          连接、协议识别、RPC 封装
src/store.js        工作区与 patch 台账
src/manifest.js     生成的方法表（勿手改）
src/methods.js      方法名解析与参数拼装
src/format.js       地址规范化、hexdump、渲染辅助
src/caps.js         能力探测
_dev/               自测、mock IDA、兼容层与补丁脚本
locale/             中英文案
```

## 许可

[MIT](LICENSE)
