#!/usr/bin/env node
/**
 * 给 IDA 侧的 mcp-plugin.py 打「老 SDK 兼容补丁」。
 *
 * 上游插件按 IDA 9.x 的 Python SDK 写，用到了 PT_EMPTY / get_ordinal_limit /
 * tinfo_t(decl, til, flags) / get_type_by_tid / get_udm_by_tid 这些新符号。
 * 8.x 上这些要么不存在要么构造失败，于是类型层、结构体层、栈帧层整块失效。
 *
 * 做法：把 _dev/ida-compat.py 追加到 mcp-plugin.py 末尾（它是纯追加，
 * 原函数一个字符都不改，靠末尾重新绑定 rpc_registry.methods 生效）。
 * 这样补丁可重复执行、可一键回滚、升级插件后重跑一次即可。
 *
 *   node _dev/patch-ida-plugin.mjs            打补丁
 *   node _dev/patch-ida-plugin.mjs --check    只看状态
 *   node _dev/patch-ida-plugin.mjs --revert   回滚到打补丁前的备份
 *   node _dev/patch-ida-plugin.mjs --file <路径>
 */
import { readFileSync, writeFileSync, existsSync, copyFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const COMPAT = join(HERE, 'ida-compat.py')
const MARKER = '# ==== dsh-ida plugin compat layer (generated; do not edit here) ===='

const args = process.argv.slice(2)
const mode = args.includes('--revert') ? 'revert' : (args.includes('--check') ? 'check' : 'apply')
const fileArg = args.indexOf('--file')
const target = resolve(
  fileArg >= 0 && args[fileArg + 1]
    ? args[fileArg + 1]
    : join(process.env.APPDATA || join(process.env.USERPROFILE || '', 'AppData', 'Roaming'),
      'Hex-Rays', 'IDA Pro', 'plugins', 'mcp-plugin.py')
)
const backup = `${target}.bak-dshida`

if (!existsSync(target)) {
  console.error(`找不到插件文件：${target}`)
  console.error('用 --file <路径> 指定，或先确认 IDA 里装过 ida-pro-mcp 的 GUI 插件。')
  process.exit(1)
}

const current = readFileSync(target, 'utf8')
const markerAt = current.indexOf(MARKER)
const pristine = markerAt >= 0 ? current.slice(0, markerAt).replace(/\s+$/, '') + '\n' : current
const patched = markerAt >= 0

function status () {
  // 每次都重新读盘：刚写完的时候内存里的 current 还是旧的
  const now = readFileSync(target, 'utf8')
  const isPatched = now.includes(MARKER)
  const lines = []
  lines.push(`插件：${target}`)
  lines.push(`备份：${existsSync(backup) ? backup : '（还没有）'}`)
  lines.push(`状态：${isPatched ? '已打补丁' : '未打补丁'}`)
  if (isPatched) {
    const version = /_DSH_COMPAT_VERSION = "([^"]+)"/.exec(now)
    lines.push(`补丁版本：${version ? version[1] : '未知'}`)
  }
  lines.push(`大小：${now.length} 字符 / ${now.split(/\r?\n/).length} 行`)
  return lines.join('\n')
}

function syntaxCheck (path, label) {
  const py = ['python', 'python3', 'py'].find((name) => {
    const probe = spawnSync(name, ['-c', 'import sys'], { encoding: 'utf8' })
    return probe.status === 0
  })
  if (!py) {
    console.log(`（没有可用的 python，跳过${label}语法检查）`)
    return true
  }
  // 用 ast.parse 而不是 py_compile：不会在插件目录里留 __pycache__
  const script = `import ast,sys,io;src=io.open(sys.argv[1],encoding="utf-8").read();ast.parse(src);print("ok")`
  const result = spawnSync(py, ['-c', script, path], { encoding: 'utf8' })
  if (result.status !== 0) {
    console.error(`${label}语法检查失败：`)
    console.error((result.stderr || result.stdout || '').trim().split('\n').slice(-8).join('\n'))
    return false
  }
  console.log(`${label}语法检查：通过`)
  return true
}

if (mode === 'check') {
  console.log(status())
  process.exit(0)
}

if (mode === 'revert') {
  if (!existsSync(backup)) {
    if (!patched) {
      console.log('本来就没打补丁，也没备份，什么都不用做。')
      process.exit(0)
    }
    writeFileSync(target, pristine, 'utf8')
    console.log(`已按标记剥离补丁块：${target}`)
    process.exit(0)
  }
  copyFileSync(backup, target)
  console.log(`已从备份恢复：${backup} → ${target}`)
  process.exit(0)
}

// ---------------------------------------------------------------- 打补丁
const compat = readFileSync(COMPAT, 'utf8').replace(/\s+$/, '')
if (!compat.startsWith(MARKER)) {
  console.error(`_dev/ida-compat.py 第一行必须是标记：${MARKER}`)
  process.exit(1)
}

if (!syntaxCheck(COMPAT, '兼容层')) process.exit(1)

if (!existsSync(backup)) {
  copyFileSync(target, backup)
  console.log(`已备份原文件：${backup}`)
} else {
  console.log(`备份已存在，保留最早那份：${backup}`)
}

const next = `${pristine.replace(/\s+$/, '')}\n\n${compat}\n`
writeFileSync(target, next, 'utf8')

if (!syntaxCheck(target, '打补丁后')) {
  console.error('补丁后文件语法有问题，已自动回滚。')
  copyFileSync(backup, target)
  process.exit(1)
}

console.log(status())
console.log('\n下一步：重启 IDA（插件在启动时加载），Output 里应出现')
console.log('  [dsh-ida] compat layer v1.1 active on IDA 8.x (11 methods rebound)')
console.log('没出现就是没加载新文件：确认 IDA 的插件目录是这一个，或看 Output 里的 Python 报错。')
