/**
 * 签名审计：直接解析本机真实的 mcp-plugin.py，把每个 @jsonrpc 方法的参数个数
 * 和 caps 表里 legacy.build() 生成的实参数做对比。
 *
 * 为什么需要这个：旧协议按位置传参、个数必须严格相等（多一个少一个都 -32602）。
 * 自检里的「假 IDA」是我照源码手写的，如果我把源码读错了，假 IDA 会跟着一起错，
 * 测试照样全绿。所以这里绕过 mock，直接对真源码。
 *
 *   node _dev/audit-caps.mjs
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CAPS } from '../src/caps.js'
import { LEGACY_METHODS } from '../src/manifest.js'

const PLUGIN = join(process.env.APPDATA || '', 'Hex-Rays', 'IDA Pro', 'plugins', 'mcp-plugin.py')

function parseSignatures (source) {
  const lines = source.split(/\r?\n/)
  const signatures = new Map()
  for (let i = 0; i < lines.length; i += 1) {
    const head = /^def ([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(lines[i])
    if (!head) continue
    const name = head[1]

    // 把整个签名收齐（可能跨行，且第一行的参数最容易漏），再按顶层逗号切。
    let depth = 0
    let started = false
    let text = ''
    for (let j = i; j < lines.length; j += 1) {
      text += `${lines[j]}\n`
      for (const char of lines[j]) {
        if ('([{'.includes(char)) { depth += 1; started = true } else if (')]}'.includes(char)) depth -= 1
      }
      if (started && depth <= 0) break
    }
    const open = text.indexOf('(')
    const close = text.lastIndexOf(')')
    const inner = open >= 0 && close > open ? text.slice(open + 1, close).replace(/\n/g, ' ') : ''
    const params = splitTopLevel(inner).filter((part) => part && part !== 'self' && part !== '*args' && part !== '**kwargs')
    signatures.set(name, params.length)
  }
  return signatures
}

function splitTopLevel (text) {
  const parts = []
  let depth = 0
  let current = ''
  for (const char of text) {
    if ('([{'.includes(char)) depth += 1
    else if (')]}'.includes(char)) depth -= 1
    if (char === ',' && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else {
      current += char
    }
  }
  if (current.trim()) parts.push(current.trim())
  return parts
}

function dummyArgs (method) {
  // 给每个位置塞一个占位参数，只要个数对就行
  return new Proxy({}, {
    get: (_target, key) => {
      const map = {
        addr: '0x401000',
        address: '0x401000',
        name: 'main',
        text: 'x',
        comment: 'x',
        prototype: 'int f(void)',
        declaration: 'struct x { int a; };',
        instructions: 'retn',
        offset: 0,
        count: 10,
        filter: '',
        size: 16,
        func: '0x401000',
        from: 'v1',
        to: 'x',
        variable: 'v1',
        type: 'int',
        newName: 'x',
      }
      return map[key] ?? 'x'
    },
  })
}

const source = readFileSync(PLUGIN, 'utf8')
const signatures = parseSignatures(source)
console.log(`从 ${PLUGIN} 解析出 ${signatures.size} 个函数签名\n`)

let checked = 0
let bad = 0
for (const [capName, cap] of Object.entries(CAPS)) {
  const spec = cap.legacy
  if (!spec) continue
  const actual = signatures.get(spec.method)
  if (actual === undefined) {
    console.log(`  ? ${capName} → ${spec.method}：源码里没找到这个方法`)
    bad += 1
    continue
  }
  const built = spec.build(dummyArgs(spec.method))
  const expected = Array.isArray(built) ? built.length : null
  if (expected === null) {
    console.log(`  ✗ ${capName} → ${spec.method}：build() 没返回数组`)
    bad += 1
    continue
  }
  checked += 1
  if (expected !== actual) {
    console.log(`  ✗ ${capName} → ${spec.method}：caps 传 ${expected} 个参数，源码要 ${actual} 个`)
    bad += 1
  } else {
    console.log(`  ✓ ${capName} → ${spec.method}(${actual})`)
  }
}

// manifest 是 ida_methods / ida_raw 的依据，它和源码对不上比 caps 对不上更严重：
// 模型会照着清单去调方法，参数个数错了就 -32602。
let manifestBad = 0
for (const method of LEGACY_METHODS) {
  const actual = signatures.get(method.name)
  if (actual === undefined) {
    console.log(`  ✗ manifest 里的 ${method.name} 在源码里不存在`)
    manifestBad += 1
    continue
  }
  if (actual !== method.params.length) {
    console.log(`  ✗ manifest ${method.name}：记了 ${method.params.length} 个参数，源码是 ${actual} 个`)
    manifestBad += 1
  }
}
const srcTotal = [...signatures.keys()].filter((name) => !name.startsWith('_')).length
console.log(`\nmanifest 核对 ${LEGACY_METHODS.length} 条，问题 ${manifestBad} 条（源码共 ${srcTotal} 个函数）`)
console.log(`\ncaps 核对 ${checked} 条，问题 ${bad} 条`)
process.exit(bad === 0 && manifestBad === 0 ? 0 : 1)
