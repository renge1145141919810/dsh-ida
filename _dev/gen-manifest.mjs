/**
 * 从本机真实的 mcp-plugin.py 抽出方法清单，生成 src/manifest.js。
 *
 * 为什么要把清单固化进插件，而不是运行时去读 py 文件：
 *   1. IDA 可能装在别的机器/盘符，插件不该依赖固定路径；
 *   2. 模型最常犯的错是「猜方法名」（get_bytes / set_name / get_many_bytes 全都不存在），
 *      有了清单，ida_methods 能自曝能力，ida_raw 能在拼错时给出最接近的建议；
 *   3. 有了参数名和顺序，位置数组可以换成具名参数，不用再数逗号。
 *
 *   node _dev/gen-manifest.mjs
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const PLUGIN = join(process.env.APPDATA || '', 'Hex-Rays', 'IDA Pro', 'plugins', 'mcp-plugin.py')
const OUT = join(here, '..', 'src', 'manifest.js')

const source = readFileSync(PLUGIN, 'utf8')
const lines = source.split(/\r?\n/)

function splitTopLevel (text) {
  const parts = []
  let depth = 0
  let current = ''
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]
    if ('([{<'.includes(char)) depth += 1
    else if (')]}>'.includes(char)) depth -= 1
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

/** 收集从第 i 行开始的完整签名文本，返回 { text, endLine } */
function collectSignature (i) {
  let depth = 0
  let started = false
  let text = ''
  for (let j = i; j < lines.length; j += 1) {
    const line = lines[j]
    text += `${line}\n`
    for (const char of line) {
      if ('([{'.includes(char)) { depth += 1; started = true } else if (')]}'.includes(char)) depth -= 1
    }
    if (started && depth <= 0) return { text, endLine: j }
  }
  return { text, endLine: lines.length - 1 }
}

function parseParams (signatureText) {
  const open = signatureText.indexOf('(')
  const close = signatureText.lastIndexOf(')')
  if (open < 0 || close < 0) return []
  const inner = signatureText.slice(open + 1, close).replace(/\n/g, ' ')
  return splitTopLevel(inner).map((part) => {
    const hasDefault = /=(?!=)/.test(part)
    const withoutDefault = hasDefault ? part.slice(0, part.indexOf('=')).trim() : part
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\s\S]+)$/.exec(withoutDefault)
    if (!match) return null
    const name = match[1]
    let type = match[2].trim()
    // Annotated[str, "..."] → str；注意第一个参数本身可能带括号（Optional[int]），
    // 所以要按括号配对截，不能用 [^,\]]+ 这种粗暴写法。
    if (type.startsWith('Annotated[')) {
      let depth = 0
      let end = -1
      for (let i = 'Annotated'.length; i < type.length; i += 1) {
        if (type[i] === '[') depth += 1
        else if (type[i] === ']') {
          depth -= 1
          if (depth === 0) { end = i; break }
        }
      }
      const inner = type.slice('Annotated['.length, end)
      const firstComma = splitTopLevel(inner)[0]
      type = (firstComma || inner).trim()
    }
    type = type.replace(/\s+/g, '')
    return { name, type, optional: hasDefault }
  }).filter(Boolean)
}

const methods = []
for (let i = 0; i < lines.length; i += 1) {
  const head = /^def ([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(lines[i])
  if (!head) continue
  const name = head[1]

  // 往上找连续的装饰器行
  const decorators = []
  for (let k = i - 1; k >= 0; k -= 1) {
    const line = lines[k]
    if (/^@/.test(line)) { decorators.push(line.trim()); continue }
    if (!line.trim()) { if (decorators.length) continue; break }
    break
  }
  if (!decorators.includes('@jsonrpc')) continue

  const { text, endLine } = collectSignature(i)
  const params = parseParams(text)
  const returnMatch = /\)\s*->\s*([^:]+):/.exec(text.replace(/\n/g, ' '))

  // docstring 第一行
  let doc = ''
  for (let k = endLine + 1; k < Math.min(endLine + 8, lines.length); k += 1) {
    const line = lines[k].trim()
    if (!line) continue
    const m = /^"""\s*(.*)$/.exec(line)
    if (m) { doc = m[1].replace(/"""$/, '').trim(); break }
    break
  }

  methods.push({
    name,
    params,
    returns: returnMatch ? returnMatch[1].trim().replace(/\s+/g, '') : null,
    doc: doc || '',
    write: decorators.includes('@idawrite'),
    unsafe: decorators.includes('@unsafe'),
  })
}

const PLUGIN_LABEL = '<IDA_USER_DIR>/plugins/mcp-plugin.py'

const header = `/**
 * 自动生成，不要手改 —— 由 _dev/gen-manifest.mjs 从真实的 mcp-plugin.py 抽取。
 * 生成时间：${new Date().toISOString()}
 * 来源：${PLUGIN_LABEL}
 *
 * 用途：ida_methods 自曝能力、ida_raw 的具名参数映射与拼写纠正。
 */

export const MANIFEST_GENERATED_AT = ${JSON.stringify(new Date().toISOString())}
export const MANIFEST_SOURCE = ${JSON.stringify(PLUGIN_LABEL)}

/** @type {Array<{name:string,params:Array<{name:string,type:string,optional:boolean}>,returns:string|null,doc:string,write:boolean,unsafe:boolean}>} */
export const LEGACY_METHODS = ${JSON.stringify(methods, null, 2)}

export const LEGACY_METHOD_NAMES = LEGACY_METHODS.map((m) => m.name)
`

writeFileSync(OUT, header, 'utf8')
console.log(`已生成 ${OUT}`)
console.log(`方法 ${methods.length} 个，其中可写 ${methods.filter((m) => m.write).length} 个、unsafe ${methods.filter((m) => m.unsafe).length} 个`)
for (const m of methods) {
  console.log(`  ${m.name}(${m.params.map((p) => `${p.name}:${p.type}${p.optional ? '?' : ''}`).join(', ')})`)
}
