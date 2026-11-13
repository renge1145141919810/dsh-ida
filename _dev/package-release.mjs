/**
 * 把工作副本打成可发布的仓库目录（默认 ../release/dsh-ida）。
 *
 * 为什么要转换而不是直接拷：
 *   - 工作副本的包名是 `@local/dsh-ida`（DSH profile 用 link 挂载），
 *     发布包必须是普通名字 `dsh-ida`，`cordis.patch.yml` 也要跟着改；
 *   - 发布包要带 LICENSE / CHANGELOG，`private` 要去掉；
 *   - 工作副本里的临时目录、node_modules 不能进包。
 *
 * 用法：
 *   node _dev/package-release.mjs [输出目录]
 *   GH_REPO=your-name/dsh-ida node _dev/package-release.mjs   # 顺便写 repository 字段
 */

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync, renameSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = resolve(here, '..')
const outDir = resolve(process.argv[2] || join(srcDir, '..', 'release', 'dsh-ida'))

const COPY = ['index.js', 'README.md', 'CHANGELOG.md', 'LICENSE', 'icon.svg', 'src', 'locale', '_dev']

// 重生成时保留发布目录里的 .git，否则每次打包都会丢历史
const keepGit = `${outDir}.gitkeep`
const hasGit = existsSync(join(outDir, '.git'))
if (hasGit) {
  if (existsSync(keepGit)) rmSync(keepGit, { recursive: true, force: true })
  renameSync(join(outDir, '.git'), keepGit)
}

if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

if (hasGit) renameSync(keepGit, join(outDir, '.git'))

for (const item of COPY) {
  const from = join(srcDir, item)
  if (!existsSync(from)) {
    console.warn(`跳过（源码里没有）：${item}`)
    continue
  }
  cpSync(from, join(outDir, item), { recursive: true })
}

const pkg = JSON.parse(readFileSync(join(srcDir, 'package.json'), 'utf8'))
const release = {
  name: 'dsh-ida',
  version: pkg.version,
  description:
    '把 IDA Pro 接进 DSH 的逆向插件：伪代码直读、批量注释与改名、带台账的 patch、' +
    '持久工作区，以及 IDA 8.x 的 SDK 兼容层。A DSH plugin that brings IDA Pro into the agent loop.',
  type: 'module',
  license: 'MIT',
  engines: pkg.engines,
  keywords: pkg.keywords,
  exports: pkg.exports,
  files: [
    'index.js',
    'src',
    'locale',
    'cordis.patch.yml',
    'icon.svg',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
  ],
  dsh: pkg.dsh,
  scripts: {
    test: 'node _dev/selftest.mjs',
    'test:offline': 'node _dev/offline-workspace.mjs .tmp-offline',
  },
}

if (process.env.GH_REPO) {
  release.repository = { type: 'git', url: `https://github.com/${process.env.GH_REPO}.git` }
  release.homepage = `https://github.com/${process.env.GH_REPO}#readme`
  release.bugs = { url: `https://github.com/${process.env.GH_REPO}/issues` }
}

writeFileSync(join(outDir, 'package.json'), `${JSON.stringify(release, null, 2)}\n`, 'utf8')

writeFileSync(
  join(outDir, 'cordis.patch.yml'),
  ['- insert:', '    - id: dsh-ida', '      name: dsh-ida', '      config: {}', ''].join('\n'),
  'utf8',
)

writeFileSync(
  join(outDir, '.gitignore'),
  ['node_modules/', '*.log', '*.tmp', '.tmp-*/', 'release/', ''].join('\n'),
  'utf8',
)

console.log(`发布目录：${outDir}`)
console.log(`包名 ${release.name} v${release.version}，许可证 ${release.license}`)
console.log(`文件：${COPY.join(', ')}, package.json, cordis.patch.yml, .gitignore`)