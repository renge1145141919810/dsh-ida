/**
 * 把 dsh-ida 挂进当前的 dsh profile（可重复执行，重复跑是幂等的）。
 *
 *   node _dev/install.mjs            # 安装/更新
 *   node _dev/install.mjs --remove   # 摘掉
 *
 * 做三件事：
 *   1. 在 <profile>/node_modules/@local/ 下建软链（和 @local/dsh-ce 一样的方式）；
 *   2. 在 package.json 的 dependencies 里加 link: 依赖；
 *   3. 把 @local/dsh-ida 加进 dsh.profile.bundles。
 *
 * 改 package.json 之前会先备份成 package.json.bak-dshida。
 */

import { existsSync, lstatSync, readFileSync, rmSync, symlinkSync, writeFileSync, copyFileSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'

const PKG_NAME = '@local/dsh-ida'
const here = dirname(dirname(fileURLToPath(import.meta.url)))
const remove = process.argv.includes('--remove')

const profileRoot = join(process.env.USERPROFILE || homedir(), '.dsh', 'profiles', 'desktop')
const pkgFile = join(profileRoot, 'package.json')
if (!existsSync(pkgFile)) {
  console.error(`没找到 profile：${pkgFile}`)
  process.exit(1)
}

const linkDir = join(profileRoot, 'node_modules', '@local')
const linkPath = join(linkDir, 'dsh-ida')

if (remove) {
  try {
    rmSync(linkPath, { force: true })
    console.log(`已删除软链 ${linkPath}`)
  } catch (error) {
    console.log(`删除软链失败：${error.message}`)
  }
  const pkg = JSON.parse(readFileSync(pkgFile, 'utf8'))
  delete pkg.dependencies?.[PKG_NAME]
  if (pkg.dsh?.profile?.bundles) {
    pkg.dsh.profile.bundles = pkg.dsh.profile.bundles.filter((item) => item !== PKG_NAME)
  }
  copyFileSync(pkgFile, `${pkgFile}.bak-dshida`)
  writeFileSync(pkgFile, `${JSON.stringify(pkg, null, 2)}\n`, 'utf8')
  console.log('已从 package.json 移除，重启 DSH 生效')
  process.exit(0)
}

// 1. 软链
if (existsSync(linkPath)) {
  const stat = lstatSync(linkPath)
  if (stat.isSymbolicLink() || stat.isDirectory()) {
    console.log(`软链已存在：${linkPath}`)
  }
} else {
  symlinkSync(resolve(here), linkPath, 'junction')
  console.log(`已建软链 ${linkPath} → ${resolve(here)}`)
}

// 2. package.json
const raw = readFileSync(pkgFile, 'utf8')
const pkg = JSON.parse(raw)
pkg.dependencies = pkg.dependencies || {}
pkg.dependencies[PKG_NAME] = `link:${resolve(here).replace(/\\/g, '/')}`
pkg.dsh = pkg.dsh || {}
pkg.dsh.profile = pkg.dsh.profile || {}
pkg.dsh.profile.bundles = pkg.dsh.profile.bundles || []
if (!pkg.dsh.profile.bundles.includes(PKG_NAME)) pkg.dsh.profile.bundles.push(PKG_NAME)

const next = `${JSON.stringify(pkg, null, 2)}\n`
if (next === raw) {
  console.log('package.json 无需改动')
} else {
  copyFileSync(pkgFile, `${pkgFile}.bak-dshida`)
  writeFileSync(pkgFile, next, 'utf8')
  console.log('已更新 package.json（备份：package.json.bak-dshida）')
  console.log(`  dependencies.${PKG_NAME} = link:...`)
  console.log('  dsh.profile.bundles += @local/dsh-ida')
}

console.log('\n重启 DSH 后生效。工具名：ida_status / ida_func / ida_annotate / ida_patch / ida_workspace / ida_export / ida_find / ida_addr / ida_raw')
