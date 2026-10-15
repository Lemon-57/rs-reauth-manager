import assert from 'node:assert/strict'
import { readdir, readFile, realpath } from 'node:fs/promises'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const repos = [root, ...process.argv.slice(2).map(value => path.resolve(value))]
const require = createRequire(path.join(root, 'frontend/package.json'))
const ts = require('typescript'), vue = require('vue/compiler-sfc')
const postcss = createRequire(require.resolve('vite'))('postcss')
let checked = 0
const test = (condition, message) => { assert.ok(condition, message); checked++ }
async function files(dir) {
  const found = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const target = path.join(dir, entry.name)
    if (entry.isDirectory()) found.push(...await files(target))
    else if (/\.(vue|ts|css|rs)$/.test(entry.name)) found.push(target)
  }
  return found
}
for (const repo of repos) {
  const name = path.basename(repo), src = path.join(repo, 'frontend/src')
  const pkg = JSON.parse(await readFile(path.join(repo, 'frontend/package.json'), 'utf8'))
  const manifest = JSON.parse(await readFile(path.join(repo, 'plugin.json'), 'utf8'))
  test(pkg.dependencies['@codex-proxy/ui'] === 'https://github.com/zyycn/codex-proxy-ui/releases/download/v0.4.1/codex-proxy-ui-0.4.1.tgz', `${name}: UI release must be pinned`)
  const lock = await readFile(path.join(repo, 'frontend/pnpm-lock.yaml'), 'utf8')
  test(lock.includes('codex-proxy-ui-0.4.1.tgz') && lock.includes('integrity:'), `${name}: release integrity lock is missing`)
  const cargo = await readFile(path.join(repo, 'backend/Cargo.toml'), 'utf8')
  test(/gateway-plugin-sdk\s*=\s*\{[^\n]*rev\s*=\s*"[a-f0-9]{40}"/.test(cargo), `${name}: public SDK must be pinned`)
  test(!/gateway-(?:core|api|admin|host)\s*=/.test(cargo), `${name}: host internal dependencies are not allowed`)
  test(!('permissions' in manifest), `${name}: legacy permission declarations are not allowed`)
  for (const file of await files(path.join(repo, 'backend/src'))) {
    const source = await readFile(file, 'utf8')
    test(source.startsWith('//!') && /\p{Script=Han}/u.test(source.split('\n')[0]), `${name}: Rust files need a concise Chinese module responsibility`)
    test(!/^\s*\/\/.*[。.]$/m.test(source), `${name}: Rust comments must follow the repository punctuation convention`)
  }
  const entry = await readFile(path.join(src, 'main.ts'), 'utf8')
  test(entry.includes("'@codex-proxy/ui/styles.css'"), `${name}: public UI styles are required`)
  const css = await readFile(path.join(src, 'utilities.css'), 'utf8')
  test(css.includes("'@codex-proxy/ui/tailwind.css'"), `${name}: public Tailwind token map is required`)
  for (const file of await files(src)) {
    const source = await readFile(file, 'utf8')
    const relative = path.relative(repo, file)
    test(!/\b(?:fetch|XMLHttpRequest)\s*\(|document\.cookie|window\.(?:parent|top)/.test(source), `${relative}: bypasses isolated management bridge`)
    test(!/[。；]/.test(source), `${relative}: UI punctuation violates theme guidance`)
    if (file.endsWith('.css')) {
      test(!/#(?:[a-f0-9]{3}|[a-f0-9]{6})\b|\b(?:rgb|rgba|hsl|hsla)\(/i.test(source), `${relative}: fixed palette bypasses theme tokens`)
      postcss.parse(source).walkRules(rule => {
        if (!rule.selector.split(',').some(selector => [':root', 'html', 'body', '#app', 'main', '.quota-manager', '.work-area'].includes(selector.trim()))) return
        rule.walkDecls(decl => {
          if (['height', 'min-height'].includes(decl.prop)) test(!/100(?:d|s|l)?vh|^100%$/.test(decl.value), `${relative}: page height must follow host document flow`)
        })
      })
    }
    let script = source
    if (file.endsWith('.vue')) {
      const { descriptor, errors } = vue.parse(source, { filename: file })
      test(!errors.length, `${relative}: invalid SFC`)
      script = descriptor.scriptSetup?.content || descriptor.script?.content || ''
      const ast = descriptor.template?.ast
      function visit(node) {
        if (node.type === 1) {
          test(!['input', 'button', 'select', 'textarea', 'h1'].includes(node.tag), `${relative}: use public controls and let the host render page titles`)
        }
        for (const child of node.children || []) visit(child)
      }
      if (ast) visit(ast)
    }
    if (!file.endsWith('.css')) {
      const ast = ts.createSourceFile(file, script, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
      for (const statement of ast.statements) {
        if (!(ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) || !statement.moduleSpecifier || !ts.isStringLiteral(statement.moduleSpecifier)) continue
        const specifier = statement.moduleSpecifier.text
        test(!specifier.includes('@codex-proxy/ui/src') && !specifier.includes('rs-ui-reference'), `${relative}: imports UI internals`)
        if (specifier.startsWith('.')) {
          const target = path.resolve(path.dirname(file), specifier)
          test(target.startsWith(src + path.sep), `${relative}: imports source across project boundaries`)
        }
      }
    }
  }
  const style = await readFile(path.join(src, 'style.css'), 'utf8')
  test(/min-height:\s*inherit/.test(style), `${name}: root must inherit host minimum height`)
  test(manifest.resources['legal/NOTICE.md'] === 'text/plain', `${name}: third-party notices missing from package`)
  const uiRoot = path.join(repo, 'frontend/node_modules/@codex-proxy/ui')
  const uiPackage = JSON.parse(await readFile(path.join(uiRoot, 'package.json'), 'utf8'))
  const dependency = path.resolve(uiRoot, uiPackage.exports['.'].import)
  test((await realpath(dependency)).includes(path.sep + 'dist' + path.sep), `${name}: production imports must resolve to compiled UI exports`)
  console.log(`PASS ${name}: public UI, SDK, bridge, SFC, theme, layout and license conventions`)
}
console.log(`Verified ${checked} convention checks`)
