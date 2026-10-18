import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { createSSRApp, h } = await import(pathToFileURL(require.resolve('vue')).href)
const { renderToString } = await import(pathToFileURL(require.resolve('vue/server-renderer')).href)
const { parse } = await import(pathToFileURL(require.resolve('vue/compiler-sfc')).href)
const server = await createServer({ root: path.join(root, 'frontend'), server: { middlewareMode: true, hmr: false } })
try {
  const { ZCheckbox } = await server.ssrLoadModule('@codex-proxy/ui/checkbox')
  const css = await readFile(path.join(root, 'frontend/src/style.css'), 'utf8')
  const app = await readFile(path.join(root, 'frontend/src/App.vue'), 'utf8')
  assert.match(app, /key: 'select', label: '', kind: 'selection'/)
  for (const props of [{ modelValue: false }, { modelValue: true }, { modelValue: false, indeterminate: true }, { modelValue: true, disabled: true }]) {
    const html = await renderToString(createSSRApp({ render: () => h(ZCheckbox, { class: 'account-checkbox', label: 'Fixture', ...props }) }))
    const label = parse(`<template>${html}</template>`).descriptor.template.ast.children.find(node => node.tag === 'label')
    assert.ok(label)
    const input = label.children.find(node => node.tag === 'input')
    const box = label.children.find(node => node.tag === 'span')
    assert.ok(input); assert.ok(box)
    const icons = box.children.filter(node => node.tag === 'svg')
    assert.equal(icons.length, 2)
    const classes = icons.map(node => node.props.find(p => p.name === 'class')?.value.content)
    assert.ok(classes.some(c => c.split(' ').includes('lucide-check')))
    assert.ok(classes.some(c => c.split(' ').includes('lucide-minus')))
    assert.match(css, /\.account-checkbox > input\[type="checkbox"\][^{]*\{[^}]*opacity: 0;[^}]*clip-path: inset\(50%\)/)
    assert.match(css, /\.account-checkbox > input \+ span > svg[^}]*inset: 2px;[^}]*width: 12px;[^}]*height: 12px;[^}]*opacity: 0;/)
    assert.ok(css.includes('input:checked:not(:indeterminate) + span > svg.lucide-check'))
    assert.ok(css.includes('input:indeterminate + span > svg.lucide-minus'))
    console.log(`PASS official checkbox DOM and single centered icon rules: ${JSON.stringify(props)}`)
  }
} finally { await server.close() }
