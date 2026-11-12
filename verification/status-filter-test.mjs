import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { createRenderer, nextTick } = await import(pathToFileURL(require.resolve('vue')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
const row = (id, status) => ({ id, name: id, email: `${id}@example.invalid`, enabled: true, planType: 'team', status, accessTokenExpiresAt: null, proxy: 'http://127.0.0.1:21001', notesValid: true, groups: [] })
const accounts = [row('abnormal', 'error'), row('failed', 'normal'), row('recovered', 'normal')]
const result = (id, status) => ({ accountId: id, requestId: `${id}-${status}`, status, step: status, message: '', startedAt: 1, finishedAt: 2 })
const jobs = [result('failed', 'failed'), result('recovered', 'failed'), { ...result('recovered', 'success'), automatic: true }]
let loginFailures = ['failed', 'recovered']
const encode = body => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer })
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'dark', request: async input => {
  if (input.path === 'api/accounts') return encode({ accounts })
  if (input.path === 'api/jobs') return encode({ jobs, loginFailures, automation: { enabled: false } })
  throw new Error('Unexpected mutation: ' + input.path)
} } }
const node = () => ({ children: [], parent: null })
const renderer = createRenderer({ createElement: node, createText: node, createComment: node, setText() {}, setElementText() {}, patchProp() {}, parentNode: n => n.parent, nextSibling: () => null, insert(c,p) { c.parent=p;p.children.push(c) }, remove() {} })
const flush = async () => { for (let i=0;i<8;i++) { await nextTick();await new Promise(resolve => setImmediate(resolve)) } }
let app, state
try {
  const { useReauthManager } = await server.ssrLoadModule('/src/useReauthManager.ts')
  for (let load=0;load<2;load++) {
    app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
    assert.deepEqual(state.statusOptions.map(option => option.label), ['账号异常', '登录失败'])
    assert.deepEqual(state.filtered.value.map(row => row.id), ['abnormal'])
    state.statusSelection.value = 'login_failed';await nextTick()
    assert.deepEqual(state.filtered.value.map(row => row.id), ['failed', 'recovered'])
    state.showResults('success');await nextTick()
    assert.equal(state.statusSelection.value, '');assert.equal(state.statusPlaceholder.value, '本次成功')
    app.unmount()
  }
  app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
  loginFailures = ['failed'];await state.load();state.statusSelection.value = 'login_failed';await nextTick()
  assert.deepEqual(state.filtered.value.map(row => row.id), ['failed'])
  console.log('PASS only two status categories; failure marks survive automatic success and reload until confirmed manual success')
} finally {
  app?.unmount();delete globalThis.window;await server.close()
}
