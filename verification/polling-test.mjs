import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { createRenderer, nextTick } = await import(pathToFileURL(require.resolve('vue')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
const nativeTimer = globalThis.setTimeout, nativeClear = globalThis.clearTimeout
let tickResolve, reads = 0, ticks = 0, failRead = false, state, app
const pendingTick = new Promise(resolve => tickResolve = resolve)
const timers = []
const account = { id: 'fixture', name: 'fixture', email: 'fixture@example.com', enabled: false, planType: 'team', status: 'disabled', accessTokenExpiresAt: null, proxy: 'http://127.0.0.1:21001', notesValid: true, groups: [] }
const job = { accountId: 'fixture', requestId: 'fixture-request', status: 'running', step: 'mfa', message: '', startedAt: 1, finishedAt: null }
const json = value => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(value)).buffer })
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'dark', request: async input => {
  if (input.path === 'api/jobs') {
    if (failRead) throw new Error('fixture read failure')
    reads++
    return json({ jobs: [{ ...job, ...(reads > 1 ? { step: 'verify_refresh' } : {}) }], automation: { enabled: false } })
  }
  if (input.path === 'api/accounts') return json({ accounts: [account] })
  if (input.path === 'api/tick') { ticks++; await pendingTick;return { ...json({ error: { message: 'state version conflicts' } }), status: 400 } }
  throw new Error('Unexpected mutation: ' + input.path)
} } }
const node = () => ({ children: [], parent: null })
const renderer = createRenderer({ createElement: node, createText: node, createComment: node, setText() {}, setElementText() {}, patchProp() {}, parentNode: n => n.parent, nextSibling: () => null, insert(c,p) { c.parent=p;p.children.push(c) }, remove() {} })
const flush = async () => { for (let i=0;i<8;i++) { await nextTick();await new Promise(resolve => setImmediate(resolve)) } }
try {
  const { useReauthManager } = await server.ssrLoadModule('/src/useReauthManager.ts')
  globalThis.setTimeout = fn => { timers.push(fn);return timers.length }
  globalThis.clearTimeout = () => {}
  app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
  assert.equal(state.jobs.value[0].step, 'verify_refresh');assert.equal(ticks,1);assert.ok(state.lastUpdated.value)
  console.log('PASS status reads finish while task advancement is still pending')
  await timers.shift()();await flush();assert.equal(ticks,1);assert.ok(reads>=3)
  console.log('PASS repeated polling reads current state without overlapping tick requests')
  tickResolve();await flush()
  assert.match(state.refreshWarning.value,/正在读取最新状态/)
  const previous=state.lastUpdated.value;failRead=true;await timers.shift()();await flush()
  assert.equal(state.lastUpdated.value,previous);assert.match(state.refreshWarning.value,/状态读取失败.*正在重试/)
  console.log('PASS failed reads retain the last update time and explicitly show stale status')
  failRead=false;await timers.shift()();await flush();assert.ok(reads>=4)
  console.log('PASS polling recovers after conflicts and read failures without resubmitting authorization')
} finally {
  app?.unmount();globalThis.setTimeout=nativeTimer;globalThis.clearTimeout=nativeClear;delete globalThis.window;await server.close()
}
