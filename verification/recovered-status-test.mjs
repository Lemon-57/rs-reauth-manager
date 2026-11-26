import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { createRenderer, nextTick } = await import(pathToFileURL(require.resolve('vue')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
const row = (id, status) => ({ id, name: id, email: `${id}@example.invalid`, enabled: true, planType: 'team', status, accessTokenExpiresAt: null, proxy: 'http://127.0.0.1:21001', notesValid: true, groups: [], automaticStatus: { code: 'review', label: '历史授权待核对', message: '旧失败保护' } })
let accounts = [row('external-rt', 'normal'), row('automatic', 'normal'), row('needs-login', 'error'), row('pending', 'normal')]
const result = (id, status, automatic = false) => ({ accountId: id, requestId: `${id}-${status}`, status, step: status, message: '原始任务结果', automatic, startedAt: 1, finishedAt: status === 'running' ? null : 2 })
let jobs = [result('external-rt', 'failed'), result('automatic', 'review', true), result('needs-login', 'failed'), result('pending', 'running')]
const details = Object.fromEntries(accounts.map(a => [a.id, { category: 'email_verification', message: '历史邮箱验证码错误', failedAt: 2 }]))
const snapshot = () => JSON.stringify({ jobs, details })
const original = snapshot()
const encode = body => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer })
let state, mutations = 0
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'dark', request: async input => {
  if (input.path === 'api/accounts') return encode({ accounts })
  if (input.path === 'api/jobs') return encode({ jobs, loginFailures: Object.keys(details), loginFailureDetails: details, automation: { enabled: false } })
  if (input.path === 'api/tick') return encode({ ok: true })
  if (input.path === 'api/submit') {
    mutations++
    const request = JSON.parse(input.body)
    const [accountId] = request.accountIds
    const status = accountId === 'needs-login' ? 'running' : 'failed'
    jobs.push({ ...result(accountId, status), requestId: request.requestId + ':' + accountId })
    return encode({ jobs })
  }
  throw new Error('Unexpected mutation: ' + input.path)
} } }
const node = () => ({ children: [], parent: null })
const renderer = createRenderer({ createElement: node, createText: node, createComment: node, setText() {}, setElementText() {}, patchProp() {}, parentNode: n => n.parent, nextSibling: () => null, insert(c,p) { c.parent=p;p.children.push(c) }, remove() {} })
const flush = async () => { for (let i=0;i<8;i++) { await nextTick();await new Promise(resolve => setImmediate(resolve)) } }
let app
try {
  const { useReauthManager } = await server.ssrLoadModule('/src/useReauthManager.ts')
  const { progress } = await server.ssrLoadModule('/src/format.ts')
  for (let reload=0;reload<2;reload++) {
    app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
    assert.deepEqual(state.filtered.value.map(a => a.id), ['needs-login'])
    for (const account of accounts.slice(0,2)) {
      assert.equal(state.loginFailed(account), false)
      assert.equal(state.jobOf(account), undefined)
      assert.equal(state.resultOf(account), undefined)
      assert.equal(state.resultFinishedAt(account), null)
      assert.equal(state.canForce(account), false)
    }
    assert.equal(state.jobOf(accounts[3]).status, 'running', 'An active job must remain visible on a normal account')
    state.statusSelection.value = 'email_verification'
    assert.deepEqual(state.filtered.value.map(a => a.id), ['needs-login'])
    state.statusSelection.value = 'normal'
    assert.deepEqual(state.filtered.value.map(a => a.id), ['external-rt', 'automatic', 'pending'])
    assert.equal(snapshot(), original, 'Rendering must preserve all task history and failure records')
    app.unmount()
  }
  app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
  accounts = accounts.map(a => a.id === 'external-rt' ? { ...a, status: 'error' } : a)
  await state.load();await nextTick()
  assert.deepEqual(state.filtered.value.map(a => a.id), ['external-rt', 'needs-login'])
  assert.equal(state.loginFailed(accounts[0]), true, 'A new actual error must remain visible after prior recovery')
  accounts = accounts.map(a => a.id === 'external-rt' ? { ...a, status: 'normal' } : a)
  await state.load();await nextTick()
  assert.deepEqual(state.filtered.value.map(a => a.id), ['needs-login'])
  await state.submit([accounts[0]]);await nextTick()
  state.showResults('failed')
  assert.deepEqual(state.filtered.value.map(a => a.id), ['external-rt'])
  assert.equal(state.resultOf(accounts[0]).status, 'failed', 'A newly submitted failed batch must retain its own result')
  assert.equal(mutations, 1)

  const account = accounts[2]
  jobs = jobs.filter(job => job.accountId !== account.id)
  await state.load()
  assert.equal(state.resultFinishedAt(account), 2, 'Only the historical failure is known')

  state.selectOne(account.id, true)
  await state.submit(state.reauthChosen.value)
  const retry = jobs.at(-1)
  assert.equal(retry.accountId, account.id)
  assert.equal(state.resultOf(account).status, 'running')
  assert.equal(state.resultFinishedAt(account), null, 'An active retry has not finished')

  Object.assign(retry, { status: 'review', step: 'mailshop_no_rt', message: '请求 Mailshop 超时，未写回', finishedAt: 90 })
  await state.load()
  assert.equal(state.resultOf(account).status, 'review')
  assert.equal(progress(state.resultOf(account)), '需要核对')
  assert.equal(state.resultFinishedAt(account), 90, 'The displayed task ending time takes precedence over failure history')
  assert.equal(state.failureOf(account).failedAt, 2, 'Showing the latest time must not modify failure history')
  console.log('PASS external RT recovery, automatic recovery, reload, current failures, active work, later errors, immutable history and current batch failures')
  console.log('PASS historical fallback, active retry without a finished time, and latest timeout timestamp')
} finally {
  app?.unmount();delete globalThis.window;await server.close()
}
