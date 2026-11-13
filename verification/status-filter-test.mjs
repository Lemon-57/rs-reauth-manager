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
const accounts = [row('abnormal', 'error'), row('email', 'error'), row('banned', 'error'), row('recovered', 'normal'), row('unknown', 'normal')]
const result = (id, status) => ({ accountId: id, requestId: `${id}-${status}`, status, step: status, message: '', startedAt: 1, finishedAt: 2 })
let jobs = [{ ...result('recovered', 'success'), automatic: true }]
const emailMessage = '邮箱验证码验证：上游要求邮箱验证码，当前任务不支持人工补码续跑（HTTP 200）'
const banMessage = '提交 2FA 动态码：账号已被封禁或停用，上游拒绝继续登录（HTTP 403）'
const details = {
  email: { category: 'email_verification', message: emailMessage, failedAt: 1 },
  banned: { category: 'account_banned', message: banMessage, failedAt: 1 },
  recovered: { category: 'email_verification', message: emailMessage, failedAt: 1 },
  unknown: { category: 'other', message: '历史登录失败记录未保存具体原因', failedAt: 1 },
}
const current = () => ({ jobs, loginFailures: Object.keys(details), loginFailureDetails: details, automation: { enabled: false } })
const encode = body => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer })
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'dark', request: async input => {
  if (input.path === 'api/accounts') return encode({ accounts })
  if (input.path === 'api/jobs') return encode(current())
  if (input.path === 'api/submit') {
    const request = JSON.parse(input.body)
    assert.deepEqual(request.accountIds, ['recovered'])
    delete details.recovered
    jobs = [{ ...result('recovered', 'success'), requestId: request.requestId + ':recovered', automatic: false }]
    return encode({ jobs })
  }
  if (input.path === 'api/tick') {
    assert.equal(state.loginFailed(accounts[3]), true, 'A partial mutation response must not clear the retained failure')
    assert.equal(state.failureMessage(accounts[3]), emailMessage)
    return encode({ ok: true })
  }
  throw new Error('Unexpected mutation: ' + input.path)
} } }
const node = () => ({ children: [], parent: null })
const renderer = createRenderer({ createElement: node, createText: node, createComment: node, setText() {}, setElementText() {}, patchProp() {}, parentNode: n => n.parent, nextSibling: () => null, insert(c,p) { c.parent=p;p.children.push(c) }, remove() {} })
const flush = async () => { for (let i=0;i<8;i++) { await nextTick();await new Promise(resolve => setImmediate(resolve)) } }
let app, state
try {
  const { useReauthManager } = await server.ssrLoadModule('/src/useReauthManager.ts')
  const { parseJobs } = await server.ssrLoadModule('/src/api/schemas/reauth.ts')
  assert.equal(parseJobs({ jobs: [] }).loginFailureDetails, undefined)
  assert.throws(() => parseJobs({ jobs: [], loginFailureDetails: { a: { category: 'guessed-ban', message: 'HTTP 403', failedAt: 1 } } }), /登录失败原因/)
  for (let load=0;load<2;load++) {
    app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
    assert.deepEqual(state.statusOptions.map(option => option.label), ['账号异常', '邮箱验证', '账号封禁'])
    assert.deepEqual(state.filtered.value.map(row => row.id), accounts.map(row => row.id))
    state.statusSelection.value = 'email_verification';await nextTick()
    assert.deepEqual(state.filtered.value.map(row => row.id), ['email', 'recovered'])
    assert.equal(state.failureMessage(accounts[3]), emailMessage)
    assert.equal(state.failureOf(accounts[3]).failedAt, 1)
    assert.equal(state.failureLabel(accounts[1]), '邮箱验证')
    assert.equal(state.failureLabel(accounts[2]), '账号封禁')
    assert.match(state.failureMessage(accounts[4]), /未保存具体原因/)
    state.statusSelection.value = 'account_banned';await nextTick()
    assert.deepEqual(state.filtered.value.map(row => row.id), ['banned'])
    state.statusSelection.value = 'login_failed';assert.equal(state.statusSelection.value, 'account_banned')
    state.showResults('success');await nextTick()
    assert.equal(state.statusSelection.value, '');assert.equal(state.statusPlaceholder.value, '本次成功')
    app.unmount()
  }
  app = renderer.createApp({ setup() { state=useReauthManager();return () => null } });app.mount(node());await flush()
  state.statusSelection.value = 'email_verification'
  jobs = [];await state.load();await nextTick()
  assert.deepEqual(state.filtered.value.map(row => row.id), ['email', 'recovered'])
  assert.equal(state.failureMessage(accounts[3]), emailMessage)
  await state.submit([accounts[3]]);await nextTick()
  assert.deepEqual(state.filtered.value.map(row => row.id), ['email'])
  assert.equal(state.loginFailed(accounts[3]), false)
  console.log('PASS three status categories, retained reasons after history removal, automatic success and reload, unknown causes and confirmed manual recovery')
} finally {
  app?.unmount();delete globalThis.window;await server.close()
}
