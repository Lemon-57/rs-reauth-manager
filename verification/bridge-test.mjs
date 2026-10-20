import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
let handler, calls = [], count = 0
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'light', request: async input => { calls.push(input); return handler(input) } } }
const json = (body, status = 200, contentType = 'application/json') => ({ status, contentType, body: new TextEncoder().encode(JSON.stringify(body)).buffer })
const check = name => { count++; console.log(`PASS ${name}`) }
try {
  const { request } = await server.ssrLoadModule('/src/api/request.ts')
  const { api } = await server.ssrLoadModule('/src/api/index.ts')
  const { planKey, planLabel, progress, statusText } = await server.ssrLoadModule('/src/format.ts')
  const { resultMessage } = await server.ssrLoadModule('/src/format.ts')
  assert.match(resultMessage({ message: '2FA 验证未通过，请检查原账号备注' }), /历史记录.*不能据此判断密钥错误/)
  assert.match(resultMessage({ message: '协议登录未完成，请检查账号或代理后重试' }), /未记录具体失败阶段/)
  assert.equal(resultMessage({ message: '创建 2FA 验证挑战：失败（HTTP 403）' }), '创建 2FA 验证挑战：失败（HTTP 403）')
  check('Legacy errors are labelled historical without inventing a cause or mutating retained state')
  assert.equal(progress({ step: 'free', status: 'success' }), '登录成功')
  assert.equal(statusText({ enabled: false, status: 'normal' }), '已停用')
  assert.equal(statusText({ enabled: false, status: 'error' }), '异常（已停用）')
  check('Verified Free fallback is labelled login success while scheduling remains disabled')
  assert.equal(planKey(' Free '), 'free'); assert.equal(planLabel(' Free '), 'Free'); assert.equal(planKey(null), 'unknown'); check('Free membership labels and filter keys normalize case and whitespace')
  const { parseAccounts } = await server.ssrLoadModule('/src/api/schemas/reauth.ts')
  const grouped = { id: 'fixture', name: 'fixture', email: null, enabled: true, planType: 'free', status: 'error', accessTokenExpiresAt: null, proxy: null, notesValid: false, groups: [{ id: 'g1', name: 'Primary' }, { id: 'g2', name: 'Shared' }] }
  assert.deepEqual(parseAccounts({ accounts: [grouped] }).accounts[0].groups, grouped.groups)
  assert.deepEqual(parseAccounts({ accounts: [{ ...grouped, groups: [] }] }).accounts[0].groups, [])
  assert.throws(() => parseAccounts({ accounts: [{ ...grouped, groups: [{ id: 'g1' }] }] }))
  check('Account decoding preserves all group names and rejects malformed memberships')
  handler = () => json({ accounts: [] }, 200, ' Application/JSON ; charset=utf-8')
  assert.deepEqual(await api.accounts(), { accounts: [] }); assert.deepEqual(calls.at(-1), { method: 'GET', path: 'api/accounts' }); check('Public bridge GET has no JSON declaration or body, MIME normalization matches workbench')
  handler = () => json({ jobs: [] })
  handler = () => json({ deletedAccountIds: ['fixture'], jobs: [] })
  assert.deepEqual(await api.deleteAccounts(['fixture']), { deletedAccountIds: ['fixture'], jobs: [] })
  assert.deepEqual(calls.at(-1), { method: 'POST', path: 'api/delete', contentType: 'application/json', body: JSON.stringify({ accountIds: ['fixture'] }) })
  for (const deletedAccountIds of [[], ['fixture','fixture'], [null]]) {
    handler = () => json({ deletedAccountIds, jobs: [] })
    await assert.rejects(api.deleteAccounts(['fixture']), /删除结果格式无效/)
  }
  check('Native-account deletion uses a single scoped POST without confirmation fields and validates business results')
  handler = () => json({ jobs: [] })
  await api.forceSubmit('source-job', 'alternate-workspace', 'request-key')
  assert.deepEqual(JSON.parse(calls.at(-1).body), { sourceRequestId: 'source-job', workspaceId: 'alternate-workspace', requestId: 'request-key', confirmation: 'replace_workspace_and_disable' })
  assert.equal(calls.at(-1).path, 'api/force-submit')
  check('Forced writeback bridge carries explicit confirmation and selected workspace without token fields')
  await api.freeFallback('source-job', 'free-request')
  assert.deepEqual(JSON.parse(calls.at(-1).body), { sourceRequestId: 'source-job', requestId: 'free-request', confirmation: 'fallback_free_and_disable' })
  assert.equal(calls.at(-1).path, 'api/free-fallback')
  check('Free fallback bridge carries explicit confirmation without workspace or token fields')
  await api.submit(['fixture'], 'fixture-request'); const input = calls.at(-1); assert.equal(input.method, 'POST'); assert.equal(input.contentType, 'application/json'); assert.deepEqual(JSON.parse(input.body), { accountIds: ['fixture'], requestId: 'fixture-request' }); check('POST uses public bridge and preserves business body')
  for (const invalid of ['/api/accounts', 'https://example.com', '../accounts', 'api/../accounts']) await assert.rejects(request('GET', invalid))
  await assert.rejects(request('GET', 'api/accounts', {})); check('Absolute URLs, cross-scope paths and GET payloads are rejected')
  handler = () => json({ error: { message: '安全的业务错误' } }, 409)
  await assert.rejects(api.jobs(), /安全的业务错误/); check('Non-2xx business errors are not mistaken for success')
  handler = () => json({ code: 200, data: { accounts: [] } })
  await assert.rejects(api.accounts(), /列表格式无效/); check('Host admin envelope is not treated as plugin business response')
  handler = () => json({ accounts: [{ id: 'fixture' }] })
  await assert.rejects(api.accounts(), /列表格式无效/)
  handler = () => json({ jobs: [{ requestId: 'fixture', accountId: 'fixture', status: 'invented', step: 'login', message: '', startedAt: null, finishedAt: null }] })
  await assert.rejects(api.jobs(), /任务列表格式无效/); check('Business decoders reject malformed accounts and unknown task states')
  handler = () => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode('{').buffer })
  await assert.rejects(api.jobs(), /无效 JSON/)
  handler = () => json({}, 200, 'text/html')
  await assert.rejects(api.jobs(), /内容类型/); check('Invalid JSON and unexpected content types fail explicitly')
  handler = () => json({ ok: false })
  await assert.rejects(api.tick(), /推进结果无效/); check('Successful HTTP without semantic tick success is rejected')
  window.codexProxyPlugin.version = 1
  await assert.rejects(api.jobs(), /插件管理页面/); check('Missing or incompatible host bridge is rejected')
} finally { await server.close(); delete globalThis.window }
console.log(`Verified ${count} bridge scenarios`)
