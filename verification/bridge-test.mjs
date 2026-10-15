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
  const { planKey, planLabel } = await server.ssrLoadModule('/src/format.ts')
  assert.equal(planKey(' Free '), 'free'); assert.equal(planLabel(' Free '), 'Free'); assert.equal(planKey(null), 'unknown'); check('Free membership labels and filter keys normalize case and whitespace')
  handler = () => json({ accounts: [] }, 200, ' Application/JSON ; charset=utf-8')
  assert.deepEqual(await api.accounts(), { accounts: [] }); assert.deepEqual(calls.at(-1), { method: 'GET', path: 'api/accounts' }); check('Public bridge GET has no JSON declaration or body, MIME normalization matches workbench')
  handler = () => json({ jobs: [] })
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
