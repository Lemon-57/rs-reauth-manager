import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
try {
  const { importResult } = await server.ssrLoadModule('/src/format.ts')
  const job = { accountId: '', requestId: 'fixture:import', status: 'review', step: 'review', message: '后台调用已中断，执行结果未确认', startedAt: 1, finishedAt: 2, importInfo: { line: 1, email: 'fixture@example.invalid' } }
  const account = { id: 'saved', email: 'fixture@example.invalid', enabled: false, status: 'disabled', planType: 'team', groups: [] }
  const loading = importResult(job, [], undefined, 'loading')
  assert.equal(loading.label, '正在读取账号状态'); assert.ok(!loading.current.includes('未找到'))
  assert.equal(loading.issue, job.message)
  const unread = importResult(job, [], undefined, 'unavailable')
  assert.equal(unread.label, '账号状态读取失败'); assert.ok(!unread.current.includes('未找到'))
  const sameEmail = importResult(job, [account])
  assert.equal(sameEmail.saved, false); assert.equal(sameEmail.label, '同邮箱账号已存在，原导入待核对')
  assert.ok(sameEmail.current.includes('Team')); assert.ok(sameEmail.current.includes('已停用'))
  const saved = importResult({ ...job, accountId: 'saved' }, [account])
  assert.equal(saved.saved, true); assert.equal(saved.label, '已入库')
  const ambiguous = importResult(job, [account, { ...account, id: 'other' }])
  assert.equal(ambiguous.saved, false); assert.ok(!ambiguous.label.includes('已存在'))
  const absent = importResult(job, [])
  assert.equal(absent.saved, false); assert.ok(absent.current.includes('完整列表未找到'))
  console.log('PASS account loading, read failure, existing email without confirmed receipt, exact saved identity, ambiguity and missing account remain distinct')
} finally { await server.close() }
