import assert from 'node:assert/strict'
import test from 'node:test'
import { importResult, visibleImportJobs } from '../src/format.ts'
import type { Job } from '../src/types.ts'

const row = (requestId: string, status = 'queued', step = status): Job => ({
  requestId, status, step, accountId: '', message: '', startedAt: null, finishedAt: null,
  importInfo: { line: 1, email: 'fixture@example.invalid' },
})

test('排队不显示为正在导入，已发往受保护入口的操作仍显示处理中', () => {
  const waiting = importResult(row('pending:import'), [], undefined, 'loading')
  assert.equal(waiting.label, '已排队，等待导入')
  assert.match(waiting.current, /尚未开始/)
  assert.equal(importResult(row('pending:import', 'queued', 'waiting_import'), []).label, '导入处理中')
  assert.equal(importResult({ ...row('pending:import'), importInfo: { line: 1, email: 'fixture@example.invalid', rtUpdate: true } }, []).label, '等待更新 RT')
})

test('显示新批次时保留更早排队的批次以及其已结束行', () => {
  const old = row('old:import', 'success')
  const olderRunning = row('older:import:1', 'running')
  const olderDone = row('older:import:2', 'success')
  const latest = row('latest:import')
  assert.deepEqual(visibleImportJobs([old, olderRunning, olderDone, latest]), [olderRunning, olderDone, latest])
  assert.deepEqual(visibleImportJobs([old, row('legacy')]), [row('legacy')])
  assert.deepEqual(visibleImportJobs([]), [])
})
