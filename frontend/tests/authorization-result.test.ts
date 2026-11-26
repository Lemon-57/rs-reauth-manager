import assert from 'node:assert/strict'
import test from 'node:test'
import { authorizationResult } from '../src/format.ts'
import type { Job } from '../src/types.ts'

const account = { status: 'normal', enabled: true }
const writtenBack: Job = { accountId: 'account', requestId: 'reauth', status: 'success', step: 'success', message: '已保存 RT', startedAt: 1, finishedAt: 2 }

test('当前异常优先显示，成功写回仅保留为历史', () => {
  const job = Object.freeze({ ...writtenBack, automatic: true })
  assert.deepEqual(authorizationResult({ ...account, status: 'error' }, job), {
    label: '当前异常', tone: 'danger', history: '历史：已写回',
  })
  assert.deepEqual(authorizationResult({ status: 'error', enabled: false }, job, '邮箱验证'), {
    label: '当前异常（已停用）', tone: 'danger', history: '历史：已写回',
  })
  assert.equal(job.finishedAt, 2)
  assert.equal(job.message, '已保存 RT')
})

test('当前正常时保留成功展示，正在处理和失败记录也保持原样', () => {
  const abnormal = { ...account, status: 'error' }
  assert.deepEqual(authorizationResult(account, writtenBack), { label: '已写回', tone: 'success', history: '' })
  assert.deepEqual(authorizationResult(abnormal, { ...writtenBack, status: 'running', step: 'login', finishedAt: null }, '邮箱验证'), {
    label: '协议登录', tone: '', history: '',
  })
  assert.deepEqual(authorizationResult(abnormal, { ...writtenBack, status: 'failed', step: 'failed' }, '邮箱验证'), {
    label: '历史：邮箱验证', tone: 'muted', history: '',
  })
  assert.deepEqual(authorizationResult(abnormal, { ...writtenBack, status: 'failed', step: 'failed' }), {
    label: '登录失败', tone: 'danger', history: '',
  })
  assert.equal(authorizationResult(account).label, '无需重新授权')
  assert.equal(authorizationResult({ ...abnormal, automaticStatus: { code: 'eligible', label: '等待自动检查', message: '等待' } }).label, '等待自动检查')
})
