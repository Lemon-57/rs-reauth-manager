import type { Account, Job } from '../../types'
import { isRecord } from '../request'

const nullableString = (value: unknown) => value === null || typeof value === 'string'
const nullableTime = (value: unknown) => value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0
function account(value: unknown): value is Account {
  return isRecord(value) && typeof value.id === 'string' && typeof value.name === 'string'
    && nullableString(value.email) && nullableString(value.planType) && nullableString(value.proxy)
    && nullableString(value.accessTokenExpiresAt) && typeof value.enabled === 'boolean'
    && typeof value.notesValid === 'boolean' && typeof value.status === 'string'
}
function job(value: unknown): value is Job {
  return isRecord(value) && typeof value.requestId === 'string' && typeof value.accountId === 'string'
    && typeof value.message === 'string' && typeof value.step === 'string'
    && typeof value.status === 'string' && ['queued', 'running', 'success', 'failed', 'review', 'interrupted', 'cancelled'].includes(value.status)
    && nullableTime(value.startedAt) && nullableTime(value.finishedAt)
}
export function parseAccounts(value: unknown): { accounts: Account[] } {
  if (!isRecord(value) || !Array.isArray(value.accounts) || !value.accounts.every(account))
    throw new Error('插件账号列表格式无效')
  return { accounts: value.accounts }
}
export function parseJobs(value: unknown): { jobs: Job[] } {
  if (!isRecord(value) || !Array.isArray(value.jobs) || !value.jobs.every(job))
    throw new Error('插件任务列表格式无效')
  return { jobs: value.jobs }
}
export function parseTick(value: unknown): { ok: true } {
  if (!isRecord(value) || value.ok !== true) throw new Error('插件任务推进结果无效')
  return { ok: true }
}
