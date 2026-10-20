import type { Account, Job } from '../../types'
import { isRecord } from '../request'

const nullableString = (value: unknown) => value === null || typeof value === 'string'
const nullableTime = (value: unknown) => value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0
function account(value: unknown): value is Account {
  return isRecord(value) && typeof value.id === 'string' && typeof value.name === 'string'
    && nullableString(value.email) && nullableString(value.planType) && nullableString(value.proxy)
    && nullableString(value.accessTokenExpiresAt) && typeof value.enabled === 'boolean'
    && typeof value.notesValid === 'boolean' && typeof value.status === 'string'
    && Array.isArray(value.groups) && value.groups.every(group => isRecord(group) && typeof group.id === 'string' && typeof group.name === 'string')
}
function job(value: unknown): value is Job {
  return isRecord(value) && typeof value.requestId === 'string' && typeof value.accountId === 'string'
    && typeof value.message === 'string' && typeof value.step === 'string'
    && typeof value.status === 'string' && ['queued', 'running', 'success', 'failed', 'review', 'interrupted', 'cancelled'].includes(value.status)
    && nullableTime(value.startedAt) && nullableTime(value.finishedAt)
    && (value.workspaceChoices === undefined || Array.isArray(value.workspaceChoices) && value.workspaceChoices.length <= 30 && value.workspaceChoices.every(w => isRecord(w) && typeof w.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(w.id)))
    && (value.forceWorkspaceId === undefined || nullableString(value.forceWorkspaceId))
    && (value.automatic === undefined || typeof value.automatic === 'boolean')
}
export function parseAccounts(value: unknown): { accounts: Account[] } {
  if (!isRecord(value) || !Array.isArray(value.accounts) || !value.accounts.every(account))
    throw new Error('插件账号列表格式无效')
  return { accounts: value.accounts }
}
export function parseJobs(value: unknown): { jobs: Job[]; automation?: { enabled: boolean } } {
  if (!isRecord(value) || !Array.isArray(value.jobs) || !value.jobs.every(job))
    throw new Error('插件任务列表格式无效')
  if (value.automation !== undefined && (!isRecord(value.automation) || typeof value.automation.enabled !== 'boolean'))
    throw new Error('自动授权状态格式无效')
  return { jobs: value.jobs, ...(isRecord(value.automation) ? { automation: { enabled: value.automation.enabled as boolean } } : {}) }
}
export function parseTick(value: unknown): { ok: true } {
  if (!isRecord(value) || value.ok !== true) throw new Error('插件任务推进结果无效')
  return { ok: true }
}
export function parseDeletion(value: unknown): { deletedAccountIds: string[]; jobs: Job[] } {
  if (!isRecord(value) || !Array.isArray(value.deletedAccountIds) || !value.deletedAccountIds.length
    || !value.deletedAccountIds.every(id => typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id))
    || new Set(value.deletedAccountIds).size !== value.deletedAccountIds.length)
    throw new Error('插件删除结果格式无效，请刷新账号列表核对')
  return { deletedAccountIds: value.deletedAccountIds, ...parseJobs(value) }
}
