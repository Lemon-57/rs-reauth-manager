import type { Account, Job } from './types'

export function resultMessage(job?: Job): string {
  const message = job?.message || ''
  if (message === '2FA 验证未通过，请检查原账号备注') return '历史记录：2FA 流程未完成，未记录具体原因，不能据此判断密钥错误'
  if (message === '协议登录未完成，请检查账号或代理后重试') return '历史记录：协议登录未完成，未记录具体失败阶段'
  return message
}

export const isActive = (job?: Job) => !!job && ['queued', 'running'].includes(job.status)
export const needsReauth = (account: Account) => account.status === 'error'
export const isUnfinished = (job?: Job) => !!job && ['failed', 'review', 'interrupted'].includes(job.status)
export function planKey(value: string | null) { return value?.trim().toLowerCase() || 'unknown' }
export function planLabel(value: string) { return ({ team: 'Team', business: 'Business', plus: 'Plus', pro: 'Pro', free: 'Free', unknown: '未知' } as Record<string, string>)[planKey(value)] || value }
export function planType(value: string | null): 'success' | 'info' | 'primary' | 'default' {
  const plan = value?.trim().toLowerCase()
  return plan === 'team' || plan === 'business' ? 'success' : plan === 'plus' ? 'info' : plan?.startsWith('pro') ? 'primary' : 'default'
}
export function displayTime(value?: number | string | null) {
  if (value == null) return '-'
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '-'
}
export function statusText(a: Account) { return !a.enabled ? '已停用' : ({ normal: '正常', error: '异常', quota_exhausted: '额度耗尽', rate_limited: '限流' } as Record<string, string>)[a.status] || a.status }
export function progress(job?: Job) { return !job ? '未执行' : ({ queued: '等待处理', preparing: '核对资料', session: '建立会话', login: '协议登录', mfa: '验证 2FA', saving: '写回授权', success: '已写回', free: '登录成功', failed: '登录失败', workspace: '工作区不匹配', review: '需要核对', interrupted: '已中断', cancelled: '已取消' } as Record<string, string>)[job.step] || '登录中' }
