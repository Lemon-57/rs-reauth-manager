import type { Account, Job } from './types'

export const isActive = (job?: Job) => !!job && ['queued', 'running'].includes(job.status)
export function planLabel(value: string) { return ({ team: 'Team', business: 'Business', plus: 'Plus', pro: 'Pro', free: 'Free', unknown: '未知' } as Record<string, string>)[value.toLowerCase()] || value }
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
export function progress(job?: Job) { return !job ? '未执行' : ({ queued: '等待处理', preparing: '核对资料', session: '建立会话', login: '协议登录', mfa: '验证 2FA', saving: '写回授权', success: '已写回', failed: '登录失败', review: '需要核对', interrupted: '已中断', cancelled: '已取消' } as Record<string, string>)[job.step] || '登录中' }
