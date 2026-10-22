import type { Account, Job } from './types'

export function resultMessage(job?: Job): string {
  const message = job?.message || ''
  if (message.includes('工作区授权身份校验失败，未更改账号或提交凭据')) return message.replaceAll('工作区授权身份校验失败，未更改账号或提交凭据', '历史授权核验未通过，请结合账号当前状态核对已保存结果')
  if (message === '2FA 验证未通过，请检查原账号备注') return '历史记录：2FA 流程未完成，未记录具体原因，不能据此判断密钥错误'
  if (message === '协议登录未完成，请检查账号或代理后重试') return '历史记录：协议登录未完成，未记录具体失败阶段'
  return message
}

export function importResult(job: Job, accounts: Account[], latest?: Job) {
  const account = accounts.find(a => !!job.accountId && a.id === job.accountId
    && !!a.email && a.email.toLowerCase() === job.importInfo?.email.toLowerCase())
  const saved = !!account
  const label = saved ? (isActive(job) ? '已入库，授权处理中' : '已入库')
    : isActive(job) ? '导入处理中' : job.status === 'success' ? '历史导入已完成' : '入库结果待核对'
  const tone = account ? account.status === 'error' ? 'danger' : account.enabled && account.status === 'normal' ? 'success' : ''
    : isUnfinished(job) ? 'danger' : ''
  const current = account ? `账号状态：${planLabel(account.planType || 'unknown')} · ${statusText(account)} · ${account.groups.map(g => g.name).join(' / ') || '未分组'}`
    : isActive(job) ? '后台正在处理，账号状态尚未读回' : '当前列表未找到对应账号，请刷新核对，不要重复导入'
  const original = `${displayTime(job.finishedAt || job.startedAt)}${job.implementationVersion ? ` · ${job.implementationVersion}` : ''} · ${progress(job)}：${resultMessage(job) || '未记录具体结果'}`
  const followup = latest && latest.requestId !== job.requestId
    ? `${displayTime(latest.finishedAt || latest.startedAt)} · ${progress(latest)}：${resultMessage(latest) || '未记录具体结果'}` : ''
  const note = isActive(job) ? '' : latest?.status === 'success' && latest.requestId !== job.requestId
    ? '后续授权任务已完成，原始记录保留' : saved && isUnfinished(job) ? '原导入任务的后续核验未完成，原始记录保留' : ''
  return { saved, label, tone, current, original, followup, note }
}

export const isActive = (job?: Job) => !!job && ['queued', 'running'].includes(job.status)
export const needsReauth = (account: Account) => account.status === 'error'
export const isUnfinished = (job?: Job) => !!job && ['failed', 'review', 'interrupted'].includes(job.status)
export function planKey(value: string | null) { return value?.trim().toLowerCase() || 'unknown' }
export function planLabel(value: string) { return ({ team: 'Team', business: 'Business', plus: 'Plus', pro: 'Pro', prolite: 'ProLite', promax: 'ProMax', go: 'Go', enterprise: 'Enterprise', education: 'Education', free: 'Free', unknown: '未知' } as Record<string, string>)[planKey(value)] || value }
export function planType(value: string | null): 'success' | 'info' | 'primary' | 'default' {
  const plan = value?.trim().toLowerCase()
  return plan === 'team' || plan === 'business' ? 'success' : plan === 'plus' ? 'info' : plan?.startsWith('pro') ? 'primary' : 'default'
}
export function displayTime(value?: number | string | null) {
  if (value == null) return '-'
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '-'
}
export function statusText(a: Account) { return !a.enabled ? (a.status === 'error' ? '异常（已停用）' : '已停用') : ({ normal: '正常', error: '异常', quota_exhausted: '额度耗尽', rate_limited: '限流' } as Record<string, string>)[a.status] || a.status }
export function progress(job?: Job) { return !job ? '未执行' : ({ queued: '等待处理', preparing: '核对资料', session: '建立会话', session_restart: '重建登录会话', login: '协议登录', mfa: '验证 2FA', saving: '写回授权', verify_refresh: '验证本次 RT', success: '已写回', free: '登录成功', failed: '登录失败', workspace: '工作区不匹配', review: '需要核对', interrupted: '已中断', cancelled: '已取消' } as Record<string, string>)[job.step] || '登录中' }
