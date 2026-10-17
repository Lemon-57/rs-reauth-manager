import { applyResolvedTheme, resolveTheme, DEFAULT_THEME_COLOR, DEFAULT_CUSTOM_THEME_COLOR } from '@codex-proxy/ui/theme'
import type { Account, Job } from './types'
export function installPreview() {
  if (window.codexProxyPlugin) return
  const theme = new URLSearchParams(location.search).get('theme') === 'dark' ? 'dark' : 'light'
  applyResolvedTheme(document.documentElement, resolveTheme(theme, DEFAULT_THEME_COLOR, DEFAULT_CUSTOM_THEME_COLOR))
  const accounts: Account[] = Array.from({ length: 61 }, (_, i) => ({ id: `acct_preview_${i}`, name: `team+account-${i + 1}@example.com+workspace3`, email: `account-${i + 1}@example.com`, enabled: i !== 4, planType: i % 6 ? 'team' : 'plus', status: i % 3 ? 'normal' : 'error', accessTokenExpiresAt: new Date(Date.now() + 86400000 * 6).toISOString(), proxy: i === 3 ? null : `http://127.0.0.1:${21001 + i}`, notesValid: i !== 7, groups: i % 5 === 0 ? [] : [{ id: 'preview-primary', name: '示例部署组' }, ...(i % 7 === 0 ? [{ id: 'preview-shared', name: '跨区域共享账号组' }] : [])] }))
  let jobs: Job[] = [{ requestId: 'preview-workspace:acct_preview_0', accountId: 'acct_preview_0', status: 'failed', step: 'workspace', message: '无法匹配原账号工作区，已停止写回', startedAt: Date.now() - 10000, finishedAt: Date.now(), workspaceChoices: [{ id: 'preview-other-team' }, { id: 'preview-personal-free' }] }]
  const diagnostics = ['创建 2FA 验证挑战：上游未成功创建 2FA 验证挑战，并非已确认验证码错误（最后响应 HTTP 403）', '提交 2FA 动态码：上游限制登录频率，不自动重试（最后响应 HTTP 429）', '密码验证：请求超时，保留原代理，不自动重试', '2FA 验证未通过，请检查原账号备注']
  jobs.push(...diagnostics.map((message, i): Job => ({ requestId: `preview-diagnostic:${i}`, accountId: `acct_preview_${i + 1}`, status: 'failed', step: 'failed', message, startedAt: Date.now() - 10000, finishedAt: Date.now() })))
  const encode = (body: unknown) => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer as ArrayBuffer })
  window.codexProxyPlugin = { version: 2, theme, async request(input) {
    const body = input.body ? JSON.parse(input.body) : {}
    if (input.path === 'api/accounts') return encode({ accounts })
    if (input.path === 'api/jobs') return encode({ jobs })
    if (input.path === 'api/force-submit') {
      const source = jobs.find(j => j.requestId === body.sourceRequestId)
      if (!source || body.confirmation !== 'replace_workspace_and_disable' || !source.workspaceChoices?.some(w => w.id === body.workspaceId)) throw new Error('工作区选择或确认无效')
      jobs.push({ requestId: `${body.requestId}:${source.accountId}`, accountId: source.accountId, status: 'queued', step: 'queued', message: '管理员已确认', startedAt: null, finishedAt: null, forceWorkspaceId: body.workspaceId })
      return encode({ jobs })
    }
    if (input.path === 'api/submit') { jobs = [...jobs.filter(j => ['queued', 'running'].includes(j.status)), ...body.accountIds.map((id: string) => ({ requestId: `${body.requestId}:${id}`, accountId: id, status: 'queued', step: 'queued', message: '', startedAt: null, finishedAt: null }))]; return encode({ jobs }) }
    if (input.path === 'api/cancel') { for (const j of jobs) if (['queued', 'running'].includes(j.status) && (!body.requestId || body.requestId === j.requestId)) { j.status = j.step = 'cancelled'; j.message = '已取消'; j.finishedAt = Date.now() } return encode({ jobs }) }
    if (input.path === 'api/tick') { const j = jobs.find(j => ['queued', 'running'].includes(j.status)); if (j) { if (j.status === 'queued') { j.status = 'running'; j.step = 'login'; j.startedAt = Date.now() } else { j.status = j.step = 'success'; j.message = j.forceWorkspaceId ? '管理员已确认，其他工作区授权已写回原账号，已停止调度' : '新授权已写回原账号，配置校验通过'; if (j.forceWorkspaceId) { const a = accounts.find(a => a.id === j.accountId)!; a.enabled = false; a.status = 'normal' } j.finishedAt = Date.now() } } return encode({ ok: true }) }
    throw new Error('未知预览请求')
  } }
}
