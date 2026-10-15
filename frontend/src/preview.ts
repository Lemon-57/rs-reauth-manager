import { applyResolvedTheme, resolveTheme, DEFAULT_THEME_COLOR, DEFAULT_CUSTOM_THEME_COLOR } from '@codex-proxy/ui/theme'
import type { Account, Job } from './types'
export function installPreview() {
  if (window.codexProxyPlugin) return
  const theme = new URLSearchParams(location.search).get('theme') === 'dark' ? 'dark' : 'light'
  applyResolvedTheme(document.documentElement, resolveTheme(theme, DEFAULT_THEME_COLOR, DEFAULT_CUSTOM_THEME_COLOR))
  const accounts: Account[] = Array.from({ length: 61 }, (_, i) => ({ id: `acct_preview_${i}`, name: `team+account-${i + 1}@example.com+workspace3`, email: `account-${i + 1}@example.com`, enabled: i !== 4, planType: i % 6 ? 'team' : 'plus', status: i % 3 ? 'normal' : 'error', accessTokenExpiresAt: new Date(Date.now() + 86400000 * 6).toISOString(), proxy: i === 3 ? null : `http://127.0.0.1:${21001 + i}`, notesValid: i !== 7 }))
  let jobs: Job[] = []
  const encode = (body: unknown) => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer as ArrayBuffer })
  window.codexProxyPlugin = { version: 2, theme, async request(input) {
    const body = input.body ? JSON.parse(input.body) : {}
    if (input.path === 'api/accounts') return encode({ accounts })
    if (input.path === 'api/jobs') return encode({ jobs })
    if (input.path === 'api/submit') { jobs = [...jobs.filter(j => ['queued', 'running'].includes(j.status)), ...body.accountIds.map((id: string) => ({ requestId: `${body.requestId}:${id}`, accountId: id, status: 'queued', step: 'queued', message: '', startedAt: null, finishedAt: null }))]; return encode({ jobs }) }
    if (input.path === 'api/cancel') { for (const j of jobs) if (['queued', 'running'].includes(j.status) && (!body.requestId || body.requestId === j.requestId)) { j.status = j.step = 'cancelled'; j.message = '已取消'; j.finishedAt = Date.now() } return encode({ jobs }) }
    if (input.path === 'api/tick') { const j = jobs.find(j => ['queued', 'running'].includes(j.status)); if (j) { if (j.status === 'queued') { j.status = 'running'; j.step = 'login'; j.startedAt = Date.now() } else { j.status = j.step = 'success'; j.message = '新授权已写回原账号，配置校验通过'; j.finishedAt = Date.now() } } return encode({ ok: true }) }
    throw new Error('未知预览请求')
  } }
}
