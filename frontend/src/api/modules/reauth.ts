import { request } from '../request'
import { parseAccounts, parseDeletion, parseJobs, parseTick } from '../schemas/reauth'

export const api = {
  accounts: () => request('GET', 'api/accounts').then(parseAccounts),
  jobs: () => request('GET', 'api/jobs').then(parseJobs),
  deleteAccounts: (accountIds: string[]) => request('POST', 'api/delete', { accountIds }).then(parseDeletion),
  submit: (accountIds: string[], requestId: string) => request('POST', 'api/submit', { accountIds, requestId }).then(parseJobs),
  cancel: (requestId: string | null = null) => request('POST', 'api/cancel', { requestId }).then(parseJobs),
  tick: () => request('POST', 'api/tick', {}).then(parseTick),
  forceSubmit: (sourceRequestId: string, workspaceId: string, requestId: string) => request('POST', 'api/force-submit', { sourceRequestId, workspaceId, requestId, confirmation: 'replace_workspace_and_disable' }).then(parseJobs),
  freeFallback: (sourceRequestId: string, requestId: string) => request('POST', 'api/free-fallback', { sourceRequestId, requestId, confirmation: 'fallback_free_and_disable' }).then(parseJobs),
}
