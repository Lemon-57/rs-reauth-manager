import { request } from '../request'
import { parseAccounts, parseJobs, parseTick } from '../schemas/reauth'

export const api = {
  accounts: () => request('GET', 'api/accounts').then(parseAccounts),
  jobs: () => request('GET', 'api/jobs').then(parseJobs),
  submit: (accountIds: string[], requestId: string) => request('POST', 'api/submit', { accountIds, requestId }).then(parseJobs),
  cancel: (requestId: string | null = null) => request('POST', 'api/cancel', { requestId }).then(parseJobs),
  tick: () => request('POST', 'api/tick', {}).then(parseTick),
}
