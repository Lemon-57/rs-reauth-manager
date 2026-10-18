import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from './api'
import { isActive, isUnfinished, needsReauth, planKey, planLabel } from './format'
import type { Account, Job } from './types'

export function useReauthManager() {
  const accounts = ref<Account[]>([]), jobs = ref<Job[]>([]), selected = ref<string[]>([])
  const loading = ref(false), busy = ref(false), error = ref(''), search = ref(''), plan = ref('all'), filter = ref('all'), page = ref(1), pageSize = ref(20)
  const showConfirm = ref(false), targets = ref<Account[]>([])
  const batchId = ref<string | null>(null), batchJobs = ref<Job[]>([])
  let timer: ReturnType<typeof setTimeout> | undefined, destroyed = false, polling = false
  const latestByAccount = computed(() => new Map(jobs.value.map(j => [j.accountId, j])))
  const batchByAccount = computed(() => new Map(batchJobs.value.map(j => [j.accountId, j])))
  const jobOf = (a: Account) => {
    const job = latestByAccount.value.get(a.id)
    return job && (isActive(job) || isUnfinished(job)) ? job : undefined
  }
  const resultOf = (a: Account) => batchByAccount.value.get(a.id) || jobOf(a)
  const ready = (a: Account) => a.notesValid && !!a.proxy && !isActive(jobOf(a))
  const showForce = ref(false), forceTarget = ref<Account>(), forceSource = ref<Job>(), forceWorkspace = ref(''), forceConfirmed = ref(false)
  const canForce = (a: Account) => { const j = jobOf(a); return ready(a) && j?.status === 'failed' && !!j.workspaceChoices?.length && (j.step === 'workspace' || j.message === '无法匹配原账号工作区，已停止写回') }
  function openForce(a: Account) { forceTarget.value = a; forceSource.value = jobOf(a); forceWorkspace.value = ''; forceConfirmed.value = false; showForce.value = true }
  const canFreeFallback = (a: Account) => { const j = jobOf(a); return ready(a) && j?.status === 'failed' && j.step === 'workspace' && !j.workspaceChoices?.length }
  async function submitFreeFallback(a: Account) {
    if (busy.value || !canFreeFallback(a)) return
    const source = jobOf(a)
    if (!source) return
    const requestId = crypto.randomUUID()
    busy.value = true; error.value = ''; batchId.value = requestId; batchJobs.value = []
    if (['success', 'failed'].includes(filter.value)) filter.value = 'all'
    try {
      receiveJobs((await api.freeFallback(source.requestId, requestId)).jobs)
      await api.tick()
      if (receiveJobs((await api.jobs()).jobs)) accounts.value = (await api.accounts()).accounts
    } catch (e) { error.value = (e as Error).message; try { receiveJobs((await api.jobs()).jobs) } catch { /* Preserve request error */ } }
    finally { busy.value = false }
  }
  async function submitForce() {
    const source = forceSource.value
    if (!source || !forceWorkspace.value || !forceConfirmed.value || busy.value) return
    const requestId = crypto.randomUUID()
    busy.value = true; error.value = ''
    try {
      const result = await api.forceSubmit(source.requestId, forceWorkspace.value, requestId)
      batchId.value = requestId; batchJobs.value = []; receiveJobs(result.jobs); showForce.value = false
      if (['success', 'failed'].includes(filter.value)) filter.value = 'all'
      await api.tick()
    } catch (e) { error.value = (e as Error).message; try { receiveJobs((await api.jobs()).jobs) } catch { /* Preserve request error */ } }
    finally { busy.value = false }
  }
  const active = computed(() => jobs.value.filter(isActive).length)
  const success = computed(() => batchJobs.value.filter(j => j.status === 'success').length)
  const failed = computed(() => batchJobs.value.filter(isUnfinished).length)
  const eligibleCount = computed(() => accounts.value.filter(needsReauth).length)
  const planOptions = computed(() => [{ value: 'all', label: '全部会员' }, ...Array.from(new Set(accounts.value.map(a => planKey(a.planType)))).sort().map(value => ({ value, label: planLabel(value) }))])
  const filtered = computed(() => accounts.value.filter(a => {
    if (plan.value !== 'all' && planKey(a.planType) !== plan.value) return false
    if (search.value && !`${a.id} ${a.name} ${a.email || ''} ${a.proxy || ''} ${a.groups.map(group => group.name).join(' ')}`.toLowerCase().includes(search.value.trim().toLowerCase())) return false
    const job = jobOf(a)
    const batchJob = batchByAccount.value.get(a.id)
    return filter.value === 'all' || filter.value === 'error' && needsReauth(a) || filter.value === 'ready' && ready(a) || filter.value === 'active' && isActive(job) || filter.value === 'failed' && isUnfinished(batchJob) || filter.value === 'success' && batchJob?.status === 'success' || filter.value === 'invalid' && (!a.notesValid || !a.proxy) || filter.value === 'disabled' && !a.enabled
  }))
  const visible = computed(() => filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
  const pageCandidates = computed(() => visible.value.filter(ready))
  const pageSelected = computed(() => !!pageCandidates.value.length && pageCandidates.value.every(a => selected.value.includes(a.id)))
  const chosen = computed(() => accounts.value.filter(a => selected.value.includes(a.id) && ready(a)))
  watch([search, plan, filter, pageSize], () => page.value = 1)
  watch(() => filtered.value.length, n => { page.value = Math.min(page.value, Math.max(1, Math.ceil(n / pageSize.value))) })
  function selectOne(id: string, checked: boolean) { selected.value = checked ? [...new Set([...selected.value, id])] : selected.value.filter(v => v !== id) }
  function selectPage(checked: boolean) { for (const a of pageCandidates.value) selectOne(a.id, checked) }
  function receiveJobs(next: Job[]) {
    const changed = next.some(j => !isActive(j) && jobs.value.some(old => old.requestId === j.requestId && isActive(old)))
    jobs.value = next
    if (batchId.value) {
      // Keep this page's outcomes even if another submission trims server history.
      const records = new Map(batchJobs.value.map(j => [j.requestId, j]))
      for (const job of next) if (job.requestId.startsWith(`${batchId.value}:`)) records.set(job.requestId, job)
      batchJobs.value = [...records.values()]
    }
    return changed
  }
  function showResults(value: 'error' | 'success' | 'failed') { search.value = ''; plan.value = 'all'; filter.value = value; page.value = 1 }
  async function load() { loading.value = true; error.value = ''; try { accounts.value = (await api.accounts()).accounts; receiveJobs((await api.jobs()).jobs) } catch (e) { error.value = (e as Error).message } finally { loading.value = false } }
  function confirm(rows: Account[]) { targets.value = rows; showConfirm.value = true }
  async function submit() {
    if (!targets.value.length || busy.value) return
    const accountIds = targets.value.map(a => a.id), requestId = crypto.randomUUID()
    busy.value = true; error.value = ''; batchId.value = requestId; batchJobs.value = []
    if (['success', 'failed'].includes(filter.value)) filter.value = 'all'
    try {
      receiveJobs((await api.submit(accountIds, requestId)).jobs)
      selected.value = selected.value.filter(id => !accountIds.includes(id)); showConfirm.value = false
      await api.tick()
      if (receiveJobs((await api.jobs()).jobs)) accounts.value = (await api.accounts()).accounts
    } catch (e) {
      error.value = (e as Error).message
      // A failed response does not prove the submission was rejected; read, never replay it.
      try { receiveJobs((await api.jobs()).jobs) } catch { /* Preserve the original submission error. */ }
    } finally { busy.value = false }
  }
  async function cancel(job?: Job) { busy.value = true; error.value = ''; try { receiveJobs((await api.cancel(job?.requestId || null)).jobs) } catch (e) { error.value = (e as Error).message } finally { busy.value = false } }
  async function poll() {
    if (destroyed || polling) return
    polling = true
    try {
      if (active.value && !busy.value) { await api.tick(); if (receiveJobs((await api.jobs()).jobs)) accounts.value = (await api.accounts()).accounts }
    } catch (e) { error.value = (e as Error).message }
    finally { polling = false; if (!destroyed) timer = setTimeout(poll, 3000) }
  }
  onMounted(async () => { await load(); await poll() })
  onUnmounted(() => { destroyed = true; clearTimeout(timer) })
  return { accounts, jobs, selected, loading, busy, error, search, plan, filter, page, pageSize, showConfirm, targets, jobOf, resultOf, ready, active, success, failed, eligibleCount, planOptions, filtered, visible, pageCandidates, pageSelected, chosen, selectOne, selectPage, showResults, load, confirm, submit, cancel, showForce, forceTarget, forceSource, forceWorkspace, forceConfirmed, canForce, openForce, submitForce, canFreeFallback, submitFreeFallback }
}
