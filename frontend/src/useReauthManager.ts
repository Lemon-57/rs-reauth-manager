import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from './api'
import { importResult, isActive, isUnfinished, needsReauth, planKey, planLabel } from './format'
import type { Account, Job } from './types'
import { supplierOptions as makeSupplierOptions, supplierMatches } from './suppliers'
import { validateImportLine } from './importInput'

export function useReauthManager() {
  const importLineCount = computed(() => importText.value.split(/\r?\n/).filter(line => line.trim()).length)
  const showImport = ref(false), importText = ref(''), importError = ref('')
  function openImport() { importText.value = ''; importError.value = ''; showImport.value = true }
  function closeImport() { if (!busy.value) { importText.value = ''; importError.value = ''; showImport.value = false } }
  async function submitImport() {
    if (busy.value) return
    let line: string
    try { line = validateImportLine(importText.value) } catch (e) { importError.value = (e as Error).message; return }
    const requestId = crypto.randomUUID()
    busy.value = true; importError.value = ''; error.value = ''; batchId.value = requestId; batchJobs.value = []
    // No local/session storage, clipboard reads or logging. Clear the editor before sending.
    importText.value = ''
    try {
      receiveJobs((await api.importLine(line, requestId)).jobs)
      showImport.value = false
      if (['success', 'failed'].includes(filter.value)) filter.value = 'all'
      await api.tick()
    } catch (e) {
      importError.value = `${(e as Error).message}，未自动重新提交，请先核对账号与任务`
      error.value = importError.value
      try { receiveJobs((await api.jobs()).jobs) } catch { /* Read back only; never replay a submitted RT. */ }
    } finally {
      line = ''
      try { accounts.value = (await api.accounts()).accounts } catch { error.value ||= '导入后列表读取未确认，请刷新核对' }
      busy.value = false
    }
  }
  watch(showImport, open => { if (!open) { importText.value = ''; importError.value = '' } })
  const accounts = ref<Account[]>([]), jobs = ref<Job[]>([]), selected = ref<string[]>([])
  const lastUpdated = ref<number | null>(null), readWarning = ref(''), tickWarning = ref('')
  const refreshWarning = computed(() => readWarning.value || tickWarning.value)
  const loading = ref(false), busy = ref(false), error = ref(''), search = ref(''), plan = ref('all'), supplier = ref(''), filter = ref('all'), page = ref(1), pageSize = ref(20)
  const deleting = ref(false), notice = ref(''), automationEnabled = ref(false), automationBusy = ref(false), automationLoaded = ref(false)
  let automationChange = 0
  async function setAutomation(enabled: boolean) {
    if (automationBusy.value || !automationLoaded.value) return
    automationChange++
    automationBusy.value = true; error.value = ''
    try {
      const state = await api.automation(enabled)
      if (!state.automation || state.automation.enabled !== enabled) throw new Error('自动授权设置未确认，请刷新核对')
      automationEnabled.value = state.automation.enabled
      automationLoaded.value = true
      receiveJobs(state.jobs)
    } catch (e) {
      error.value = (e as Error).message
      try {
        const state = await api.jobs()
        if (!state.automation) throw new Error('自动授权设置未确认，请刷新核对')
        automationEnabled.value = state.automation.enabled; automationLoaded.value = true
        receiveJobs(state.jobs)
        if (state.automation.enabled === enabled) error.value = ''
        else error.value ||= '自动授权设置未确认，请刷新核对'
      } catch (e) { error.value ||= (e as Error).message }
    } finally {
      automationBusy.value = false
    }
  }
  const batchId = ref<string | null>(null), batchJobs = ref<Job[]>([])
  let timer: ReturnType<typeof setTimeout> | undefined, destroyed = false, polling = false, ticking = false
  const recentImports = computed(() => {
    const imports = jobs.value.filter(job => job.importInfo)
    const last = imports.at(-1)
    if (!last) return []
    const prefix = last.requestId.split(':')[0] + ':'
    return imports.filter(job => job.requestId.startsWith(prefix))
  })
  const latestByAccount = computed(() => new Map(jobs.value.map(j => [j.accountId, j])))
  const importViews = computed(() => new Map(recentImports.value.map(job => [job.requestId, importResult(job, accounts.value, latestByAccount.value.get(job.accountId))])))
  const importView = (job: Job) => importViews.value.get(job.requestId) || importResult(job, accounts.value, latestByAccount.value.get(job.accountId))
  const importsActive = computed(() => recentImports.value.some(isActive))
  const batchByAccount = computed(() => new Map(batchJobs.value.map(j => [j.accountId, j])))
  const jobOf = (a: Account) => {
    const job = latestByAccount.value.get(a.id)
    return job && (isActive(job) || isUnfinished(job) || job.automatic) ? job : undefined
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
  const planOptions = computed(() => [{ value: 'all', label: '全部订阅' }, ...Array.from(new Set(accounts.value.map(a => planKey(a.planType)))).sort().map(value => ({ value, label: planLabel(value) }))])
  const supplierOptions = computed(() => makeSupplierOptions(accounts.value))
  const filtered = computed(() => accounts.value.filter(a => {
    if (!supplierMatches(a, supplier.value)) return false
    if (plan.value !== 'all' && planKey(a.planType) !== plan.value) return false
    if (search.value && !`${a.id} ${a.name} ${a.email || ''} ${a.proxy || ''} ${a.groups.map(group => group.name).join(' ')}`.toLowerCase().includes(search.value.trim().toLowerCase())) return false
    const job = jobOf(a)
    const batchJob = batchByAccount.value.get(a.id)
    return filter.value === 'all' || filter.value === 'error' && needsReauth(a) || filter.value === 'ready' && ready(a) || filter.value === 'active' && isActive(job) || filter.value === 'failed' && isUnfinished(batchJob) || filter.value === 'success' && batchJob?.status === 'success' || filter.value === 'invalid' && (!a.notesValid || !a.proxy) || filter.value === 'disabled' && !a.enabled
  }))
  const visible = computed(() => filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
  const pageCandidates = computed(() => visible.value)
  const pageSelected = computed(() => !!pageCandidates.value.length && pageCandidates.value.every(a => selected.value.includes(a.id)))
  const pageIndeterminate = computed(() => !pageSelected.value && pageCandidates.value.some(a => selected.value.includes(a.id)))
  const allSelected = computed(() => !!filtered.value.length && filtered.value.every(a => selected.value.includes(a.id)))
  const allIndeterminate = computed(() => !allSelected.value && filtered.value.some(a => selected.value.includes(a.id)))
  const chosen = computed(() => accounts.value.filter(a => selected.value.includes(a.id)))
  const reauthChosen = computed(() => chosen.value.filter(ready))
  watch([search, plan, supplier, filter, pageSize], () => page.value = 1)
  watch(() => filtered.value.length, n => { page.value = Math.min(page.value, Math.max(1, Math.ceil(n / pageSize.value))) })
  function selectOne(id: string, checked: boolean) { selected.value = checked ? [...new Set([...selected.value, id])] : selected.value.filter(v => v !== id) }
  function selectPage(checked: boolean) { for (const a of pageCandidates.value) selectOne(a.id, checked) }
  function selectAll(checked: boolean) {
    const ids = new Set(filtered.value.map(a => a.id))
    selected.value = checked ? [...new Set([...selected.value, ...ids])] : selected.value.filter(id => !ids.has(id))
  }
  function receiveJobs(next: Job[]) {
    const changed = next.some(j => !isActive(j) && jobs.value.some(old => old.requestId === j.requestId && isActive(old)))
    jobs.value = next
    lastUpdated.value = Date.now()
    if (batchId.value) {
      // Keep this page's outcomes even if another submission trims server history.
      const records = new Map(batchJobs.value.map(j => [j.requestId, j]))
      for (const job of next) if (job.requestId.startsWith(`${batchId.value}:`)) records.set(job.requestId, job)
      batchJobs.value = [...records.values()]
    }
    return changed
  }
  function showResults(value: 'error' | 'success' | 'failed') { search.value = ''; plan.value = 'all'; supplier.value = ''; filter.value = value; page.value = 1 }
  async function load() {
    loading.value = true; error.value = ''
    const settingChange = automationChange
    const results = await Promise.allSettled([
      api.jobs().then(state => {
        if (state.automation && !automationBusy.value && settingChange === automationChange) { automationEnabled.value = state.automation.enabled; automationLoaded.value = true }
        receiveJobs(state.jobs)
      }),
      api.accounts().then(state => { accounts.value = state.accounts }),
    ])
    for (const result of results) if (result.status === 'rejected') error.value ||= (result.reason as Error).message
    loading.value = false
  }
  async function deleteSelected() {
    if (busy.value || !chosen.value.length) return
    const ids = chosen.value.map(a => a.id)
    busy.value = true; deleting.value = true; error.value = ''; notice.value = ''
    try {
      const result = await api.deleteAccounts(ids)
      if (result.deletedAccountIds.length !== ids.length || result.deletedAccountIds.some(id => !ids.includes(id)))
        throw new Error('删除结果与所选账号不一致，请刷新核对')
      accounts.value = accounts.value.filter(a => !ids.includes(a.id))
      selected.value = selected.value.filter(id => !ids.includes(id))
      batchJobs.value = batchJobs.value.filter(j => !ids.includes(j.accountId))
      receiveJobs(result.jobs)
      if (forceTarget.value && ids.includes(forceTarget.value.id)) showForce.value = false
      notice.value = `已从 RS 网关删除 ${ids.length} 个账号`
    } catch (e) {
      error.value = `${(e as Error).message}，请核对当前列表，未自动重复删除`
    } finally {
      try {
        accounts.value = (await api.accounts()).accounts
        selected.value = selected.value.filter(id => accounts.value.some(a => a.id === id))
        receiveJobs((await api.jobs()).jobs)
        batchJobs.value = batchJobs.value.filter(j => accounts.value.some(a => a.id === j.accountId))
      } catch {
        error.value ||= '删除请求已结束，但最新列表读取失败，请手动刷新核对'
      }
      busy.value = false; deleting.value = false
    }
  }
  async function submit(rows: Account[]) {
    if (busy.value) return
    const requested = new Set(rows.map(a => a.id))
    const accountIds = accounts.value.filter(a => requested.has(a.id) && ready(a)).map(a => a.id)
    if (!accountIds.length) return
    const requestId = crypto.randomUUID()
    busy.value = true; error.value = ''; batchId.value = requestId; batchJobs.value = []
    if (['success', 'failed'].includes(filter.value)) filter.value = 'all'
    try {
      receiveJobs((await api.submit(accountIds, requestId)).jobs)
      selected.value = selected.value.filter(id => !accountIds.includes(id))
      await api.tick()
      if (receiveJobs((await api.jobs()).jobs)) accounts.value = (await api.accounts()).accounts
    } catch (e) {
      error.value = (e as Error).message
      // A failed response does not prove the submission was rejected; read, never replay it.
      try { receiveJobs((await api.jobs()).jobs) } catch { /* Preserve the original submission error. */ }
    } finally { busy.value = false }
  }
  async function cancel(job?: Job) { busy.value = true; error.value = ''; try { receiveJobs((await api.cancel(job?.requestId || null)).jobs); const state = await api.jobs(); if (state.automation) automationEnabled.value = state.automation.enabled; receiveJobs(state.jobs) } catch (e) { error.value = (e as Error).message } finally { busy.value = false } }
  async function poll() {
    if (destroyed || polling) return
    polling = true
    try {
      if (!busy.value && !automationBusy.value) {
        const settingChange = automationChange
        // Progress is a separate request: a conflict or a slow tick must never block reads.
        if (active.value && !ticking) {
          ticking = true
          void api.tick().catch(e => { if (!destroyed) tickWarning.value = (e as Error).message }).finally(() => { ticking = false })
        }
        const state = await api.jobs()
        if (state.automation && !automationBusy.value && settingChange === automationChange) automationEnabled.value = state.automation.enabled
        receiveJobs(state.jobs)
        accounts.value = (await api.accounts()).accounts
        readWarning.value = ''; tickWarning.value = ''
      }
    } catch (e) { readWarning.value = `状态读取失败，正在重试：${(e as Error).message}` }
    finally { polling = false; if (!destroyed) timer = setTimeout(poll, active.value ? 3000 : 15000) }
  }
  onMounted(async () => { await load(); await poll() })
  onUnmounted(() => { importText.value = ''; destroyed = true; clearTimeout(timer) })
  return { lastUpdated, refreshWarning, importLineCount, recentImports, importView, importsActive, showImport, importText, importError, openImport, closeImport, submitImport, automationEnabled, automationBusy, automationLoaded, setAutomation, accounts, jobs, selected, loading, busy, deleting, notice, error, search, plan, filter, page, pageSize, jobOf, resultOf, ready, active, success, failed, eligibleCount, planOptions, supplier, supplierOptions, filtered, visible, pageCandidates, pageSelected, pageIndeterminate, allSelected, allIndeterminate, chosen, reauthChosen, selectOne, selectPage, selectAll, showResults, load, submit, cancel, deleteSelected, showForce, forceTarget, forceSource, forceWorkspace, forceConfirmed, canForce, openForce, submitForce, canFreeFallback, submitFreeFallback }
}
