import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from './api'
import { isActive, planLabel } from './format'
import type { Account, Job } from './types'

export function useReauthManager() {
  const accounts = ref<Account[]>([]), jobs = ref<Job[]>([]), selected = ref<string[]>([])
  const loading = ref(false), busy = ref(false), error = ref(''), search = ref(''), plan = ref('all'), filter = ref('all'), page = ref(1), pageSize = ref(20)
  const showConfirm = ref(false), targets = ref<Account[]>([])
  let timer: ReturnType<typeof setTimeout> | undefined, destroyed = false, polling = false
  const byAccount = computed(() => new Map(jobs.value.map(j => [j.accountId, j])))
  const jobOf = (a: Account) => byAccount.value.get(a.id)
  const ready = (a: Account) => a.notesValid && !!a.proxy && !isActive(jobOf(a))
  const active = computed(() => jobs.value.filter(isActive).length)
  const success = computed(() => jobs.value.filter(j => j.status === 'success').length)
  const failed = computed(() => jobs.value.filter(j => ['failed', 'review', 'interrupted'].includes(j.status)).length)
  const eligibleCount = computed(() => accounts.value.filter(ready).length)
  const planOptions = computed(() => [{ value: 'all', label: '全部会员' }, ...Array.from(new Set(accounts.value.map(a => a.planType || 'unknown'))).sort().map(value => ({ value, label: planLabel(value) }))])
  const filtered = computed(() => accounts.value.filter(a => {
    if (plan.value !== 'all' && (a.planType || 'unknown') !== plan.value) return false
    if (search.value && !`${a.id} ${a.name} ${a.email || ''} ${a.proxy || ''}`.toLowerCase().includes(search.value.trim().toLowerCase())) return false
    const job = jobOf(a)
    return filter.value === 'all' || filter.value === 'error' && a.status === 'error' || filter.value === 'ready' && ready(a) || filter.value === 'active' && isActive(job) || filter.value === 'failed' && !!job && ['failed', 'review', 'interrupted'].includes(job.status) || filter.value === 'success' && job?.status === 'success' || filter.value === 'invalid' && (!a.notesValid || !a.proxy) || filter.value === 'disabled' && !a.enabled
  }))
  const visible = computed(() => filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
  const pageCandidates = computed(() => visible.value.filter(ready))
  const pageSelected = computed(() => !!pageCandidates.value.length && pageCandidates.value.every(a => selected.value.includes(a.id)))
  const chosen = computed(() => accounts.value.filter(a => selected.value.includes(a.id) && ready(a)))
  watch([search, plan, filter, pageSize], () => page.value = 1)
  watch(() => filtered.value.length, n => { page.value = Math.min(page.value, Math.max(1, Math.ceil(n / pageSize.value))) })
  function selectOne(id: string, checked: boolean) { selected.value = checked ? [...new Set([...selected.value, id])] : selected.value.filter(v => v !== id) }
  function selectPage(checked: boolean) { for (const a of pageCandidates.value) selectOne(a.id, checked) }
  async function load() { loading.value = true; error.value = ''; try { accounts.value = (await api.accounts()).accounts; jobs.value = (await api.jobs()).jobs } catch (e) { error.value = (e as Error).message } finally { loading.value = false } }
  function confirm(rows: Account[]) { targets.value = rows; showConfirm.value = true }
  async function submit() { if (!targets.value.length || busy.value) return; busy.value = true; error.value = ''; try { jobs.value = (await api.submit(targets.value.map(a => a.id), crypto.randomUUID())).jobs; selected.value = selected.value.filter(id => !targets.value.some(a => a.id === id)); showConfirm.value = false; await api.tick(); jobs.value = (await api.jobs()).jobs } catch (e) { error.value = (e as Error).message } finally { busy.value = false } }
  async function cancel(job?: Job) { busy.value = true; error.value = ''; try { jobs.value = (await api.cancel(job?.requestId || null)).jobs } catch (e) { error.value = (e as Error).message } finally { busy.value = false } }
  async function poll() {
    if (destroyed || polling) return
    polling = true
    try {
      if (active.value && !busy.value) { await api.tick(); const next = (await api.jobs()).jobs; const changed = next.some(j => !isActive(j) && jobs.value.some(old => old.requestId === j.requestId && isActive(old))); jobs.value = next; if (changed) accounts.value = (await api.accounts()).accounts }
    } catch (e) { error.value = (e as Error).message }
    finally { polling = false; if (!destroyed) timer = setTimeout(poll, 3000) }
  }
  onMounted(async () => { await load(); await poll() })
  onUnmounted(() => { destroyed = true; clearTimeout(timer) })
  return { accounts, jobs, selected, loading, busy, error, search, plan, filter, page, pageSize, showConfirm, targets, jobOf, ready, active, success, failed, eligibleCount, planOptions, filtered, visible, pageCandidates, pageSelected, chosen, selectOne, selectPage, load, confirm, submit, cancel }
}
