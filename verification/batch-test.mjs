import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(path.join(root, 'frontend/package.json'))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { createRenderer, nextTick } = await import(pathToFileURL(require.resolve('vue')).href)
const server = await createServer({ root: path.join(root, 'frontend'), configFile: false, server: { middlewareMode: true, hmr: false } })
const account = (id, overrides = {}) => ({ id, name: `${id}@example.com`, email: `${id}@example.com`, enabled: true, planType: 'free', status: 'error', accessTokenExpiresAt: null, proxy: 'http://127.0.0.1:21001', notesValid: true, groups: id === 'error' ? [{ id: 'g1', name: 'Primary Group' }, { id: 'g2', name: 'Shared Group' }] : [], ...overrides })
let accounts = [account('error'), account('missing', { notesValid: false, proxy: null }), account('paused', { enabled: false }), account('healthy', { status: 'normal' }), account('expired-access', { status: 'normal', accessTokenExpiresAt: '2020-01-01T00:00:00Z' }), account('quota', { status: 'quota_exhausted' }), account('limited', { status: 'rate_limited' })]
const job = (id, status, batch = 'history') => ({ accountId: id, requestId: `${batch}:${id}`, status, step: status, message: status === 'failed' ? 'fixture failure' : '', startedAt: 1, finishedAt: ['queued', 'running'].includes(status) ? null : 2 })
let jobs = [job('healthy', 'success'), job('error', 'failed'), job('error', 'failed', 'older')]
let outcomes = {}, throwAfterSubmit = false, throwAfterForce = false, throwAfterFree = false, freeGate = null, submitGate = null, calls = [], latestBatch = null, checks = 0, mounted
const clone = value => structuredClone(value)
const reply = body => ({ status: 200, contentType: 'application/json', body: new TextEncoder().encode(JSON.stringify(body)).buffer })
globalThis.window = { codexProxyPlugin: { version: 2, theme: 'light', request: async input => {
  calls.push(clone(input))
  if (input.path === 'api/accounts') return reply({ accounts })
  if (input.path === 'api/jobs') return reply({ jobs })
  const body = input.body ? JSON.parse(input.body) : {}
  if (input.path === 'api/submit') {
    latestBatch = body.requestId
    jobs.push(...body.accountIds.map(id => job(id, 'queued', latestBatch)))
    if (submitGate) await submitGate.promise
    if (throwAfterSubmit) throw new Error('fixture response lost')
    return reply({ jobs })
  }
  if (input.path === 'api/force-submit') {
    assert.equal(body.confirmation, 'replace_workspace_and_disable')
    assert.equal(body.workspaceId, 'alternate-workspace')
    latestBatch = body.requestId
    jobs.push({ ...job('error', 'queued', latestBatch), forceWorkspaceId: body.workspaceId })
    if (throwAfterForce) throw new Error('fixture forced response lost')
    return reply({ jobs })
  }
  if (input.path === 'api/free-fallback') {
    assert.equal(body.confirmation, 'fallback_free_and_disable')
    assert.deepEqual(Object.keys(body).sort(), ['confirmation', 'requestId', 'sourceRequestId'])
    const source = jobs.find(j => j.requestId === body.sourceRequestId)
    assert.equal(source.status, 'failed'); assert.equal(source.step, 'workspace'); assert.ok(!source.workspaceChoices?.length)
    latestBatch = body.requestId
    jobs.push(job(source.accountId, 'queued', latestBatch))
    if (freeGate) await freeGate.promise
    if (throwAfterFree) throw new Error('fixture Free response lost')
    return reply({ jobs })
  }
  if (input.path === 'api/tick') {
    for (const entry of jobs.filter(j => j.requestId.startsWith(`${latestBatch}:`) && ['queued', 'running'].includes(j.status))) {
      const freeFallback = outcomes[entry.accountId] === 'free'
      entry.status = freeFallback ? 'success' : outcomes[entry.accountId] || 'success'; entry.step = freeFallback ? 'free' : entry.status
      entry.message = entry.status === 'failed' ? 'fixture current failure' : ''; entry.finishedAt = 3
      if (entry.status === 'success') accounts.find(a => a.id === entry.accountId).status = 'normal'
      if (freeFallback) { const a = accounts.find(a => a.id === entry.accountId); a.enabled = false; a.planType = 'free'; entry.message = '原工作区已失效，已切回 Free，已停止调度' }
    }
    return reply({ ok: true })
  }
  if (input.path === 'api/cancel') {
    for (const entry of jobs) if (['queued', 'running'].includes(entry.status) && (!body.requestId || entry.requestId === body.requestId)) { entry.status = entry.step = 'cancelled'; entry.finishedAt = 4 }
    return reply({ jobs })
  }
  throw new Error(`Unexpected fixture request: ${input.path}`)
} } }

const node = () => ({ children: [], parent: null })
const renderer = createRenderer({
  createElement: node, createText: node, createComment: node,
  setText() {}, setElementText() {}, patchProp() {},
  parentNode: value => value.parent, nextSibling: () => null,
  insert(child, parent) { child.parent = parent; parent.children.push(child) },
  remove(child) { if (child.parent) child.parent.children = child.parent.children.filter(item => item !== child) },
})
const flush = async () => { for (let i = 0; i < 5; i++) { await nextTick(); await new Promise(resolve => setImmediate(resolve)) } }
const check = name => { checks++; console.log(`PASS ${name}`) }
try {
  const { useReauthManager } = await server.ssrLoadModule('/src/useReauthManager.ts')
  async function mount() {
    let state
    mounted = renderer.createApp({ setup() { state = useReauthManager(); return () => null } })
    mounted.mount(node()); await flush(); return state
  }
  let state = await mount()
  assert.equal(state.success.value, 0); assert.equal(state.failed.value, 0); assert.equal(state.jobs.value.length, 3)
  assert.equal(state.resultOf(accounts.find(a => a.id === 'healthy')), undefined)
  assert.equal(state.resultOf(accounts.find(a => a.id === 'error')).status, 'failed')
  check('Entering the page clears batch counters without clearing retained history')
  assert.equal(state.eligibleCount.value, 3)
  assert.equal(state.ready(accounts[1]), false)
  state.showResults('error'); assert.deepEqual(state.filtered.value.map(a => a.id).sort(), ['error', 'missing', 'paused'])
  check('Needs-update count includes every RS error account, not just credential-ready accounts or expired access tokens')
  state.filter.value = 'all'; state.search.value = 'Shared Group'
  assert.deepEqual(state.filtered.value.map(a => a.id), ['error']); state.search.value = ''
  check('Group search matches any RS membership without excluding ungrouped accounts')
  assert.equal('showConfirm' in state, false); assert.equal('targets' in state, false); assert.equal('confirm' in state, false)
  outcomes = { error: 'success', healthy: 'failed' }; await state.submit([accounts[0], accounts[3]])
  assert.equal(state.success.value, 1); assert.equal(state.failed.value, 1); assert.equal(state.eligibleCount.value, 2)
  check('Only the submitted batch contributes outcomes and successful account recovery reduces the error count')
  state.plan.value = 'team'; state.search.value = 'not-found'; state.page.value = 4
  const requestCount = calls.length; state.showResults('failed'); await nextTick()
  assert.equal(state.plan.value, 'all'); assert.equal(state.search.value, ''); assert.equal(state.page.value, 1)
  assert.deepEqual(state.filtered.value.map(a => a.id), ['healthy']); assert.equal(calls.length, requestCount)
  check('Clicking unfinished shows this batch accounts and clears conflicting search, plan and page without submitting anything')
  const failedRequest = state.resultOf(accounts[3]).requestId
  jobs.push(job('healthy', 'success', 'another-page')); await state.load()
  assert.equal(state.resultOf(accounts[3]).requestId, failedRequest); assert.equal(state.resultOf(accounts[3]).status, 'failed')
  state.showResults('success'); assert.deepEqual(state.filtered.value.map(a => a.id), ['error'])
  check('Result filters and displayed errors remain bound to this batch even when later history exists')
  jobs = []; await state.load(); assert.equal(state.success.value, 1); assert.equal(state.failed.value, 1)
  check('Manual refresh and server history pruning cannot erase this page batch outcomes')
  const noOpCount = calls.length
  await state.submit([]); await state.submit([accounts[1], account('unknown')])
  assert.equal(calls.length, noOpCount)
  assert.equal(state.success.value, 1); assert.equal(state.failed.value, 1)
  check('Empty or ineligible direct submissions preserve batch outcomes without requests or dialogs')
  outcomes = { healthy: 'success' }; await state.submit([accounts[3]])
  assert.equal(state.success.value, 1); assert.equal(state.failed.value, 0); assert.equal(state.filter.value, 'all')
  check('Retrying a failed account in another batch replaces old totals instead of retaining its previous failure')
  jobs.push(job('error', 'failed', 'historical-after-success')); await state.load()
  mounted.unmount(); state = await mount(); assert.equal(state.success.value, 0); assert.equal(state.failed.value, 0)
  assert.equal(state.resultOf(accounts.find(a => a.id === 'healthy')), undefined)
  assert.equal(state.resultOf(accounts.find(a => a.id === 'error')).status, 'failed')
  state.showResults('failed'); assert.equal(state.filtered.value.length, 0)
  check('Reopening hides historical success as unexecuted while retaining the latest historical failure reason')
  outcomes = { error: 'review', healthy: 'interrupted', paused: 'cancelled' }; await state.submit([accounts[0], accounts[3], accounts[2]])
  assert.equal(state.success.value, 0); assert.equal(state.failed.value, 2)
  check('Needs-review and interrupted count as unfinished, explicit cancellation does not')
  throwAfterSubmit = true; const before = calls.filter(c => c.path === 'api/submit').length; await state.submit([accounts[3]])
  assert.match(state.error.value, /fixture response lost/); assert.equal(state.active.value, 1)
  assert.equal(calls.filter(c => c.path === 'api/submit').length, before + 1)
  assert.equal(state.success.value, 0); assert.equal(state.failed.value, 0)
  check('A lost submission response is reconciled through read-only jobs lookup, never auto-resubmitted')
  await state.cancel(); assert.equal(state.active.value, 0); assert.equal(state.failed.value, 0)
  check('Cancelling updates live queue state without treating cancellation as a failed authorization')
  throwAfterSubmit = false
  submitGate = Promise.withResolvers(); outcomes = { error: 'success' }
  state.selected.value = ['error', 'missing']
  const directCount = calls.filter(c => c.path === 'api/submit').length
  const pendingSubmit = state.submit([accounts[0], accounts[0], accounts[1], account('unknown')])
  assert.equal(state.busy.value, true)
  await state.submit([accounts[3]])
  assert.equal(calls.filter(c => c.path === 'api/submit').length, directCount + 1)
  assert.deepEqual(JSON.parse(calls.findLast(c => c.path === 'api/submit').body).accountIds, ['error'])
  submitGate.resolve(); await pendingSubmit; submitGate = null
  assert.equal(state.busy.value, false); assert.deepEqual(state.selected.value, ['missing'])
  check('Direct submission deduplicates current eligible accounts and blocks concurrent double clicks')
  outcomes = { error: 'free' }; await state.submit([accounts[0]])
  assert.equal(state.success.value, 1); assert.equal(state.failed.value, 0)
  const recovered = state.accounts.value.find(a => a.id === 'error')
  assert.equal(recovered.enabled, false); assert.equal(recovered.planType, 'free'); assert.equal(recovered.status, 'normal')
  state.showResults('success'); assert.equal(state.resultOf(recovered).step, 'free'); assert.match(state.resultOf(recovered).message, /已停止调度/)
  check('Free recovery counts in this batch success, refreshes the disabled Free account and preserves the explanatory outcome')
  jobs.push({ ...job('error', 'failed', 'workspace-source'), step: 'workspace', message: '无法匹配原账号工作区，已停止写回', workspaceChoices: [{ id: 'alternate-workspace' }] })
  await state.load(); const target = state.accounts.value.find(a => a.id === 'error')
  assert.equal(state.canForce(target), true)
  const count = calls.length; state.openForce(target)
  assert.equal(calls.length, count); assert.equal(state.forceWorkspace.value, ''); assert.equal(state.forceConfirmed.value, false)
  await state.submitForce(); assert.equal(calls.length, count)
  state.forceWorkspace.value = 'alternate-workspace'; await state.submitForce(); assert.equal(calls.length, count)
  state.showForce.value = false; assert.equal(calls.length, count)
  check('Opening/cancelling forced writeback never submits; both selection and confirmation are required')
  state.openForce(target); state.forceWorkspace.value = 'alternate-workspace'; state.forceConfirmed.value = true; outcomes = { error: 'success' }
  await state.submitForce(); assert.equal(calls.filter(c => c.path === 'api/force-submit').length, 1)
  assert.equal(state.showForce.value, false)
  await state.load(); assert.equal(state.success.value, 1); assert.equal(state.failed.value, 0)
  check('Confirmed forced submission forms a new batch with the exact source job and selected workspace')
  jobs.push({ ...job('error', 'failed', 'workspace-source-2'), step: 'workspace', workspaceChoices: [{ id: 'alternate-workspace' }] }); await state.load()
  state.openForce(target); state.forceWorkspace.value = 'alternate-workspace'; state.forceConfirmed.value = true; throwAfterForce = true
  await state.submitForce(); assert.match(state.error.value, /forced response lost/)
  assert.equal(calls.filter(c => c.path === 'api/force-submit').length, 2)
  assert.equal(state.active.value, 1)
  check('Lost forced submission response is read back without automatically replaying authorization')
  await state.cancel()
  const source = { ...job('error', 'failed', 'free-source'), step: 'workspace', workspaceChoices: [] }
  jobs.push(source); accounts[0].enabled = true; accounts[0].planType = 'team'; accounts[0].status = 'error'; await state.load()
  assert.equal(state.canFreeFallback(target), true)
  assert.equal('showFreeFallback' in state, false); assert.equal('freeConfirmed' in state, false)
  freeGate = Promise.withResolvers(); outcomes = { error: 'free' }
  const freeCount = calls.filter(c => c.path === 'api/free-fallback').length
  const pendingFree = state.submitFreeFallback(target)
  assert.equal(state.busy.value, true)
  await state.submitFreeFallback(target)
  assert.equal(calls.filter(c => c.path === 'api/free-fallback').length, freeCount + 1)
  assert.equal(JSON.parse(calls.findLast(c => c.path === 'api/free-fallback').body).sourceRequestId, source.requestId)
  freeGate.resolve(); await pendingFree; freeGate = null
  assert.equal(state.busy.value, false); assert.equal(state.success.value, 1); assert.equal(state.failed.value, 0)
  assert.equal(state.accounts.value.find(a => a.id === 'error').enabled, false)
  assert.equal(state.accounts.value.find(a => a.id === 'error').planType, 'free')
  assert.equal(state.resultOf(target).step, 'free'); assert.match(state.resultOf(target).message, /已停止调度/)
  check('Free action submits immediately without dialog state, blocks double clicks and refreshes the disabled Free result')
  const guardedCount = calls.filter(c => c.path === 'api/free-fallback').length
  await state.submitFreeFallback(state.accounts.value.find(a => a.id === 'error'))
  await state.submitFreeFallback(accounts.find(a => a.id === 'healthy'))
  await state.submitFreeFallback(accounts.find(a => a.id === 'missing'))
  jobs.push({ ...job('error', 'failed', 'free-with-choices'), step: 'workspace', workspaceChoices: [{ id: 'alternate-workspace' }] }); await state.load()
  await state.submitFreeFallback(target)
  assert.equal(calls.filter(c => c.path === 'api/free-fallback').length, guardedCount)
  check('Free action rejects successful, unrelated, incomplete or workspace-selectable accounts without submitting')
  jobs.push({ ...job('error', 'failed', 'free-lost-source'), step: 'workspace', workspaceChoices: [] }); await state.load()
  throwAfterFree = true
  const ticksBefore = calls.filter(c => c.path === 'api/tick').length
  await state.submitFreeFallback(target)
  assert.match(state.error.value, /Free response lost/); assert.equal(state.busy.value, false)
  assert.equal(state.active.value, 1); assert.equal(state.resultOf(target).status, 'queued')
  assert.equal(calls.filter(c => c.path === 'api/free-fallback').length, guardedCount + 1)
  assert.equal(calls.filter(c => c.path === 'api/tick').length, ticksBefore)
  await state.submitFreeFallback(target)
  assert.equal(calls.filter(c => c.path === 'api/free-fallback').length, guardedCount + 1)
  check('Lost Free submission response is reconciled with the current batch and never automatically resubmitted')
  console.log(`Verified ${checks} batch scenarios`)
} finally { mounted?.unmount(); delete globalThis.window; await server.close() }
