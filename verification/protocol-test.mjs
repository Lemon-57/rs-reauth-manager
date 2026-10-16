import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'

const binary = process.argv[2] || fileURLToPath(new URL(`../backend/target/debug/reauth-manager${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url))
const python = process.env.RS_REAUTH_TEST_PYTHON || process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
const worker = fileURLToPath(new URL('./fake-worker.py', import.meta.url))
const innerAuthorization = 'https://auth.openai.com/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: 'fixture', redirect_uri: 'http://127.0.0.1:1455/auth/callback', state: 'fixture', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256' })
const nativeAuthorization = 'https://chatgpt.com/codex/desktop-auth?' + new URLSearchParams({ authorize_url: innerAuthorization, codex_streamlined_login: 'true', no_universal_links: '1' })
const make = (id, prefix = id) => ({ id, provider: 'openai', name: `team+${prefix}@example.com+workspace3`, email: `${prefix}@example.com`, authenticationKind: 'oauth', enabled: id !== 'disabled', planType: 'team', status: 'error', notes: `${prefix}@example.com----fixture-password----GEZDGNBVGY3TQOJQ`, outboundProxyEndpoint: 'http://127.0.0.1:21001', accountId: 'original-workspace', groups: [{ id: 'g1', name: 'Team' }], weight: 3, concurrencyLimit: null, modelAccess: { mode: 'all' }, hasRefreshToken: true, accessTokenExpiresAt: '2026-10-23T00:00:00Z', capacity: { usedSlots: 0, totalSlots: null } })
const accounts = [make('good'), make('disabled'), make('slow'), make('failed'), make('missing_proxy'), make('bad_notes'), make('changed'), make('active'), make('uncertain')]
accounts.find(a => a.id === 'missing_proxy').outboundProxyEndpoint = null
accounts.find(a => a.id === 'bad_notes').notes = 'different@example.com----fixture-password----GEZDGNBVGY3TQOJQ'
accounts.find(a => a.id === 'active').capacity.usedSlots = 1
const free = make('free'); free.planType = ' Free '; accounts.push(free)
accounts.push(make('credential_changed'))
const apiKey = make('api_key'); apiKey.authenticationKind = 'api_key'; accounts.push(apiKey)
const otherProvider = make('other_provider'); otherProvider.provider = 'other'; accounts.push(otherProvider)
accounts[0].groups.push({ id: 'g2', name: 'Shared Group', privateField: 'fixture-password' })
free.groups = []
const revisions = new Map(accounts.map(a => [a.id, 1]))
const records = new Map(), handles = new Map(), starts = [], completes = []
const disables = [], saves = [], credentials = new Map()
function credential(a) {
  return { account_id: a.id, provider_id: 'openai', credential_revision: revisions.get(a.id), facts: { name: a.name, authentication_kind: 'oauth', material: { schema_version: 1, installation_id: '3d07c9c6-3b57-4a12-a51d-1e21df254477', transport: 'http', principal: { oauth_subject: 'original-subject', poid: null }, access_token: 'old-access', refresh_token: 'old-secret-rt', id_token: 'old-id', oauth_client_id: 'fixture', oauth_scope: 'openid', cookies: [{ name: 'fixture', value: 'fixture-cookie' }] }, email: a.email, upstream_user_id: a.userId, upstream_account_id: a.accountId, plan_type: a.planType, has_refresh_token: true, access_token_expires_at_ms: null, next_refresh_at_ms: null } }
}
let child, buffer, pending, ready, sequence = 99, errors = '', failComplete = false
function send(meta, payload = Buffer.alloc(0)) { if (!Buffer.isBuffer(payload)) payload = Buffer.from(JSON.stringify(payload)); const json = Buffer.from(JSON.stringify(meta)), head = Buffer.alloc(12); head.writeUInt32BE(json.length); head.writeBigUInt64BE(BigInt(payload.length), 4); child.stdin.write(Buffer.concat([head, json, payload])) }
const result = (id, value = {}, payload) => send({ type: 'result', id, result: value }, payload)
async function callback(meta, payload) {
  const data = payload.length ? JSON.parse(payload.toString()) : meta.params
  if (meta.method === 'host.auth.get_runtime') { assert.ok(payload.length); assert.deepEqual(meta.params, {}); return result(meta.id, {}, { account_id: data.account_id, provider_id: 'openai', credential_revision: revisions.get(data.account_id) }) }
  if (meta.method === 'host.auth.get') {
    assert.ok(payload.length); assert.deepEqual(meta.params, {}); assert.deepEqual(Object.keys(data), ['account_id'])
    const a = accounts.find(a => a.id === data.account_id)
    if (!credentials.has(a.id)) credentials.set(a.id, credential(a))
    return result(meta.id, {}, credentials.get(a.id))
  }
  if (meta.method === 'host.auth.save') {
    assert.ok(payload.length); assert.deepEqual(meta.params, {}); assert.equal(data.action, 'replace')
    const a = accounts.find(a => a.id === data.account_id), old = credentials.get(a.id)
    assert.equal(a.enabled, false); assert.equal(a.capacity.usedSlots, 0); assert.equal(data.credential_revision, revisions.get(a.id))
    for (const key of ['installation_id', 'transport', 'cookies', 'oauth_client_id', 'oauth_scope']) assert.deepEqual(data.facts.material[key], old.facts.material[key])
    assert.equal(data.facts.email, old.facts.email); assert.equal(data.facts.upstream_user_id, old.facts.upstream_user_id); assert.equal(data.facts.name, old.facts.name)
    assert.equal(data.facts.plan_type, a.id.startsWith('force_') ? 'plus' : 'free'); assert.equal(data.facts.upstream_account_id, a.id.startsWith('force_') ? 'alternate-workspace' : 'personal-workspace'); assert.equal(data.facts.material.refresh_token, 'fallback-private-rt')
    saves.push(a.id)
    if (a.id === 'fb_save_failure') return result(meta.id, {}, {})
    a.accountId = data.facts.upstream_account_id; a.planType = data.facts.plan_type; a.status = 'normal'
    const revision = revisions.get(a.id) + 1; revisions.set(a.id, revision)
    credentials.set(a.id, { ...old, credential_revision: revision, facts: structuredClone(data.facts) })
    if (a.id === 'fb_uncertain') return result(meta.id, {}, {})
    if (a.id === 'fb_postcheck') a.enabled = true
    return result(meta.id, {}, { account_id: a.id, credential_revision: revision })
  }
  if (meta.method === 'host.state.get') return result(meta.id, { record: records.get(data.key) || null })
  if (meta.method === 'host.state.put') {
    const old = records.get(data.key)
    assert.equal(data.expected_version, old?.version ?? null)
    const version = (old?.version || 0) + 1
    const serialized = JSON.stringify(data.value)
    for (const secret of ['fixture-password', 'fixture:pass', 'secret-code', 'refreshToken', 'authorizationUrl', 'callbackUrl', 'fallback-private-rt', 'access_token', 'id_token', 'refresh_token', 'fixture-cookie']) assert.ok(!serialized.includes(secret), `Persistent state leaked ${secret}`)
    records.set(data.key, { value: structuredClone(data.value), version, schema_version: 1 })
    return result(meta.id, { version })
  }
  if (meta.method === 'host.http.dispatch') {
    const url = new URL(meta.params.uri, 'http://mock.invalid')
    let dataReply, status = 200, code = 200
    if (url.pathname === '/api/admin/accounts') { assert.equal(meta.params.method, 'GET'); dataReply = { items: accounts } }
    else if (url.pathname === '/api/admin/accounts/detail') { assert.equal(meta.params.method, 'GET'); dataReply = { account: accounts.find(a => a.id === url.searchParams.get('accountId')), credentialConfiguration: { transport: 'http' } } }
    else if (url.pathname === '/api/admin/accounts/export') {
      assert.equal(meta.params.method, 'GET'); assert.equal(url.searchParams.get('confirm'), 'export_sensitive_accounts')
      const id = url.searchParams.get('accountIds'); assert.ok(!id.includes(','))
      dataReply = { documents: [{ provider: 'openai', document: { accounts: [{ id, outboundProxyUrl: 'http://fixture:pass@127.0.0.1:21001', refreshToken: 'old-secret-rt' }] } }] }
    }
    else if (url.pathname === '/api/admin/accounts/oauth/start') { assert.equal(meta.params.method, 'POST'); assert.deepEqual(Object.keys(data).sort(), ['accountId', 'name', 'provider']); starts.push(structuredClone(data)); dataReply = { flowId: `flow_${data.accountId}`, authorizationUrl: nativeAuthorization }; status = 201 }
    else if (url.pathname === '/api/admin/accounts/batch-update') {
      assert.equal(meta.params.method, 'POST'); assert.deepEqual(Object.keys(data).sort(), ['accountIds', 'enabled']); assert.equal(data.accountIds.length, 1); assert.equal(data.enabled, false)
      const a = accounts.find(a => a.id === data.accountIds[0]); assert.equal(a.capacity.usedSlots, 0)
      disables.push(a.id); dataReply = {}
      if (a.id === 'fb_disable_failure') { status = 502; code = 50201 }
      else { a.enabled = false; if (a.id === 'fb_disable_race') revisions.set(a.id, revisions.get(a.id) + 1); if (a.id === 'fb_inflight_race') a.capacity.usedSlots = 1 }
    }
    else if (url.pathname === '/api/admin/accounts/oauth/complete') {
      assert.equal(meta.params.method, 'POST'); assert.deepEqual(Object.keys(data).sort(), ['callbackUrl', 'flowId', 'provider']); completes.push(structuredClone(data)); const a = accounts.find(a => `flow_${a.id}` === data.flowId)
      assert.ok(a); a.status = 'normal'; a.accessTokenExpiresAt = '2026-10-24T00:00:00Z'; dataReply = { accountId: a.id }; status = 201
      if (failComplete) { status = 502; code = 50201; dataReply = null }
    } else throw new Error(`Unexpected route ${url.pathname}`)
    const handle = randomUUID(); handles.set(handle, Buffer.from(JSON.stringify({ code, message: code === 200 ? 'ok' : 'secret-code fixture-password', data: dataReply })))
    return result(meta.id, { status, version: 'HTTP/1.1', headers: [], body: { kind: 'handle', handle }, response: null, session: false })
  }
  if (meta.method === 'host.http.body_read') { const value = handles.get(meta.params.handle); if (value) { handles.delete(meta.params.handle); return result(meta.id, { eof: false, trailers: null }, value) } return result(meta.id, { eof: true, trailers: null }) }
  if (meta.method === 'host.http.body_close') return result(meta.id)
  throw new Error(`Unexpected callback ${meta.method}`)
}
function parse() {
  while (buffer.length >= 12) {
    const m = buffer.readUInt32BE(), p = Number(buffer.readBigUInt64BE(4)), total = 12 + m + p
    if (buffer.length < total) break
    const meta = JSON.parse(buffer.subarray(12, 12 + m).toString()), payload = buffer.subarray(12 + m, total); buffer = buffer.subarray(total)
    if (meta.type === 'ready') ready.resolve()
    else if (meta.type === 'callback') callback(meta, payload).catch(e => { ready.reject(e); for (const w of pending.values()) w.reject(e) })
    else { const w = pending.get(meta.id); if (w) { pending.delete(meta.id); if (meta.type === 'result') w.resolve({ result: meta.result, payload }); else w.reject(new Error(JSON.stringify(meta.error))) } }
  }
}
async function start() {
  ready = Promise.withResolvers(); pending = new Map(); buffer = Buffer.alloc(0); errors = ''
  child = spawn(binary, [], { env: { ...process.env, RS_REAUTH_TEST_PYTHON: python, RS_REAUTH_TEST_WORKER: worker }, stdio: ['pipe', 'pipe', 'pipe'] })
  child.stdout.on('data', data => { buffer = Buffer.concat([buffer, data]); parse() }); child.stderr.on('data', data => errors += data)
  child.on('error', e => ready.reject(e))
  child.on('exit', code => { if (code) { const e = new Error(`Plugin exit ${code}: ${errors}`); ready.reject(e); for (const w of pending.values()) w.reject(e) } })
  send({ type: 'hello', handshake: { protocol_version: 2, artifact_sha256: 'a'.repeat(64), plugin_id: 'personal.reauth-manager', instance_id: 'test_instance', generation: 1, incarnation: 'fixture', configuration: {}, contributes: { management: { id: 'personal.reauth-manager.management', version: 1, stages: ['management'] }, maintenance: { id: 'personal.reauth-manager.maintenance', version: 1, stages: ['maintenance'] } } } })
  await ready.promise
}
async function stop() { const exited = new Promise(resolve => child.once('exit', resolve)); send({ type: 'shutdown' }); child.stdin.end(); await exited }
async function call(method, params = {}, payload = Buffer.alloc(0), stage = 'management') {
  const id = sequence += 2, w = Promise.withResolvers(); pending.set(id, w)
  send({ type: 'call', id, method, params, context: { call_id: id, instance_id: 'test_instance', generation: 1, incarnation: 'fixture', stage, timeout_ms: 60000, resource_stream: false, resource_scope_id: `scope_${id}` } }, payload)
  return Promise.race([w.promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`Timeout ${method}`)), 10000).unref())])
}
async function request(path, data) { const r = await call('management.handle', { method: data === undefined ? 'GET' : 'POST', path: `api/${path}`, query: '', content_type: data === undefined ? null : 'application/json', headers: [] }, data === undefined ? Buffer.alloc(0) : data); return { status: r.result.status, value: JSON.parse(r.payload.toString()) } }
const submit = (ids, requestId = randomUUID()) => request('submit', { accountIds: ids, requestId })
const tick = () => request('tick', {})
const job = id => records.get('queue').value.jobs.filter(j => j.accountId === id).at(-1)
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
async function finish(id) { for (let i = 0; i < 60; i++) { await tick(); if (!['queued', 'running'].includes(job(id).status)) return job(id); await sleep(60) } throw new Error('Job did not finish: ' + JSON.stringify(job(id))) }
let passed = 0
const check = name => { passed++; console.log(`PASS ${name}`) }
try {
  await start()
  const reg = JSON.parse((await call('management.register', {}, Buffer.alloc(0), 'registration')).payload.toString()); assert.equal(reg.resources.length, 3); assert.equal(reg.routes.length, 8); assert.ok(!reg.resources.some(r => r.path.includes('runtime'))); check('Only UI resources are exposed, protocol runtime stays private')
  const beforeProbe = records.get('queue')?.value.jobs.length ?? 0; assert.deepEqual((await request('runtime-check', {})).value, { ready: true }); assert.equal(starts.length, 0); assert.equal(completes.length, 0); assert.equal(records.get('queue')?.value.jobs.length ?? 0, beforeProbe); check('Runtime preflight never queues an account or starts native authorization')
  const listing = await request('accounts'); assert.equal(listing.status, 200); assert.equal(listing.value.accounts.length, 11); assert.ok(listing.value.accounts.some(a => a.id === 'free')); assert.ok(!listing.value.accounts.some(a => ['api_key', 'other_provider'].includes(a.id))); for (const a of listing.value.accounts) { assert.ok(!('notes' in a)); assert.ok(!('refreshToken' in a)); assert.ok(!JSON.stringify(a).includes('fixture-password')) } check('All OpenAI OAuth plans including Free are listed without leaking credentials')
  assert.equal(listing.value.accounts.find(a => a.id === 'bad_notes').notesValid, false); check('Notes must match original account email')
  assert.deepEqual(listing.value.accounts.find(a => a.id === 'good').groups, [{ id: 'g1', name: 'Team' }, { id: 'g2', name: 'Shared Group' }]); assert.deepEqual(listing.value.accounts.find(a => a.id === 'free').groups, []); check('RS group names and multiple memberships are returned without leaking unrelated fields')
  assert.equal((await submit(['good', 'good'])).status, 400); assert.equal((await submit(['../escape'])).status, 400); assert.equal((await submit([])).status, 400); check('Reject duplicate, malformed and empty selections')
  const requestId = randomUUID(); await submit(['good'], requestId); await submit(['good'], requestId); assert.equal(records.get('queue').value.jobs.length, 1); assert.equal(starts.length, 0); check('Submission is idempotent and GET/submission never starts a login')
  assert.equal((await submit(['good'])).status, 400); check('Concurrent submissions cannot duplicate an account')
  const before = structuredClone(accounts.find(a => a.id === 'good')); await tick(); assert.equal(starts.length, 1); assert.equal(completes.length, 0); const done = await finish('good'); assert.equal(done.status, 'success'); const after = accounts.find(a => a.id === 'good'); for (const k of ['enabled', 'groups', 'notes', 'weight', 'concurrencyLimit', 'outboundProxyEndpoint', 'name', 'accountId']) assert.deepEqual(after[k], before[k]); check('Real SDK process completes native OAuth start/complete and verifies unchanged configuration')
  await submit(['disabled']); assert.equal((await finish('disabled')).status, 'success'); assert.equal(accounts.find(a => a.id === 'disabled').enabled, false); check('Disabled account remains disabled after reauthorization')
  const freeBefore = structuredClone(free); const freeStarts = starts.length, freeCompletes = completes.length; await submit(['free']); assert.equal((await finish('free')).status, 'success'); assert.equal(starts.length, freeStarts + 1); assert.equal(completes.length, freeCompletes + 1); for (const k of ['id', 'enabled', 'groups', 'notes', 'outboundProxyEndpoint', 'name', 'accountId', 'planType']) assert.deepEqual(free[k], freeBefore[k]); check('Free account completes original-account authorization while preserving proxy and configuration')
  for (const id of ['missing_proxy', 'bad_notes', 'active', 'api_key', 'other_provider']) { const old = starts.length; await submit([id]); assert.equal((await finish(id)).status, 'failed'); assert.equal(starts.length, old) } check('Missing proxy, invalid notes, active requests and unsupported credentials stop before login')
  await submit(['failed']); assert.equal((await finish('failed')).status, 'failed'); assert.match(job('failed').message, /密码/); check('Password rejection returns a safe actionable error')
  await submit(['changed']); await tick(); accounts.find(a => a.id === 'changed').enabled = false; const count = completes.length; assert.equal((await finish('changed')).status, 'review'); assert.equal(completes.length, count); check('Configuration changes during login block credential writeback')
  await submit(['credential_changed']); await tick(); revisions.set('credential_changed', 2); const previous = completes.length; assert.equal((await finish('credential_changed')).status, 'review'); assert.equal(completes.length, previous); check('Concurrent credential rotation blocks stale OAuth writeback')
  await submit(['slow', 'good']); await tick(); const startsBefore = starts.length; const c = completes.length; await request('cancel', { requestId: null }); await tick(); assert.equal(job('slow').status, 'cancelled'); assert.equal(job('good').status, 'cancelled'); assert.equal(starts.length, startsBefore); assert.equal(completes.length, c); check('Cancel kills current helper and stops all later accounts without writeback')
  failComplete = true; await submit(['uncertain']); assert.equal((await finish('uncertain')).status, 'review'); const committed = completes.length; await tick(); await tick(); assert.equal(completes.length, committed); failComplete = false; check('Uncertain native commit is never automatically replayed')
  await submit(['slow', 'good']); await tick(); await stop(); await start(); await request('jobs'); assert.equal(job('slow').status, 'interrupted'); assert.equal(job('good').status, 'interrupted'); const prior = starts.length; await tick(); assert.equal(starts.length, prior); check('Restart interrupts all queued/running tasks without automatic credential submission')
  function fallbackAccount(id) { const a = make(id); a.userId = 'original-user'; accounts.push(a); revisions.set(id, 1); return a }
  for (const id of ['fb_good', 'fb_disabled', 'fb_already_free']) {
    const a = fallbackAccount(id)
    if (id === 'fb_disabled') a.enabled = false
    if (id === 'fb_already_free') a.planType = 'free'
    const before = structuredClone(a), oldCompletes = completes.length, d = disables.length
    await submit([id]); const done = await finish(id)
    assert.equal(done.status, 'success'); assert.equal(done.step, 'free'); assert.match(done.message, /原工作区已失效.*已切回 Free.*已停止调度/)
    assert.equal(a.enabled, false); assert.equal(a.planType, 'free'); assert.equal(a.accountId, 'personal-workspace'); assert.equal(a.status, 'normal')
    for (const k of ['id', 'email', 'userId', 'name', 'groups', 'notes', 'outboundProxyEndpoint', 'weight', 'concurrencyLimit', 'modelAccess']) assert.deepEqual(a[k], before[k])
    assert.equal(completes.length, oldCompletes); assert.equal(disables.length, d + (before.enabled ? 1 : 0)); assert.equal(saves.at(-1), id)
    check(`${id}: verified Free recovery replaces original ID via SDK CAS, preserves settings, and stops scheduling`)
  }
  for (const id of ['fb_user', 'fb_workspace', 'fb_plan', 'fb_email', 'fb_expired', 'fb_proof', 'fb_rt', 'fb_old_workspace', 'fb_missing_user']) {
    const a = fallbackAccount(id); if (id === 'fb_missing_user') a.userId = null
    const old = structuredClone(a), d = disables.length, s = saves.length
    await submit([id]); assert.equal((await finish(id)).status, 'review'); assert.equal(disables.length, d); assert.equal(saves.length, s); assert.deepEqual(a, old)
  }
  check('Wrong user/email/workspace/plan, stale token, missing proof/RT/original identity never disable or write')
  for (const id of ['fb_changed', 'fb_revision', 'fb_active']) {
    const a = fallbackAccount(id), d = disables.length, s = saves.length
    await submit([id]); await tick()
    if (id === 'fb_changed') a.weight = 4
    if (id === 'fb_revision') revisions.set(id, 2)
    if (id === 'fb_active') a.capacity.usedSlots = 1
    assert.equal((await finish(id)).status, 'review'); assert.equal(disables.length, d); assert.equal(saves.length, s)
  }
  check('Concurrent settings/credential changes and in-flight work stop before Free recovery mutations')
  for (const id of ['fb_disable_failure', 'fb_disable_race', 'fb_inflight_race', 'fb_save_failure', 'fb_uncertain', 'fb_postcheck']) {
    const a = fallbackAccount(id), s = saves.length
    await submit([id]); assert.equal((await finish(id)).status, 'review')
    if (!['fb_disable_failure', 'fb_postcheck'].includes(id)) assert.equal(a.enabled, false)
    if (['fb_disable_failure', 'fb_disable_race', 'fb_inflight_race'].includes(id)) assert.equal(saves.length, s)
    const count = saves.length, d = disables.length; await tick(); await tick(); assert.equal(saves.length, count); assert.equal(disables.length, d)
    check(`${id}: partial or uncertain mutation requires review and is never replayed`)
  }
  for (const id of ['force_good', 'force_wrong_user', 'force_wrong_workspace', 'force_changed', 'force_disabled', 'force_no_confirmation']) {
    const a = fallbackAccount(id); if (id === 'force_disabled') a.enabled = false
    const original = structuredClone(a), saved = saves.length, disabled = disables.length
    await submit([id]); assert.equal((await finish(id)).step, 'workspace')
    assert.equal(saves.length, saved); assert.equal(disables.length, disabled)
    const source = structuredClone(job(id))
    assert.deepEqual(source.workspaceChoices, [{ id: 'alternate-workspace' }, { id: 'second-workspace' }])
    const payload = { sourceRequestId: source.requestId, workspaceId: 'alternate-workspace', requestId: randomUUID(), confirmation: 'replace_workspace_and_disable' }
    assert.equal((await request('force-submit', { ...payload, confirmation: '' })).status, 400)
    assert.equal((await request('force-submit', { ...payload, workspaceId: 'unknown-workspace' })).status, 400)
    assert.equal((await request('force-submit', payload)).status, 200)
    assert.equal((await request('force-submit', payload)).status, 200)
    assert.equal((await request('force-submit', { ...payload, requestId: randomUUID() })).status, 400)
    await tick()
    if (id === 'force_changed') a.weight = 5
    const done = await finish(id)
    if (['force_good', 'force_disabled'].includes(id)) {
      assert.equal(done.status, 'success'); assert.match(done.message, /管理员已确认.*已停止调度/)
      assert.equal(a.accountId, 'alternate-workspace'); assert.equal(a.planType, 'plus'); assert.equal(a.enabled, false)
      for (const key of ['id', 'email', 'userId', 'name', 'groups', 'notes', 'outboundProxyEndpoint', 'weight', 'concurrencyLimit', 'modelAccess']) assert.deepEqual(a[key], original[key])
      const count = saves.length; await tick(); assert.equal(saves.length, count)
    } else { assert.equal(done.status, 'review'); assert.equal(saves.length, saved); assert.equal(disables.length, disabled) }
    check(`${id}: explicit workspace selection and confirmation, identity/CAS guards and scheduling policy`)
  }
  {
    const id = 'free_fallback_no_candidates'; const a = fallbackAccount(id); const saved = saves.length; const disabled = disables.length
    await submit([id]); assert.equal((await finish(id)).status, 'failed'); assert.equal(job(id).step, 'workspace'); assert.deepEqual(job(id).workspaceChoices, [])
    const sourceRequestId = job(id).requestId
    assert.equal((await request('free-fallback', { sourceRequestId, requestId: randomUUID(), confirmation: '' })).status, 400)
    const fallbackRequestId = randomUUID(); const freeResult = await request('free-fallback', { sourceRequestId, requestId: fallbackRequestId, confirmation: 'fallback_free_and_disable' }); if (freeResult.status !== 200) console.log(JSON.stringify(freeResult)); assert.equal(freeResult.status, 200)
    assert.equal((await request('free-fallback', { sourceRequestId, requestId: fallbackRequestId, confirmation: 'fallback_free_and_disable' })).status, 200)
    await tick(); const done = await finish(id); assert.equal(done.status, 'success'); assert.equal(done.step, 'free'); assert.match(done.message, /退回同一用户的 Free/)
    assert.equal(a.planType, 'free'); assert.equal(a.enabled, false); assert.equal(saves.at(-1), id); assert.equal(disables.length, disabled + 1); assert.ok(saves.length > saved)
    check('No-candidate failure requires explicit Free fallback confirmation and writes the verified Free token')
  }
  await stop(); assert.equal(errors, ''); console.log(`Verified ${passed} protocol scenarios`)
} catch (error) { child?.kill(); console.error(error); process.exitCode = 1 }
