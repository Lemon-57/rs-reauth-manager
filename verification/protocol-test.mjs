import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'

const binary = process.argv[2] || fileURLToPath(new URL(`../backend/target/debug/reauth-manager${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url))
const python = process.env.RS_REAUTH_TEST_PYTHON || process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
const worker = fileURLToPath(new URL('./fake-worker.py', import.meta.url))
const innerAuthorization = 'https://auth.openai.com/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: 'fixture', redirect_uri: 'http://127.0.0.1:1455/auth/callback', state: 'fixture', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256' })
const nativeAuthorization = 'https://chatgpt.com/codex/desktop-auth?' + new URLSearchParams({ authorize_url: innerAuthorization, codex_streamlined_login: 'true', no_universal_links: '1' })
const make = id => ({id,provider:'openai',name:`team+${id}@example.com+workspace3`,email:`${id}@example.com`,authenticationKind:'oauth',userId:'original-user',enabled:id!=='disabled',planType:'team',status:'error',notes:`${id}@example.com----fixture-password----GEZDGNBVGY3TQOJQ`,outboundProxyEndpoint:'http://127.0.0.1:21001',accountId:'original-workspace',groups:[{id:'g1',name:'Team'}],weight:3,concurrencyLimit:null,modelAccess:{mode:'all'},hasRefreshToken:true,capacity:{usedSlots:0},errorReason:null})
const accounts=[],records=new Map(),handles=new Map(),credentials=new Map(),revisions=new Map(),nativeMaterials=new Map()
const starts=[],completes=[],refreshes=[],metadataSaves=[],controls=[],deleted=[]
const importFlows=new Map()
let child,buffer,pending,ready,sequence=99,errors='',directoryGate=null
const AUTH='https://api.openai.com/auth'
const jwt = p => 'fixture.'+Buffer.from(JSON.stringify(p)).toString('base64url')+'.signature'
function credential(a,workspace=a.accountId,plan=a.planType) {
 const payload={email:a.email,sub:'original-subject',exp:Math.floor(Date.now()/1000)+3600,[AUTH]:{chatgpt_account_id:workspace,chatgpt_user_id:a.userId,chatgpt_plan_type:plan.trim().toLowerCase()}}
 const token=jwt(payload)
 return {account_id:a.id,provider_id:'openai',credential_revision:revisions.get(a.id),facts:{name:a.name,authentication_kind:'oauth',material:{schema_version:1,installation_id:'3d07c9c6-3b57-4a12-a51d-1e21df254477',transport:'http',principal:{oauth_subject:'original-subject',poid:null},access_token:token,id_token:token,refresh_token:'old-private-rt',oauth_client_id:'fixture',oauth_scope:'openid',cookies:[{name:'fixture',value:'fixture-cookie'}]},email:a.email,upstream_user_id:a.userId,upstream_account_id:a.accountId,plan_type:a.planType,has_refresh_token:true,access_token_expires_at_ms:null,next_refresh_at_ms:null}}
}
function add(id) {const a=make(id);accounts.push(a);revisions.set(id,1);credentials.set(id,credential(a));return a}
function send(meta, payload = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(JSON.stringify(payload))
  meta = structuredClone(meta)
  let business
  if (meta.type === 'hello') { business = meta.handshake.configuration; delete meta.handshake.configuration }
  else if (meta.type === 'call' || meta.type === 'callback') { business = meta.params; delete meta.params }
  else if (meta.type === 'result') { business = meta.result; delete meta.result }
  if (business !== undefined) { const data = Buffer.from(JSON.stringify(business)); meta.data_bytes = data.length; payload = Buffer.concat([data, payload]) }
  const json = Buffer.from(JSON.stringify(meta)), head = Buffer.alloc(12)
  head.writeUInt32BE(json.length); head.writeBigUInt64BE(BigInt(payload.length), 4)
  child.stdin.write(Buffer.concat([head, json, payload]))
}
const result = (id, value = {}, payload) => send({ type: 'result', id, result: value }, payload)
async function callback(meta,payload) {
 const data=payload.length?JSON.parse(payload.toString()):meta.params
 if(meta.method==='host.auth.get_runtime')return result(meta.id,{}, {account_id:data.account_id,provider_id:'openai',credential_revision:revisions.get(data.account_id),credential_state:accounts.find(a=>a.id===data.account_id)?.runtimeCredentialState||'ready'})
 if(meta.method==='host.auth.get')return result(meta.id,{},credentials.get(data.account_id))
 if(meta.method==='host.auth.save') {
  const a=accounts.find(a=>a.id===data.account_id),old=credentials.get(a.id)
  assert.equal(a.enabled,false);assert.equal(data.credential_revision,revisions.get(a.id));assert.equal(data.action,'replace')
  for(const key of ['access_token','refresh_token','id_token'])assert.deepEqual(data.facts.material[key],nativeMaterials.get(a.id)[key],'Only native-issued tokens may be retained during metadata updates')
  metadataSaves.push(a.id)
  if(a.id==='fb_metadata_lost')return result(meta.id,{}, {})
  const revision=revisions.get(a.id)+1;revisions.set(a.id,revision)
  a.accountId=data.facts.upstream_account_id;a.planType=data.facts.plan_type;a.status='disabled'
  credentials.set(a.id,{...old,credential_revision:revision,facts:structuredClone(data.facts)})
  return result(meta.id,{}, {account_id:a.id,credential_revision:revision})
 }
 if(meta.method==='host.state.get')return result(meta.id,{record:records.get(data.key)||null})
 if(meta.method==='host.state.put') {
  const old=records.get(data.key);assert.equal(data.expected_version,old?.version??null)
  const raw=JSON.stringify(data.value)
  for(const secret of ['fixture-password','fixture:pass','secret-code','access_token','refresh_token','id_token','fixture-cookie','fixture-current-session','59859b73-b63b-45f4-86f9-e728a9512905'])assert.ok(!raw.includes(secret),'Private material must not enter job state')
  const version=(old?.version||0)+1;records.set(data.key,{value:structuredClone(data.value),version,schema_version:1});return result(meta.id,{version})
 }
 if(meta.method==='host.http.dispatch') {
  const url=new URL(meta.params.uri,'http://mock.invalid');let dataReply,status=200,code=200
  if(url.pathname==='/api/admin/accounts/oauth/start'&&!data.accountId){
   assert.deepEqual(Object.keys(data).sort(),['name','outboundProxyUrl','provider'])
   assert.equal(data.outboundProxyUrl,'http://fixture:pass@127.0.0.1:21001')
   const id=data.name.slice('team+'.length).split('@')[0],flowId='import_'+id
   importFlows.set(flowId,id);starts.push(structuredClone(data));dataReply={flowId,authorizationUrl:nativeAuthorization};status=201
  }else if(url.pathname==='/api/admin/accounts/oauth/complete'&&data.settings){
   assert.deepEqual(Object.keys(data).sort(),['callbackUrl','flowId','provider','settings'])
   assert.equal(data.settings.enabled,false);assert.equal(data.callbackUrl,'http://127.0.0.1:1455/auth/callback?state=fixture&code=secret-code')
   const id=importFlows.get(data.flowId);assert.ok(id);const a=add(id)
   Object.assign(a,{enabled:false,status:'disabled',notes:data.settings.notes,groups:data.settings.groupIds.map(id=>({id,name:'Team'})),concurrencyLimit:data.settings.concurrencyLimit,weight:data.settings.weight,modelAccess:data.settings.modelAccess})
   credentials.set(a.id,credential(a));completes.push(structuredClone(data))
   if(id==='new_wrong_user'){const c=credentials.get(a.id),p=JSON.parse(Buffer.from(c.facts.material.access_token.split('.')[1],'base64url'));p[AUTH].chatgpt_user_id='wrong-user';c.facts.material.access_token=jwt(p)}
   if(id==='new_missing_rt')credentials.get(a.id).facts.material.refresh_token=''
   dataReply={accountId:a.id}
  }else if(url.pathname==='/api/admin/accounts'){if(directoryGate)await directoryGate.promise;dataReply={items:accounts}}
  else if(url.pathname==='/api/admin/accounts/detail')dataReply={account:accounts.find(a=>a.id===url.searchParams.get('accountId')),credentialConfiguration:{transport:'http'}}
  else if(url.pathname==='/api/admin/accounts/export') {
   assert.equal(url.searchParams.get('confirm'),'export_sensitive_accounts');const id=url.searchParams.get('accountIds');assert.ok(!id.includes(','))
   dataReply={documents:[{provider:'openai',document:{accounts:[{id,outboundProxyUrl:'http://fixture:pass@127.0.0.1:21001'+(id.startsWith('new_')?'/':'')}]}}]}
  } else if(url.pathname==='/api/admin/accounts/oauth/start') {
   assert.deepEqual(Object.keys(data).sort(),['accountId','name','provider']);starts.push(structuredClone(data));dataReply={flowId:`flow_${data.accountId}`,authorizationUrl:nativeAuthorization};status=201
  } else if(url.pathname==='/api/admin/accounts/batch-update') {
   assert.deepEqual(Object.keys(data).sort(),['accountIds','enabled']);assert.equal(data.accountIds.length,1)
   const a=accounts.find(a=>a.id===data.accountIds[0]);assert.equal(a.capacity.usedSlots,0);controls.push([a.id,data.enabled])
   a.enabled=data.enabled;a.status=data.enabled?'normal':'disabled';dataReply={}
   if(a.id==='pause_race'&&!data.enabled)revisions.set(a.id,revisions.get(a.id)+1)
   if(a.id==='resume_lost'&&data.enabled){status=503;code=50301}
  } else if(url.pathname==='/api/admin/accounts/oauth/complete') {
   assert.deepEqual(Object.keys(data).sort(),['callbackUrl','flowId','provider'])
   const a=accounts.find(a=>`flow_${a.id}`===data.flowId);assert.equal(a.enabled,false);assert.equal(a.capacity.usedSlots,0)
   assert.equal(data.callbackUrl,'http://127.0.0.1:1455/auth/callback?state=fixture&code=secret-code');completes.push(structuredClone(data))
   if(a.id==='native_503'||a.id==='auto_native_503'){status=503;code=50301;dataReply=null}
   else {
    let workspace=a.accountId,plan=a.planType
    if(a.id.startsWith('fb_')||a.id==='free_fallback_no_candidates'){workspace='personal-workspace';plan='free'}
    if(a.id.startsWith('up_')){workspace='team-workspace';plan='team'}
    if(a.id.startsWith('force_')){workspace='alternate-workspace';plan='plus'}
    const c=credential(a,workspace,plan);c.facts.material.principal=credentials.get(a.id).facts.material.principal;const p=JSON.parse(Buffer.from(c.facts.material.id_token.split('.')[1],'base64url'))
    if(a.id.includes('wrong_user'))p[AUTH].chatgpt_user_id='wrong-user'
    if(a.id.includes('wrong_workspace'))p[AUTH].chatgpt_account_id='other-workspace'
    if(a.id.includes('wrong_plan'))p[AUTH].chatgpt_plan_type=a.planType==='free'?'free':'plus'
    if(a.id.includes('wrong_email'))p.email='other@example.com'
    if(a.id.includes('wrong_subject'))p.sub='wrong-subject'
    if(a.id.includes('expired_tokens'))p.exp=1
    c.facts.material.access_token=c.facts.material.id_token=jwt(p);c.facts.material.refresh_token=a.id==='missing_rt'?'':'native-issued-private-rt'
    const rev=revisions.get(a.id)+1;revisions.set(a.id,rev);c.credential_revision=rev;credentials.set(a.id,c);nativeMaterials.set(a.id,structuredClone(c.facts.material));a.status='disabled'
    a.runtimeCredentialState='ready';a.errorReason=null
    dataReply={accountId:a.id};status=201
   }
  } else if(url.pathname==='/api/admin/accounts/refresh') {
   assert.deepEqual(Object.keys(data),['accountId']);const a=accounts.find(a=>a.id===data.accountId);assert.equal(a.enabled,false);refreshes.push(a.id)
   if(a.id==='refresh_503'){status=503;code=50301;dataReply=null}
   else {
    const c=credentials.get(a.id),rev=revisions.get(a.id)+1;c.credential_revision=rev;revisions.set(a.id,rev)
    c.facts.material.refresh_token='native-refreshed-private-rt'
    if(a.id==='refresh_wrong_user'){const p=JSON.parse(Buffer.from(c.facts.material.access_token.split('.')[1],'base64url'));p[AUTH].chatgpt_user_id='wrong-user';c.facts.material.access_token=jwt(p)}
    a.status='disabled';dataReply={account:a}
   }
  } else if(url.pathname==='/api/admin/accounts/delete') {
   deleted.push(...data.accountIds);for(const id of data.accountIds){const i=accounts.findIndex(a=>a.id===id);if(i>=0)accounts.splice(i,1)}dataReply={accountIds:data.accountIds,deletedCount:data.accountIds.length}
  } else throw Error('Unexpected native route '+url.pathname)
  const handle=randomUUID();handles.set(handle,Buffer.from(JSON.stringify({code,message:code===200?'ok':'private-upstream-response',data:dataReply})))
  return result(meta.id,{status,version:'HTTP/1.1',headers:[],body:{kind:'handle',handle},response:null,session:false})
 }
 if(meta.method==='host.http.body_read'){const v=handles.get(meta.params.handle);if(v){handles.delete(meta.params.handle);return result(meta.id,{eof:false,trailers:null},v)}return result(meta.id,{eof:true,trailers:null})}
 if(meta.method==='host.http.body_close')return result(meta.id)
 throw Error('Unexpected SDK callback '+meta.method)
}
function parse() {
  while (buffer.length >= 12) {
    const m = buffer.readUInt32BE(), p = Number(buffer.readBigUInt64BE(4)), total = 12 + m + p
    if (buffer.length < total) break
    const meta = JSON.parse(buffer.subarray(12, 12 + m).toString()); let payload = buffer.subarray(12 + m, total); buffer = buffer.subarray(total)
    const requestBytes = meta.request_context_bytes ?? 0, dataBytes = meta.data_bytes ?? 0
    if (dataBytes) {
      const data = JSON.parse(payload.subarray(requestBytes, requestBytes + dataBytes).toString())
      if (meta.type === 'hello') meta.handshake.configuration = data
      else if (meta.type === 'call' || meta.type === 'callback') meta.params = data
      else if (meta.type === 'result') meta.result = data
    }
    payload = payload.subarray(requestBytes + dataBytes)
    if (meta.type === 'ready') { assert.equal(meta.protocol_version, 4); ready.resolve() }
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
  send({ type: 'hello', handshake: { protocol_version: 4, artifact_sha256: 'a'.repeat(64), plugin_id: 'personal.reauth-manager', instance_id: 'test_instance', generation: 1, incarnation: 'fixture', configuration: {}, contributes: { management: { id: 'personal.reauth-manager.management', version: 2, stages: ['management'] }, maintenance: { id: 'personal.reauth-manager.maintenance', version: 1, stages: ['maintenance'] } } } })
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
let passed=0
const check=name=>{passed++;console.log('PASS '+name)}
try {
 await start()
 const reg=JSON.parse((await call('management.register',{},Buffer.alloc(0),'registration')).payload.toString());assert.equal(reg.routes.length,11)
 assert.deepEqual((await request('runtime-check',{})).value,{ready:true});assert.equal(starts.length,0);check('Runtime preflight never starts authorization')
 for(const id of ['new_team','new_wrong_user','new_missing_rt','new_cleanup_failure','new_verify_failure']){
  const req={requestId:randomUUID(),email:id+'@example.com',notes:id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ',proxyUrl:'http://fixture:pass@127.0.0.1:21001',groupIds:['g1']}
  const n=starts.length,c=completes.length
  assert.equal((await request('import',req)).status,200)
  const duplicate=await request('import',req);assert.equal(duplicate.status,200);assert.equal(starts.length,n+1)
  let done
  for(let i=0;i<60;i++){await tick();done=records.get('queue').value.jobs.find(j=>j.requestId===req.requestId);if(!['queued','running'].includes(done.status))break;await sleep(60)}
  assert.equal(completes.length,c+1);assert.equal(accounts.find(a=>a.id===id).enabled,id==='new_team')
  if(id==='new_team'){assert.equal(done.status,'success',done.message);assert.equal(done.accountId,id);assert.equal(done.cleanupStarted,true);assert.ok(refreshes.includes(id))}
  else{assert.equal(done.status,'review',done.message);const before=[starts.length,completes.length];await tick();assert.deepEqual([starts.length,completes.length],before)}
  const count=starts.length;assert.equal((await request('import',{...req,requestId:randomUUID(),email:'other@example.com',notes:'other@example.com----fixture-password----GEZDGNBVGY3TQOJQ'})).status,400);assert.equal(starts.length,count)
  accounts.splice(accounts.findIndex(a=>a.id===id),1)
  check(`${id}: new accounts use native start/complete, validate AT and ID Token, enable on success and never replay`)
 }
 {
  const n=starts.length
  const req={requestId:randomUUID(),email:'invalid@example.com',notes:'invalid@example.com----fixture----not-valid-2FA',proxyUrl:'http://fixture:pass@127.0.0.1:21001',groupIds:['g1']}
  assert.equal((await request('import',req)).status,400);assert.equal(starts.length,n)
  check('Malformed new-account credentials never start an OAuth flow')
 }

 for(const id of ['good','disabled','free','legacy_principal']) {
  const a=add(id);if(id==='legacy_principal')credentials.get(id).facts.material.principal=null;if(id==='free'){a.planType='free';credentials.set(id,credential(a))}
  const before=structuredClone(a),n=completes.length,r=refreshes.length,m=metadataSaves.length
  await submit([id]);const done=await finish(id);assert.equal(done.status,'success',done.message)
  assert.equal(completes.length,n+1);assert.equal(refreshes.length,r+1);assert.equal(metadataSaves.length,m)
  assert.match(done.message,/已登出其他设备/);assert.equal(credentials.get(id).facts.material.refresh_token,'native-refreshed-private-rt')
  for(const k of ['enabled','groups','notes','name','userId','accountId','planType','outboundProxyEndpoint','weight','concurrencyLimit','modelAccess'])assert.deepEqual(a[k],before[k])
  check(`${id}: RS native completion and native refresh exclusively issue and save RT, configuration preserved`)
 }
 for(const id of ['wrong_user','wrong_workspace','wrong_plan','wrong_email','wrong_subject','expired_tokens','missing_rt','native_503','pause_race','plugin_tokens_injected']) {
  const a=add(id),before=completes.length,ref=refreshes.length,meta=metadataSaves.length
  await submit([id]);const done=await finish(id);assert.equal(done.status,'review',done.message)
  assert.equal(refreshes.length,ref);assert.equal(metadataSaves.length,meta)
  if(!['plugin_tokens_injected'].includes(id))assert.equal(a.enabled,false)
  if(['pause_race','plugin_tokens_injected'].includes(id))assert.equal(completes.length,before)
  else assert.equal(completes.length,before+1)
  assert.ok(!done.message.includes('private-upstream-response'));const count=completes.length;await tick();assert.equal(completes.length,count)
  check(`${id}: unconfirmed native save or changed identity is quarantined without alternative token exchange or replay`)
 }
 for(const id of ['fb_good','fb_metadata_lost','up_good','up_wrong_plan']) {
  const a=add(id);if(id.startsWith('up_')){a.planType='free';credentials.set(id,credential(a))}
  const n=completes.length,r=refreshes.length,m=metadataSaves.length
  await submit([id]);const done=await finish(id)
  assert.equal(completes.length,n+1)
  if(['fb_good','up_good'].includes(id)) {
   assert.equal(done.status,'success',done.message);assert.equal(refreshes.length,r+1);assert.equal(metadataSaves.length,m+1)
   assert.equal(a.accountId,id.startsWith('up_')?'team-workspace':'personal-workspace');assert.equal(a.enabled,id.startsWith('up_'))
  } else {assert.equal(done.status,'review');assert.equal(a.enabled,false);assert.equal(refreshes.length,r)}
  check(`${id}: workspace recovery still uses native callback and only changes metadata after the native RT is saved`)
 }
 {
  const a=add('force_good');await submit([a.id]);assert.equal((await finish(a.id)).step,'workspace')
  const sourceRequestId=job(a.id).requestId,n=completes.length
  assert.equal((await request('force-submit',{sourceRequestId,workspaceId:'alternate-workspace',requestId:randomUUID(),confirmation:''})).status,400)
  await request('force-submit',{sourceRequestId,workspaceId:'alternate-workspace',requestId:randomUUID(),confirmation:'replace_workspace_and_disable'})
  assert.equal((await finish(a.id)).status,'success');assert.equal(completes.length,n+1);assert.equal(a.enabled,false);assert.equal(a.planType,'plus')
  check('Explicit workspace replacement keeps confirmation and also delegates code exchange and RT persistence to RS')
 }
 {
  const a=add('free_fallback_no_candidates');await submit([a.id]);await finish(a.id)
  await request('free-fallback',{sourceRequestId:job(a.id).requestId,requestId:randomUUID(),confirmation:'fallback_free_and_disable'})
  assert.equal((await finish(a.id)).status,'success');assert.equal(a.enabled,false);assert.equal(a.planType,'free')
  check('Free recovery without candidates still follows the native callback flow')
 }
 for(const id of ['cleanup_failure','cleanup_no_proof','refresh_503','refresh_wrong_user','resume_lost','verify_failure']) {
  const a=add(id),n=completes.length;await submit([id]);const done=await finish(id);assert.equal(done.status,'review',done.message);assert.equal(completes.length,n+1)
  if(id==='resume_lost'){assert.equal(a.enabled,true);assert.match(done.message,/恢复调度结果不确定/)}else assert.equal(a.enabled,false)
  const calls=[starts.length,completes.length,refreshes.length];await tick();await tick();assert.deepEqual([starts.length,completes.length,refreshes.length],calls)
  check(`${id}: partial device cleanup, native refresh and scheduling uncertainty are not replayed`)
 }
 {
  const a=add('slow');await submit([a.id]);await tick();await request('cancel',{requestId:null});assert.equal(job(a.id).status,'cancelled')
  check('Cancel stops the helper without replaying login or OAuth completion')
 }
 for(const id of ['auto_good','auto_wrong_user','auto_native_503','auto_legacy_principal']) {
  const a=add(id);a.errorReason='credential_expired';a.runtimeCredentialState='expired';if(id==='auto_legacy_principal'){const c=credentials.get(id);c.facts.material.principal=null;for(const key of ['id_token','access_token']){const p=JSON.parse(Buffer.from(c.facts.material[key].split('.')[1],'base64url'));p.exp=1;c.facts.material[key]=jwt(p)}}
  const n=completes.length,r=refreshes.length,m=metadataSaves.length
  await request('automation',{enabled:true})
  await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');assert.equal(job(id).automatic,true)
  const done=await finish(id);assert.equal(completes.length,n+1);assert.equal(metadataSaves.length,m)
  if(['auto_good','auto_legacy_principal'].includes(id)){assert.equal(done.status,'success',done.message);assert.equal(refreshes.length,r+1);assert.equal(a.enabled,true)}
  else {assert.equal(done.status,'review');assert.equal(refreshes.length,r);assert.equal(a.enabled,false)}
  const count=starts.length;await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');assert.equal(starts.length,count)
  await request('automation',{enabled:false})
  check(`${id}: automatic authorization uses the same start/callback/complete/refresh protocol as manual authorization`)
 }
 for(const enabled of [true,false]) {
  const a=add(enabled?'auto_invalid_enabled':'auto_invalid_paused');a.enabled=enabled;a.status='error';a.errorReason='credential_invalid';a.runtimeCredentialState='invalid'
  const n=completes.length,c=controls.length;await request('automation',{enabled:true})
  await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');assert.equal(job(a.id).automatic,true)
  const done=await finish(a.id);assert.equal(done.status,'success',done.message);assert.equal(a.enabled,enabled);assert.equal(completes.length,n+1)
  if(!enabled){assert.ok(!controls.slice(c).some(([id,value])=>id===a.id&&value));await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');assert.equal(records.get('queue').value.automation.attempts[a.id].recovered,true)}
  await request('automation',{enabled:false})
  check(`${a.id}: native Invalid proof triggers the same OAuth flow and preserves the original pause without a temporary enable`)
 }
 {
  const a=add('auto_invalid_unconfirmed');a.enabled=false;a.status='error';a.errorReason='credential_invalid';a.runtimeCredentialState='ready'
  const n=starts.length;await request('automation',{enabled:true});await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');assert.equal(starts.length,n);await request('automation',{enabled:false})
  check('A paused account with stale credential_invalid text and Ready runtime credentials never triggers automatic login')
 }
 {
  const a=add('auto_cancel_during_scan');a.errorReason='credential_expired';a.runtimeCredentialState='expired'
  await request('automation',{enabled:true});const n=starts.length
  directoryGate=Promise.withResolvers()
  const reconcile=call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');await sleep(80)
  const off=await request('automation',{enabled:false});assert.equal(off.status,200);assert.equal(off.value.automation.enabled,false)
  assert.equal((await request('jobs')).value.automation.enabled,false)
  directoryGate.resolve();directoryGate=null;await reconcile
  assert.equal(starts.length,n,'A scan finishing after disable must not send login credentials')
  assert.equal((await request('jobs')).value.automation.enabled,false,'Stale queue saves must not reenable automation')
  await stop();await start();assert.equal((await request('jobs')).value.automation.enabled,false)
  check('Disabling stays responsive during a blocked scan, fences late work, persists across restart and cannot be overwritten by queue saves')
 }
 {
  const a=add('legacy');await submit([a.id]);delete job(a.id).logoutOthers;delete job(a.id).cleanupStarted
  const r=refreshes.length;assert.equal((await finish(a.id)).status,'success');assert.equal(refreshes.length,r);assert.equal(a.enabled,true)
  check('Legacy queued records retain native authorization without silently gaining device logout')
 }
 await stop();console.log(`Verified ${passed} unified native protocol scenarios`)
} finally {if(child?.exitCode===null)child.kill()}
