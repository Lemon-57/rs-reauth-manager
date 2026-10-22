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
const starts=[],completes=[],refreshes=[],metadataSaves=[],controls=[],deleted=[],groupMoves=[]
let groupMode='normal'
const importFlows=new Map(), providedImports=[]
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
  for(const secret of ['fixture-password','fixture:pass','secret-code','access_token','refresh_token','id_token','fixture-cookie','fixture-admin-key','fixture-provided-rt','fixture-current-session','59859b73-b63b-45f4-86f9-e728a9512905'])assert.ok(!raw.includes(secret),'Private material must not enter job state')
  const version=(old?.version||0)+1;records.set(data.key,{value:structuredClone(data.value),version,schema_version:1});return result(meta.id,{version})
 }
 if(meta.method==='host.http.do_stream') {
  const url=new URL(meta.params.url);assert.equal(url.origin,'http://127.0.0.1:18139')
  assert.ok(meta.params.headers.some(([name,value])=>name==='x-api-key'&&Buffer.from(value).toString()==='fixture-admin-key'))
  let reply,protectedStatus=200
  if(url.pathname==='/_management/onboarding/start') {
   const id=data.email.split('@')[0],flowId='import_'+id
   importFlows.set(flowId,id);starts.push({protected:true,email:data.email});reply={flowId,authorizationUrl:nativeAuthorization,outboundProxyUrl:'http://fixture:pass@127.0.0.1:21001'}
  } else if(url.pathname==='/api/admin/accounts/import') {
   const id=data.data.email.split('@')[0];providedImports.push(id);assert.equal(data.settings.notes.split('----').length,3);assert.equal(data.settings.enabled,false)
   assert.equal(data.data.refreshToken,'fixture-provided-rt')
   const a=add(id);Object.assign(a,{enabled:false,status:'disabled',notes:data.settings.notes,groups:[],planType:(id.startsWith('up_')||id.startsWith('unbound_'))?'free':id.startsWith('rt_business')?'business':'team'})
   credentials.set(id,credential(a));
   if(id.startsWith('unbound_')) {
    a.accountId=null;const c=credentials.get(id);c.facts.upstream_account_id=null
    for(const key of ['access_token','id_token']){const p=JSON.parse(Buffer.from(c.facts.material[key].split('.')[1],'base64url'));p[AUTH]={user_id:a.userId};c.facts.material[key]=jwt(p)}
   }
   reply={accountIds:[id]};if(id==='rt_lost_batch')protectedStatus=503
  } else if(url.pathname==='/api/admin/accounts/batch-update') {
   const a=accounts.find(a=>a.id===data.accountIds[0]);assert.equal(a.capacity.usedSlots,0);a.enabled=data.enabled;a.status=data.enabled?'normal':'disabled';reply={}
  } else if(url.pathname==='/api/admin/accounts/oauth/complete') {
   const id=importFlows.get(data.flowId);assert.ok(id);const a=add(id)
   Object.assign(a,{enabled:false,status:'disabled',notes:data.settings.notes,groups:[],concurrencyLimit:null,weight:1,modelAccess:data.settings.modelAccess})
   if(id==='new_import_free_ui')a.planType='free'
   credentials.set(a.id,credential(a));completes.push({protected:true,flowId:data.flowId});reply={accountId:id}
  } else throw Error('Unexpected protected route '+url.pathname)
  const stream=randomUUID();handles.set(stream,Buffer.from(JSON.stringify({code:200,data:reply})))
  return result(meta.id,{status:protectedStatus,http_version:'HTTP/1.1',headers:[],stream,trailers:[]})
 }
 if(meta.method==='host.http.stream_read'){const v=handles.get(meta.params.stream);if(v){handles.delete(meta.params.stream);return result(meta.id,{eof:false,trailers:[]},v)}return result(meta.id,{eof:true,trailers:[]})}
 if(meta.method==='host.http.stream_close')return result(meta.id)
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
  }else if(url.pathname==='/api/admin/account-groups/options'){
   let items=groupMode==='missing'?[]:[{id:'gpt-pro',name:'GPT Pro',enabled:groupMode!=='disabled'}]
   if(groupMode==='duplicate')items.push({id:'duplicate-pro',name:'GPT Pro',enabled:true})
   dataReply={items,page:{total:items.length}}
  }else if(url.pathname==='/api/admin/accounts'){if(directoryGate)await directoryGate.promise;dataReply={items:accounts}}
  else if(url.pathname==='/api/admin/accounts/detail')dataReply={account:accounts.find(a=>a.id===url.searchParams.get('accountId')),credentialConfiguration:{transport:'http'}}
  else if(url.pathname==='/api/admin/accounts/export') {
   assert.equal(url.searchParams.get('confirm'),'export_sensitive_accounts');const id=url.searchParams.get('accountIds');assert.ok(!id.includes(','))
   dataReply={documents:[{provider:'openai',document:{accounts:[{id,outboundProxyUrl:'http://fixture:pass@127.0.0.1:21001'+(id.startsWith('new_')?'/':'')}]}}]}
  } else if(url.pathname==='/api/admin/accounts/oauth/start') {
   assert.deepEqual(Object.keys(data).sort(),['accountId','name','provider']);starts.push(structuredClone(data));dataReply={flowId:`flow_${data.accountId}`,authorizationUrl:nativeAuthorization};status=201
  } else if(url.pathname==='/api/admin/accounts/batch-update'&&data.groupIds) {
   assert.deepEqual(Object.keys(data).sort(),['accountIds','groupIds']);assert.equal(data.accountIds.length,1);assert.deepEqual(data.groupIds,['gpt-pro'])
   const a=accounts.find(a=>a.id===data.accountIds[0]);assert.equal(a.enabled,false);assert.equal(a.capacity.usedSlots,0)
   a.groups=[{id:'gpt-pro',name:'GPT Pro',enabled:true}];groupMoves.push(a.id);dataReply={}
   if(a.id==='group_lost'){status=503;code=50301}
   if(a.id==='group_revision_race')revisions.set(a.id,revisions.get(a.id)+1)
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
    if(a.id.startsWith('fb_')||a.id.startsWith('auto_fb_')||a.id==='free_fallback_no_candidates'){workspace='personal-workspace';plan='free'}
    if(a.id.startsWith('up_')||a.id.startsWith('auto_up_')){workspace='team-workspace';plan='team'}
    if(a.id.startsWith('unbound_')){workspace=a.id.includes('personal')?'personal-workspace':'team-workspace';plan=a.id.includes('personal')?'free':'team'}
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
    if (meta.type === 'ready') { assert.equal(meta.protocol_version, 5); ready.resolve() }
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
  send({ type: 'hello', handshake: { protocol_version: 5, artifact_sha256: 'a'.repeat(64), plugin_id: 'personal.reauth-manager', instance_id: 'test_instance', generation: 1, incarnation: 'fixture', configuration: {protectedManagementUrl:'http://127.0.0.1:18139'}, contributes: { management: { id: 'personal.reauth-manager.management', version: 2, stages: ['management'] }, maintenance: { id: 'personal.reauth-manager.maintenance', version: 1, stages: ['maintenance'] } } } })
  await ready.promise
}
async function stop() { const exited = new Promise(resolve => child.once('exit', resolve)); send({ type: 'shutdown' }); child.stdin.end(); await exited }
async function call(method, params = {}, payload = Buffer.alloc(0), stage = 'management') {
  const id = sequence += 2, w = Promise.withResolvers(); pending.set(id, w)
  send({ type: 'call', id, method, params, context: { call_id: id, instance_id: 'test_instance', generation: 1, incarnation: 'fixture', stage, timeout_ms: 60000, resource_stream: false, resource_scope_id: `scope_${id}` } }, payload)
  return Promise.race([w.promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`Timeout ${method}`)), 10000).unref())])
}
async function request(path, data) { const r = await call('management.handle', { method: data === undefined ? 'GET' : 'POST', path: `api/${path}`, query: '', content_type: data === undefined ? null : 'application/json', headers: [{name:'x-api-key',value:Array.from(Buffer.from('fixture-admin-key'))}] }, data === undefined ? Buffer.alloc(0) : data); return { status: r.result.status, value: JSON.parse(r.payload.toString()) } }
const submit = (ids, requestId = randomUUID()) => request('submit', { accountIds: ids, requestId })
const tick = () => request('tick', {})
const job = id => records.get('queue').value.jobs.filter(j => j.accountId === id).at(-1)
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
async function finish(id) { for (let i = 0; i < 60; i++) { await tick(); if (!['queued', 'running'].includes(job(id).status)) return job(id); await sleep(60) } throw new Error('Job did not finish: ' + JSON.stringify(job(id))) }
let passed=0
const check=name=>{passed++;console.log('PASS '+name)}
try {
 await start()
 const reg=JSON.parse((await call('management.register',{},Buffer.alloc(0),'registration')).payload.toString());assert.equal(reg.routes.length,12)
 assert.deepEqual((await request('runtime-check',{})).value,{ready:true});assert.equal(starts.length,0);check('Runtime preflight never starts authorization')
 for(const [id,hasRT] of [['new_import_ui',false],['new_import_free_ui',false],['rt_team_ui',true],['rt_business_ui',true],['up_import_ui',true]]) {
  const requestId=randomUUID(),n=starts.length,c=completes.length
  const body={requestId,line:id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ'+(hasRT?'----fixture-provided-rt':''),groupIds:[]}
  const response=await request('import-line',body);assert.equal(response.status,200,JSON.stringify(response.value))
  let done=records.get('queue').value.jobs.find(j=>j.requestId===requestId+':import')
  for(let i=0;i<80&&['queued','running'].includes(done.status);i++){await tick();await sleep(60);done=records.get('queue').value.jobs.find(j=>j.requestId===requestId+':import')}
  assert.equal(done.status,'success',done.message);assert.equal(done.accountId,id)
  assert.equal(accounts.find(a=>a.id===id).enabled,id!=='new_import_free_ui');if(id!=='new_import_free_ui')assert.deepEqual(accounts.find(a=>a.id===id).groups.map(g=>g.id),['gpt-pro'])
  if(id.startsWith('rt_')){assert.equal(starts.length,n);assert.equal(completes.length,c);assert.equal(done.cleanupStarted,false)}
  else {assert.equal(starts.length,n+1);assert.equal(completes.length,c+1);assert.equal(done.cleanupStarted,false)}
  if(id==='up_import_ui'){assert.equal(accounts.find(a=>a.id===id).planType,'team');assert.equal(accounts.filter(a=>a.email===id+'@example.com').length,1)}
  const before=[starts.length,completes.length,accounts.length]
  assert.equal((await request('import-line',body)).status,200);assert.deepEqual([starts.length,completes.length,accounts.length],before)
  assert.equal((await request('import-line',{...body,requestId:randomUUID(),line:body.line.toUpperCase()})).status,400)
  assert.deepEqual([starts.length,completes.length,accounts.length],before)
  accounts.splice(accounts.findIndex(a=>a.id===id),1)
  check(id+': format routing, native persistence, same-account Free upgrade, no duplicate allocation or replay')
 }

 {
  const ids=['new_multi_three','password_failure','rt_multi_team','up_multi_free','rt_lost_batch']
  const requestId=randomUUID(), beforeImports=providedImports.length
  const line=ids.map((id,i)=>id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ'+(i>=2?'----fixture-provided-rt':'')).join('\r\n')
  const response=await request('import-line',{requestId,line,groupIds:[]});assert.equal(response.status,200,JSON.stringify(response.value))
  const batch=()=>records.get('queue').value.jobs.filter(j=>j.requestId.startsWith(requestId+':'))
  assert.equal(batch().length,5);assert.ok(batch().every(j=>j.status==='queued'))
  assert.equal(providedImports.length,beforeImports,'Submitting a batch stores only intents, without executing RTs')
  for(let i=0;i<160&&batch().some(j=>['queued','running'].includes(j.status));i++){await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance');await sleep(40)}
  assert.deepEqual(batch().map(j=>j.status),['success','failed','success','success','review'])
  assert.deepEqual(batch().map(j=>j.importInfo.line),[1,2,3,4,5])
  assert.equal(accounts.filter(a=>a.id==='up_multi_free').length,1);assert.equal(accounts.find(a=>a.id==='up_multi_free').planType,'team')
  assert.equal(accounts.find(a=>a.id==='rt_lost_batch').enabled,false)
  assert.equal(providedImports.length,beforeImports+3)
  const after=[starts.length,completes.length,providedImports.length]
  await request('import-line',{requestId,line,groupIds:[]});await tick();assert.deepEqual([starts.length,completes.length,providedImports.length],after)
  for(const id of ids){const index=accounts.findIndex(a=>a.id===id);if(index>=0)accounts.splice(index,1)}
  check('A mixed multiline batch runs serially without browser ticks, continues after one failed row, upgrades the same Free account and never replays an uncertain RT')
 }
 {
  const row='not_submitted@example.com----fixture-password----GEZDGNBVGY3TQOJQ',before=[starts.length,completes.length,providedImports.length,records.get('queue').value.jobs.length]
  for(const line of [row+'\ninvalid-private-row',row+'\n'+row.toUpperCase()])assert.equal((await request('import-line',{requestId:randomUUID(),line,groupIds:[]})).status,400)
  assert.deepEqual([starts.length,completes.length,providedImports.length,records.get('queue').value.jobs.length],before)
  check('All rows are parsed and deduplicated before any job, allocation, login or RT exchange')
 }
 {
  const requestId=randomUUID(),ids=['rt_cancel_first','rt_cancel_second'],line=ids.map(id=>id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ----fixture-provided-rt').join('\n')
  assert.equal((await request('import-line',{requestId,line,groupIds:[]})).status,200)
  await request('cancel',{requestId:requestId+':import:1'})
  for(let i=0;i<4;i++)await tick()
  assert.ok(!providedImports.includes(ids[0]));assert.ok(providedImports.includes(ids[1]))
  assert.ok(!records.get('queue').value.automation.attempts[''])
  accounts.splice(accounts.findIndex(a=>a.id===ids[1]),1)
  check('Cancelling a queued row removes its in-memory credentials while the next row remains independently executable')
 }
 {
  const requestId=randomUUID(),ids=['rt_restart_first','rt_restart_second'],line=ids.map(id=>id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ----fixture-provided-rt').join('\n')
  assert.equal((await request('import-line',{requestId,line,groupIds:[]})).status,200)
  await stop();await start();await tick()
  const batch=records.get('queue').value.jobs.filter(j=>j.requestId.startsWith(requestId+':'))
  assert.ok(batch.every(j=>j.status==='interrupted'));assert.ok(ids.every(id=>!providedImports.includes(id)))
  await request('import-line',{requestId,line,groupIds:[]});await tick();assert.ok(ids.every(id=>!providedImports.includes(id)))
  check('A restarted plugin retains safe row results but never reconstructs secrets or replays a queued import batch')
 }
 for(const id of ['new_team','new_wrong_user','new_missing_rt']){
  const req={requestId:randomUUID(),email:id+'@example.com',notes:id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ',proxyUrl:'http://fixture:pass@127.0.0.1:21001',groupIds:['g1']}
  const n=starts.length,c=completes.length
  assert.equal((await request('import',req)).status,200)
  const duplicate=await request('import',req);assert.equal(duplicate.status,200);assert.equal(starts.length,n+1)
  let done
  for(let i=0;i<60;i++){await tick();done=records.get('queue').value.jobs.find(j=>j.requestId===req.requestId);if(!['queued','running'].includes(done.status))break;await sleep(60)}
  assert.equal(completes.length,c+1);assert.equal(accounts.find(a=>a.id===id).enabled,id==='new_team')
  if(id==='new_team'){assert.equal(done.status,'success',done.message);assert.equal(done.accountId,id);assert.equal(done.cleanupStarted,false);assert.ok(refreshes.includes(id))}
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


 for(const id of ['unbound_team','unbound_personal','unbound_wrong_user','unbound_wrong_subject','unbound_wrong_workspace','unbound_wrong_plan']) {
  const requestId=randomUUID(),n=starts.length,c=completes.length,im=providedImports.length
  await request('import-line',{requestId,line:id+'@example.com----fixture-password----GEZDGNBVGY3TQOJQ----fixture-provided-rt',groupIds:[]})
  let done
  for(let i=0;i<100;i++){await tick();done=records.get('queue').value.jobs.find(j=>j.requestId===requestId+':import');if(!['queued','running'].includes(done.status))break;await sleep(50)}
  assert.equal(providedImports.length,im+1);assert.equal(starts.length,n+1);assert.equal(completes.length,c+1)
  const a=accounts.find(a=>a.id===id);assert.equal(accounts.filter(a=>a.id===id).length,1)
  if(['unbound_team','unbound_personal'].includes(id)) {
   assert.equal(done.status,'success',done.message);assert.equal(a.enabled,id==='unbound_team');assert.equal(a.planType,id==='unbound_team'?'team':'free')
   assert.equal(a.accountId,id==='unbound_team'?'team-workspace':'personal-workspace');assert.equal(done.cleanupStarted,false)
   assert.deepEqual(a.groups.map(g=>g.id),id==='unbound_team'?['gpt-pro']:[])
  } else {assert.equal(done.status,'review',done.message);assert.equal(a.enabled,false)}
  const counts=[starts.length,completes.length,providedImports.length];await tick();assert.deepEqual([starts.length,completes.length,providedImports.length],counts)
  accounts.splice(accounts.findIndex(a=>a.id===id),1)
  check(id+': missing old workspace continues through the same bound native OAuth and validates new identity before grouping or enabling')
 }
 for(const id of ['unbound_existing_team','unbound_existing_personal']) {
  const a=add(id);a.enabled=false;a.planType='free';a.accountId=null;const c=credential(a)
  for(const key of ['access_token','id_token']){const p=JSON.parse(Buffer.from(c.facts.material[key].split('.')[1],'base64url'));p[AUTH]={user_id:a.userId};c.facts.material[key]=jwt(p)}
  credentials.set(id,c);const im=providedImports.length
  await submit([id]);const done=await finish(id);assert.equal(done.status,'success',done.message);assert.equal(a.enabled,!id.includes('personal'));assert.equal(providedImports.length,im)
  check(id+': previously interrupted imports resume on their existing account without replaying RT or allocating another proxy')
 }
 for(const id of ['good','disabled','free','legacy_principal','business']) {
  const a=add(id);if(id==='legacy_principal')credentials.get(id).facts.material.principal=null;if(id==='free'||id==='business'){a.planType=id;credentials.set(id,credential(a))}
  const before=structuredClone(a),n=completes.length,r=refreshes.length,m=metadataSaves.length
  await submit([id]);const done=await finish(id);assert.equal(done.status,'success',done.message)
  assert.equal(completes.length,n+1);assert.equal(refreshes.length,r+1);assert.equal(metadataSaves.length,m)
  assert.match(done.message,/原生 RT 刷新及保存已确认/);assert.equal(credentials.get(id).facts.material.refresh_token,'native-refreshed-private-rt')
  for(const k of ['enabled','notes','name','userId','accountId','planType','outboundProxyEndpoint','weight','concurrencyLimit','modelAccess'])assert.deepEqual(a[k],before[k])
  assert.deepEqual(a.groups,a.planType==='free'?before.groups:[{id:'gpt-pro',name:'GPT Pro',enabled:true}])
  check(`${id}: RS native completion and native refresh exclusively issue and save RT, configuration preserved`)
 }

 for(const mode of ['missing','disabled','duplicate']) {
  const id='group_'+mode,a=add(id),moves=groupMoves.length;groupMode=mode
  await submit([id]);const done=await finish(id);assert.equal(done.status,'review');assert.equal(a.enabled,false);assert.equal(groupMoves.length,moves);assert.match(done.message,/GPT Pro/)
  groupMode='normal';check(mode+': absent, disabled or ambiguous GPT Pro never reports authorization success or enables scheduling')
 }
 for(const id of ['group_lost','group_revision_race']) {
  const a=add(id),moves=groupMoves.length;await submit([id]);const done=await finish(id)
  assert.equal(done.status,'review');assert.equal(a.enabled,false);assert.equal(groupMoves.length,moves+1)
  await tick();assert.equal(groupMoves.length,moves+1)
  check(id+': unconfirmed grouping or changed credentials stay paused without replaying a write')
 }
 {
  const a=add('group_already');a.groups=[{id:'gpt-pro',name:'GPT Pro',enabled:true}];const moves=groupMoves.length
  await submit([a.id]);assert.equal((await finish(a.id)).status,'success');assert.equal(groupMoves.length,moves)
  check('An account already exclusively in GPT Pro is verified without a redundant grouping write')
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
 for(const id of ['up_stale_workspace','up_same_workspace','up_stale_wrong_user','up_stale_wrong_email','up_stale_wrong_subject','stale_workspace_regular']) {
  const a=add(id);a.planType='free'
  if(id==='up_same_workspace')a.accountId='team-workspace'
  const c=credential(a);c.facts.material.principal=null
  for(const key of ['id_token','access_token']) {
   const p=JSON.parse(Buffer.from(c.facts.material[key].split('.')[1],'base64url'))
   p.exp=1;p[AUTH].chatgpt_account_id='stale-personal-workspace'
   if(id==='up_stale_wrong_user')p[AUTH].chatgpt_user_id='another-user'
   if(id==='up_stale_wrong_email')p.email='another@example.com'
   if(id==='up_stale_wrong_subject')p.sub='different-old-subject'
   c.facts.material[key]=jwt(p)
  }
  credentials.set(id,c)
  const n=completes.length;await submit([id]);const done=await finish(id)
  if(['up_stale_workspace','up_same_workspace'].includes(id)) {
   assert.equal(done.status,'success',done.message);assert.equal(completes.length,n+1);assert.equal(a.planType,'team');assert.equal(a.enabled,true)
  } else {
   assert.equal(done.status,'review');assert.equal(completes.length,n+(id==='up_stale_wrong_subject'?1:0))
  }
  check(`${id}: Team membership tolerates stale old workspace while user, email and new authorization remain checked`)
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
 for(const id of ['refresh_503','refresh_wrong_user','resume_lost']) {
  const a=add(id),n=completes.length;await submit([id]);const done=await finish(id);assert.equal(done.status,'review',done.message);assert.equal(completes.length,n+1)
  if(id==='resume_lost'){assert.equal(a.enabled,true);assert.match(done.message,/恢复调度结果不确定/)}else assert.equal(a.enabled,false)
  const calls=[starts.length,completes.length,refreshes.length];await tick();await tick();assert.deepEqual([starts.length,completes.length,refreshes.length],calls)
  check(`${id}: native refresh and scheduling uncertainty are not replayed`)
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

 for(const [id,plan,enabled] of [['auto_up_enabled','free',true],['auto_up_paused','free',false],['auto_fb_team','team',true]]) {
  const a=add(id);Object.assign(a,{planType:plan,enabled,status:'error',errorReason:'credential_invalid',runtimeCredentialState:'invalid'});credentials.set(id,credential(a))
  const n=completes.length,r=refreshes.length
  await request('automation',{enabled:true});await call('plugin.reconcile',{},Buffer.alloc(0),'maintenance')
  assert.equal(job(id).automatic,true)
  const done=await finish(id);assert.equal(done.status,'success',done.message);assert.equal(completes.length,n+1);assert.equal(refreshes.length,r+1)
  assert.equal(a.planType,id.startsWith('auto_up_')?'team':'free');assert.equal(a.enabled,id==='auto_up_enabled');if(a.planType==='team')assert.deepEqual(a.groups.map(g=>g.id),['gpt-pro'])
  assert.equal(done.implementationVersion,'0.1.43');assert.equal(done.cleanupStarted,false);assert.equal(done.logoutOthers,false)
  await request('automation',{enabled:false})
  check(id+': native workspace validation and RT refresh preserve automatic pause policy without any device worker')
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
  const a=add('legacy');await submit([a.id]);job(a.id).logoutOthers=true;job(a.id).cleanupStarted=true
  const r=refreshes.length;assert.equal((await finish(a.id)).status,'success');assert.equal(refreshes.length,r+1);assert.equal(a.enabled,true)
  check('Legacy queued device flags are inert; native refresh remains required without any device action')
 }
 assert.ok(!records.get('queue').value.automation.attempts[''],'Import failures without an account ID never create an empty automatic-attempt identity')
 await stop();console.log(`Verified ${passed} unified native protocol scenarios`)
} finally {if(child?.exitCode===null)child.kill()}
