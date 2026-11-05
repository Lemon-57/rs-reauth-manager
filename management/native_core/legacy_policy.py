"""账号管理写入时分配并验证固定 IPv6，不扫描正常账号或处理推理流量"""
import base64,copy,hashlib,http.client,ipaddress,json,os,ssl,threading,time,urllib.parse,uuid

class PolicyError(Exception):
 def __init__(self,message,status=409):super().__init__(message);self.status=status

def token_fields(value):
 found={};pending=[value]
 while pending:
  item=pending.pop()
  if isinstance(item,dict):
   for k,v in item.items():
    if k in ['accessToken','access_token','idToken','id_token','refreshToken','refresh_token'] and isinstance(v,str):found[k]=v
    elif isinstance(v,(dict,list)):pending.append(v)
  elif isinstance(item,list):pending.extend(item)
 return found

def identity(value):
 fields=token_fields(value);claims={}
 for name in ['access_token','accessToken','id_token','idToken']:
  token=fields.get(name)
  if not token:continue
  try:
   p=token.split('.')[1];auth=json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))).get('https://api.openai.com/auth') or {}
   claims.update({k:v for k,v in auth.items() if v is not None})
  except (ValueError,IndexError):pass
 user=claims.get('chatgpt_user_id') or claims.get('user_id')
 return (user,claims.get('chatgpt_account_id')) if user else None

def candidates(doc):
 if not isinstance(doc,dict):raise PolicyError('导入文档必须是对象',400)
 root=doc.get('data') if isinstance(doc.get('data'),dict) and 'accounts' in doc['data'] else doc
 items=root.get('accounts',[root]);
 if not isinstance(items,list) or not items or len(items)>500:raise PolicyError('导入账号数量无效',400)
 return items

def oauth_candidate(item):
 if not isinstance(item,dict):return False
 if str(item.get('platform',item.get('provider','openai'))).lower() not in ['openai','codex']:return False
 credentials=item.get('credentials') or item
 return not (item.get('authentication_kind')=='api_key' or item.get('type') in ['apikey','api_key'] or credentials.get('api_key') or item.get('apiKey'))

class AccountPolicy:
 def __init__(self,backend,allocator,plan_reconciler=None):self.backend=backend;self.allocator=allocator;self.lock=threading.RLock();self.plan_reconciler=plan_reconciler
 def inventory(self):
  result=[];page=1
  while True:
   items=self.backend('/api/admin/accounts?page='+str(page)+'&pageSize=100')['items'];result+=items
   if len(items)<100:return [a for a in result if a.get('provider')=='openai' or a.get('authenticationKind')=='oauth']
   page+=1
 def detail(self,rid):return self.backend('/api/admin/accounts/detail?accountId='+urllib.parse.quote(rid,safe=''))['account']
 def entry_for(self,a,verify=False):
  doc=self.backend('/api/admin/accounts/export?accountIds='+a['id']+'&confirm=export_sensitive_accounts')['documents'][0]['document']['accounts'][0]
  url=doc.get('outboundProxyUrl')
  if url:
   entry=self.allocator.lookup(url)
   if entry is None:raise PolicyError('账号绑定的代理不属于独立 IPv6 池，请先改为自动分配')
  else:entry=self.allocator.allocate('account:'+a['id'])
  if verify:self.allocator.verify(entry)
  return entry
 def import_item(self,body,reservation_prefix):
  if body.get('provider')!='openai':return body,[]
  result=copy.deepcopy(body);result.pop('outboundProxyId',None);existing=self.inventory();identities={(a.get('userId'),a.get('accountId')):a for a in existing};used=set();allocations=[]
  for index,item in enumerate(candidates(result['data'])):
   if not oauth_candidate(item):continue
   ident=identity(item);match=identities.get(ident) if ident else None
   if ident is None:
    email=str(item.get('email') or '').strip().lower();fields=token_fields(item);refresh=fields.get('refreshToken') or fields.get('refresh_token')
    if not email or '@' not in email or not refresh:raise PolicyError('RT import requires the expected account email',422)
    by_email=[a for a in existing if str(a.get('email') or '').lower()==email]
    if len(by_email)>1:raise PolicyError('Email matches multiple accounts; select an exact account',409)
    original=by_email[0] if by_email else None
    if original and (original.get('capacity') or {}).get('usedSlots') != 0:raise PolicyError('Account must be idle before RT import',409)
    entry=self.entry_for(original) if original else self.allocator.allocate('email:'+hashlib.sha256(email.encode()).hexdigest())
    self.allocator.verify(entry)
    tokens=self.allocator.exchange_refresh(entry,refresh)
    claims=[]
    for name in ['id_token','access_token']:
     if tokens.get(name):
      try:
       part=tokens[name].split('.')[1];claims.append(json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4))))
      except (ValueError,IndexError):raise PolicyError('RT returned invalid identity token',422) from None
    emails={str(c.get('email') or (c.get('https://api.openai.com/profile') or {}).get('email') or '').lower() for c in claims};emails.discard('')
    if emails!={email}:raise PolicyError('RT identity email does not match expected email; not imported',409)
    item.update({'accessToken':tokens['access_token'],'refreshToken':tokens['refresh_token']})
    if tokens.get('id_token'):item['idToken']=tokens['id_token']
    item.pop('refresh_token',None)
    ident=identity(item);match=identities.get(ident) if ident else None
    if ident is None or (match and (not original or match['id']!=original['id'])) or (original and (not match or match['id']!=original['id'])):raise PolicyError('RT identity conflicts with the selected email; not imported',409)
   else:
    entry=self.entry_for(match) if match else self.allocator.allocate('identity:'+hashlib.sha256(json.dumps(ident).encode()).hexdigest())
   if ident in used:raise PolicyError('同一次导入包含重复账号身份',422)
   used.add(ident)
   self.allocator.verify(entry)
   for name in ['outbound_proxy_url','proxy_key']:item.pop(name,None)
   item['outboundProxyUrl']=self.allocator.url(entry);allocations.append((entry,ident))
  if not allocations:return result,[]
  settings=result.get('settings')
  if settings is None:
   # 再导入沿用原暂停、备注、分组；新文档备注随账号迁入
   if len(allocations)>1:raise PolicyError('多个账号请通过后台批量导入，每条独立指定设置以保留备注',422)
   row=next(item for item in candidates(result['data']) if oauth_candidate(item));match=identities.get(identity(row))
   settings={'enabled':match['enabled'] if match else True,'concurrencyLimit':match['concurrencyLimit'] if match else None,'weight':match['weight'] if match else 1,'groupIds':[g['id'] for g in match['groups']] if match else [],'notes':row.get('notes',match.get('notes') if match else None)};result['settings']=settings
  # 导入是凭据操作，再导入现有账号不得因为 UI 默认勾选而解除暂停
  if len(allocations)==1:
   row=next(item for item in candidates(result['data']) if oauth_candidate(item));match=identities.get(identity(row))
   if settings.get('notes') is None and 'notes' in row:settings['notes']=row['notes']
   if match:
    settings['enabled']=match['enabled']
    if settings.get('notes') is None and 'notes' not in row:settings['notes']=match.get('notes')
  desired=settings['enabled'];settings['enabled']=False
  return result,[(entry,ident,desired) for entry,ident in allocations]
 def ensure_new_proxy_budget(self,rid):
  pass
 def finish(self,account_ids,allocations):
  matches={ident:(entry,desired) for entry,ident,desired in allocations}
  for rid in account_ids:
   a=self.detail(rid)
   if a.get('authenticationKind')!='oauth':continue
   match=matches.get((a.get('userId'),a.get('accountId')))
   if not match:raise PolicyError('导入结果身份与代理预分配不一致，账号保持暂停',502)
   entry,desired=match
   if time.time()-entry.get('validated_at',0)>300:self.allocator.verify(entry)
   if (a.get('outboundProxyEndpoint') or '').rstrip('/')!=self.allocator.endpoint(entry).rstrip('/'):raise PolicyError('导入代理回读不一致，账号保持暂停',502)
   self.allocator.bind(entry,rid)
   self.ensure_new_proxy_budget(rid)
   self.backend('/api/admin/accounts/batch-update',{'accountIds':[rid],'enabled':desired})
 def import_sync(self,body):
  if body.get('provider')=='openai' and len(candidates(body['data']))>1:
   ids=[];revision=0
   for row in candidates(body['data']):
    item=copy.deepcopy(body);item['data']=row
    if row.get('notes') is not None:
     item.setdefault('settings',{'enabled':True,'concurrencyLimit':None,'weight':1,'groupIds':[]})['notes']=row['notes']
    result=self.import_sync(item);ids+=result['accountIds'];revision=result['configRevision']
   return {'accountIds':ids,'importedCount':len(ids),'configRevision':revision}
  prepared,allocations=self.import_item(body,'import:'+uuid.uuid4().hex)
  result=self.backend('/api/admin/accounts/import',prepared)
  if allocations:self.finish(result['accountIds'],allocations)
  return result
 def update(self,path,body):
  batch=path.endswith('/batch-update');ids=body.get('accountIds') if batch else [body.get('accountId')]
  if not isinstance(ids,list) or not ids or any(not isinstance(rid,str) for rid in ids):raise PolicyError('账号 ID 无效',400)
  accounts=[self.detail(rid) for rid in ids]
  if batch and len(ids)>1:
   if 'outboundProxyUrl' not in body and 'outboundProxyId' not in body and all(a.get('outboundProxyEndpoint') or a.get('authenticationKind')!='oauth' for a in accounts):
    for a in accounts:
     if a.get('authenticationKind')=='oauth':self.entry_for(a)
    return self.backend(path,body)
   # 多账号不得通过批量编辑绑定同一个出口
   results=[]
   for a in accounts:
    one=copy.deepcopy(body);one['accountIds']=[a['id']];results.append(self.update(path,one))
   return {'accountIds':ids,'configRevision':max(r['configRevision'] for r in results)}
  prepared=copy.deepcopy(body)
  for a in accounts:
   if a.get('authenticationKind')!='oauth':continue
   changed='outboundProxyUrl' in body or 'outboundProxyId' in body
   if changed:
    selected=body.get('outboundProxyUrl');saved=body.get('outboundProxyId')
    current=self.entry_for(a) if a.get('outboundProxyEndpoint') else None
    if selected and selected!=a.get('outboundProxyEndpoint'):
     entry=self.allocator.lookup(selected)
     if entry is None:raise PolicyError('OAuth 账号只能选择独立 IPv6 池代理，留空将自动分配',422)
     owner=self.allocator.owner(entry)
     if owner and owner!=a['id']:raise PolicyError('此代理已属于其他账号，不能共享',409)
    elif saved:raise PolicyError('OAuth 账号不能绑定共享代理，请使用自动分配',422)
    elif selected:entry=current
    else:entry=self.allocator.allocate('account:'+a['id'])
   else:
    entry=self.entry_for(a) if a.get('outboundProxyEndpoint') else self.allocator.allocate('account:'+a['id'])
   if changed or not a.get('outboundProxyEndpoint'):self.allocator.verify(entry)
   prepared.pop('outboundProxyId',None);prepared['outboundProxyUrl']=self.allocator.url(entry)
   # 正常编辑只复用固定绑定，不进行周期探测
   self.allocator.bind(entry,a['id'])
  result=self.backend(path,prepared)
  for a in accounts:
   if a.get('authenticationKind')=='oauth':
    live=self.detail(a['id']);assert live['outboundProxyEndpoint'].rstrip('/')==self.allocator.endpoint(self.allocator.lookup(prepared['outboundProxyUrl'])).rstrip('/')
  return result
 def start_oauth(self,body):
  if body.get('provider')!='openai':return self.backend('/api/admin/accounts/oauth/start',body)
  prepared=copy.deepcopy(body);prepared.pop('outboundProxyId',None)
  rid=body.get('accountId');entry=self.entry_for(self.detail(rid)) if rid else self.allocator.allocate('oauth:'+uuid.uuid4().hex)
  self.allocator.verify(entry);prepared['outboundProxyUrl']=self.allocator.url(entry)
  result=self.backend('/api/admin/accounts/oauth/start',prepared);self.allocator.flow(result['flowId'],entry,rid);return result
 def complete_oauth(self,body):
  if body.get('provider')!='openai':return self.backend('/api/admin/accounts/oauth/complete',body)
  entry,rid=self.allocator.get_flow(body['flowId'])
  original=None
  if rid:
   a=self.detail(rid);original=a
   if (a.get('outboundProxyEndpoint') or '').rstrip('/')!=self.allocator.endpoint(entry).rstrip('/'):raise PolicyError('授权期间账号代理已改变，请重新开始授权',409)
  self.allocator.verify(entry);prepared=copy.deepcopy(body);settings=prepared.get('settings');desired=settings.get('enabled',True) if settings else (self.detail(rid)['enabled'] if rid else True)
  if original:
   desired=original['enabled'];settings=None
   # 重登只替换凭据；启停、备注和分组的编辑走独立设置入口
   prepared.pop('settings',None)
   self.backend('/api/admin/accounts/batch-update',{'accountIds':[rid],'enabled':False})
  if not settings and not original:
   prepared['settings']={'enabled':False,'concurrencyLimit':original['concurrencyLimit'] if original else None,'weight':original['weight'] if original else 1,'groupIds':[g['id'] for g in original['groups']] if original else [],'notes':original.get('notes') if original else None}
   if original:prepared['settings']['modelAccess']=original['modelAccess']
  elif settings:settings['enabled']=False
  result=self.backend('/api/admin/accounts/oauth/complete',prepared);rid=result['accountId'];live=self.detail(rid)
  if live['outboundProxyEndpoint'].rstrip('/')!=self.allocator.endpoint(entry).rstrip('/'):raise PolicyError('授权结果代理回读不一致',502)
  self.allocator.bind(entry,rid)
  if not original:self.ensure_new_proxy_budget(rid)
  if original:
   # Read the new credential, not the potentially stale quota-derived label.
   from credential_plan_sync import reconcile_reauthorized_plan,PlanSyncError
   reconcile=self.plan_reconciler or reconcile_reauthorized_plan
   try:verified=reconcile(self.backend,rid)
   except PlanSyncError:raise PolicyError('新凭据套餐与标签尚未一致，账号保持暂停，请重试或联系管理员',503) from None
   live=self.detail(rid)
   # Keep the pre-existing scheduling state, including Free accounts.
  if original and (live.get('userId')!=original.get('userId') or live.get('accountId')!=original.get('accountId')):raise PolicyError('OAuth user/workspace changed; account retained paused',409)
  if prepared.get('settings') or original:self.backend('/api/admin/accounts/batch-update',{'accountIds':[rid],'enabled':desired})
  return result
