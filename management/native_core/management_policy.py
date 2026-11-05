"""Native-registry checks around the existing supported account API contract."""
import copy,hashlib,json,urllib.parse
from legacy_policy import AccountPolicy,PolicyError,candidates,identity,oauth_candidate

DEFAULT_WS_BUDGET=128

class NativePolicy(AccountPolicy):
    def update_proxy_budget(self,body):
        required={'id','revision','name','maxWebsocketConnections'}
        if set(body)!=required or not isinstance(body['id'],str) or not isinstance(body['revision'],int) or isinstance(body['maxWebsocketConnections'],bool) or not isinstance(body['maxWebsocketConnections'],int) or not 0<=body['maxWebsocketConnections']<=4294967295:raise PolicyError('Only a saved native proxy WS budget may be changed',422)
        rows=[];expected=None
        for page in range(1,1001):
            result=self.backend('/api/admin/proxies?page='+str(page)+'&pageSize=100');items=result['items'];rows.extend(items)
            count=(result.get('page') or {}).get('total')
            if expected is not None and count is not None and count!=expected:raise PolicyError('Proxy directory changed during pagination',409)
            if count is not None:expected=count
            if len(items)<100:break
        if len({r['id'] for r in rows})!=len(rows) or (expected is not None and len(rows)!=expected):raise PolicyError('Incomplete proxy directory',503)
        matches=[r for r in rows if r['id']==body['id']]
        if len(matches)!=1:raise PolicyError('Saved native proxy not found',404)
        before=matches[0];entry=self.allocator.lookup(before['endpoint'])
        if not entry or not self.allocator.owner(entry) or before['enabled'] is not True or body['name']!=before['name']:raise PolicyError('Fixed native proxy identity must remain unchanged and enabled',409)
        members=self.backend('/api/admin/proxies/accounts?proxyId='+urllib.parse.quote(body['id'],safe='')+'&page=1&pageSize=100')
        if len(members['items'])!=1 or members['items'][0]['id']!=self.allocator.owner(entry) or (members.get('page') or {}).get('total')!=1:raise PolicyError('Only an exact one-account native binding may change budget',409)
        account=self.detail(self.allocator.owner(entry));verified=self.entry_for(account)
        if self.allocator.url(verified)!=self.allocator.url(entry):raise PolicyError('Native proxy authentication does not match registered account',409)
        result=self.backend('/api/admin/proxies/update',body)
        # 更新用例本身校验 revision；只读回本页，不重新提交可能已成功的写入
        for page in range(1,1001):
            items=self.backend('/api/admin/proxies?page='+str(page)+'&pageSize=100')['items'];live=next((r for r in items if r['id']==body['id']),None)
            if live:
                if any(live.get(k)!=before.get(k) for k in ['id','name','enabled','endpoint','hasAuthentication']) or live.get('maxWebsocketConnections')!=body['maxWebsocketConnections']:raise PolicyError('Native proxy WS budget readback mismatch',502)
                return result
            if len(items)<100:break
        raise PolicyError('Updated native proxy absent from readback',502)

    def ensure_new_proxy_budget(self,rid):
        if DEFAULT_WS_BUDGET == 0:return
        account=self.detail(rid);endpoint=(account.get('outboundProxyEndpoint') or '').rstrip('/')
        if not endpoint:raise PolicyError('Imported account has no saved proxy; account retained paused',502)
        rows=[];expected=None
        for page in range(1,1001):
            result=self.backend('/api/admin/proxies?page='+str(page)+'&pageSize=100');items=result['items'];rows.extend(items)
            total=(result.get('page') or {}).get('total')
            if expected is not None and total is not None and total!=expected:raise PolicyError('Proxy directory changed during pagination',409)
            if total is not None:expected=total
            if len(items)<100:break
        if len({r['id'] for r in rows})!=len(rows) or (expected is not None and len(rows)!=expected):raise PolicyError('Incomplete proxy directory',503)
        matches=[r for r in rows if r['endpoint'].rstrip('/')==endpoint and r.get('accountCount')==1]
        if len(matches)!=1:raise PolicyError('Saved fixed proxy missing; account retained paused',502)
        proxy=matches[0]
        # 只给新建代理的零值设置默认预算，保留人工预算与重新授权状态。
        if proxy.get('maxWebsocketConnections',0)!=0:return
        self.update_proxy_budget({'id':proxy['id'],'revision':proxy['revision'],'name':proxy['name'],'maxWebsocketConnections':DEFAULT_WS_BUDGET})

    def inventory(self):
        rows=[];seen=set()
        for page in range(1,1001):
            items=self.backend('/api/admin/accounts?page='+str(page)+'&pageSize=100')['items']
            for a in items:
                if a['id'] in seen:raise PolicyError('Repeated account page; import refused',503)
                seen.add(a['id']);rows.append(a)
            if len(items)<100:return rows
        raise PolicyError('Incomplete account directory; import refused',503)

    def match(self,row,provider='openai',existing=None):
        existing=self.inventory() if existing is None else existing;ident=identity(row);email=str(row.get('email') or '').strip().lower()
        same=[a for a in existing if a.get('provider')==provider and ident and (a.get('userId'),a.get('accountId'))==ident]
        mail=[a for a in existing if a.get('provider')==provider and email and str(a.get('email') or '').strip().lower()==email]
        if len(same)>1 or len(mail)>1:raise PolicyError('Ambiguous existing account; choose the exact record',409)
        if same and mail and same[0]['id']!=mail[0]['id']:raise PolicyError('Account identity and email conflict',409)
        match=(same or mail or [None])[0]
        if match and ident and (match.get('userId'),match.get('accountId'))!=ident:raise PolicyError('Email belongs to a different user or workspace',409)
        if same and email and str(same[0].get('email') or '').lower()!=email:raise PolicyError('Account identity email mismatch',409)
        return match

    def preflight_imports(self,items):
        existing=self.inventory();seen=set()
        for item in items:
            if item.get('provider')!='openai':raise PolicyError('Only OpenAI imports are supported by this native registry',422)
            for row in candidates(item['data']):
                if not oauth_candidate(row):raise PolicyError('Only OAuth accounts are supported by this native registry',422)
                if self.match(row,existing=existing):raise PolicyError('Account already exists; current credentials and fixed exit were retained. Edit its notes on the existing record.',409)
                ident=identity(row);email=str(row.get('email') or '').lower();keys=[]
                if ident:keys.append(('identity',ident))
                if email:keys.append(('email',email))
                if not keys:raise PolicyError('Import requires account identity or expected email',422)
                if any(k in seen for k in keys):raise PolicyError('Duplicate account in submitted import batch',422)
                seen.update(keys)

    def import_item(self,body,reservation_prefix):
        self.preflight_imports([body]);return super().import_item(body,reservation_prefix)

    def import_sync(self,body):
        self.preflight_imports([body]);return super().import_sync(body)

    def entry_for(self,a,verify=False):
        e=super().entry_for(a,False)
        if self.allocator.owner(e)!=a['id']:raise PolicyError('Native exit registry does not match this account',409)
        if verify:self.allocator.verify(e)
        return e

    def update(self,path,body):
        batch=path.endswith('/batch-update');ids=body.get('accountIds') if batch else [body.get('accountId')]
        if not isinstance(ids,list) or not ids or any(not isinstance(r,str) or not r for r in ids) or len(set(ids))!=len(ids):raise PolicyError('Account selection invalid',400)
        rows=[self.detail(rid) for rid in ids];prepared=copy.deepcopy(body)
        change_proxy='outboundProxyUrl' in body or 'outboundProxyId' in body
        for a in rows:
            if a.get('authenticationKind')!='oauth':continue
            e=self.entry_for(a)
            if change_proxy:
                wanted=body.get('outboundProxyUrl')
                if body.get('outboundProxyId') or (wanted and self.allocator.lookup(wanted)!=e):raise PolicyError('Existing account fixed exit cannot be changed or shared',409)
                if len(rows)!=1:raise PolicyError('Proxy fields require one account',422)
                prepared.pop('outboundProxyId',None);prepared['outboundProxyUrl']=self.allocator.url(e)
            sensitive=(body.get('enabled') is False) or any(k in body for k in ['connection','credentials','data','accessToken','refreshToken'])
            if sensitive and int((a.get('capacity') or {}).get('usedSlots',0))>0:raise PolicyError('Account has in-flight requests; retry after natural completion',409)
        result=self.backend(path,prepared)
        for a in rows:
            live=self.detail(a['id'])
            if a.get('outboundProxyEndpoint')!=live.get('outboundProxyEndpoint'):raise PolicyError('Account exit readback mismatch',502)
            for key in ['enabled','concurrencyLimit','weight','modelAccess','notes']:
                if key not in body and a.get(key)!=live.get(key):raise PolicyError('Unrequested account setting changed',502)
        return result

    def start_oauth(self,body):
        rid=body.get('accountId')
        if rid and int((self.detail(rid).get('capacity') or {}).get('usedSlots',0))>0:raise PolicyError('Account has in-flight requests; retry later',409)
        return super().start_oauth(body)

    def complete_oauth(self,body):
        entry,rid=self.allocator.get_flow(body['flowId'])
        if rid:
            a=self.detail(rid)
            if int((a.get('capacity') or {}).get('usedSlots',0))>0:raise PolicyError('Account has in-flight requests; retry later',409)
        return super().complete_oauth(body)
