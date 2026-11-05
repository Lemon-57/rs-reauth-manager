"""Protected RS management on its actual LA host; no inference proxying."""
import argparse,copy,datetime,hashlib,http.client,json,os,signal,threading,time,urllib.parse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from legacy_policy import PolicyError,candidates
from management_policy import NativePolicy
from fleet_slots import RemoteAllocator as NativeAllocator, atomic

ROOT=Path('/var/lib/rs-native-import')
REGISTRY_SOURCES={'127.0.0.1'}
UPSTREAM_PORT=0
MUTATION=threading.RLock();SLOTS=threading.BoundedSemaphore(8)
PATHS={
 '/api/admin/accounts/import','/api/admin/accounts/import-tasks','/api/admin/accounts/import-tasks/detail','/api/admin/accounts/import-tasks/stop',
 '/api/admin/accounts/update','/api/admin/accounts/batch-update','/api/admin/accounts/recover','/api/admin/accounts/oauth/start','/api/admin/accounts/oauth/complete',
 '/api/admin/proxies/update','/api/admin/proxies/accounts/remove'}

class UpstreamError(Exception):
    def __init__(self,status,raw):self.status=status;self.raw=raw

def backend_request(path,headers,body=None):
    conn=http.client.HTTPConnection('127.0.0.1',UPSTREAM_PORT,timeout=180)
    try:
        h={k:v for k,v in headers.items() if k.lower() in ['cookie','x-api-key','authorization','origin','referer','x-csrf-token','x-forwarded-for']}
        h.update({'Content-Type':'application/json','Host':urllib.parse.urlsplit(PUBLIC_ORIGIN).netloc,'X-Forwarded-Proto':'https'})
        conn.request('GET' if body is None else 'POST',path,body=None if body is None else json.dumps(body).encode(),headers=h)
        r=conn.getresponse();raw=r.read(32*1024*1024+1)
        if len(raw)>32*1024*1024:raise PolicyError('Backend response exceeds management limit',503)
        if r.status>=400:raise UpstreamError(r.status,raw)
        doc=json.loads(raw)
        if doc.get('code')!=200:raise UpstreamError(r.status,raw)
        return doc['data']
    finally:conn.close()

class Application:
    def __init__(self,allocator,root=ROOT/'private',backend=backend_request):
        self.allocator=allocator;self.root=Path(root);self.backend=backend;self.root.mkdir(mode=0o700,parents=True,exist_ok=True);self.workers=set()
    def audit(self,path,status):
        # Never retain request bodies, cookies, credentials, IPs or response content.
        event={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'path':path,'status':status}
        with (self.root/'audit.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(event)+'\n')
    def record_path(self,submission):
        return self.root/('task-'+hashlib.sha256(submission.encode()).hexdigest()+'.json')
    def record_for_task(self,task_id):
        for path in self.root.glob('task-*.json'):
            record=json.loads(path.read_text())
            if record.get('result',{}).get('taskId')==task_id:return path,record
        return None,None
    def finish_task(self,path,record,backend,policy):
        # A caller poll may have completed this task since the worker last ran.
        record=json.loads(path.read_text())
        task=backend('/api/admin/accounts/import-tasks/detail?taskId='+urllib.parse.quote(record['result']['taskId'],safe=''))
        finished=set(record.get('finished',[]))
        for item in task['items']:
            index=item['index']
            if item['status']!='succeeded' or index in finished:continue
            bindings=[]
            for binding in record['bindings']:
                if binding['index']!=index:continue
                e=next((r for r in self.allocator.all_rows() if r['port']==binding['port']),None)
                if not e:raise PolicyError('Native task reservation missing; account remains paused',503)
                bindings.append((e,tuple(binding['identity']),binding['desired']))
            policy.finish(item['accountIds'],bindings)
            finished.add(index);record['finished']=sorted(finished);atomic(path,record)
        return task
    def submit_task(self,body,backend,policy):
        sid=body.get('submissionId');items=body.get('items')
        if not isinstance(sid,str) or not isinstance(items,list) or not 0<len(items)<=500:raise PolicyError('Import task submission invalid',400)
        # Let the supported API validate the submission UUID as well.
        import uuid
        try:assert uuid.UUID(sid).int!=0
        except (ValueError,AssertionError):raise PolicyError('Import submission UUID invalid',400) from None
        digest=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest();path=self.record_path(sid)
        if path.exists():
            prior=json.loads(path.read_text())
            if prior['digest']!=digest:raise PolicyError('Submission ID reused for a different import',409)
            if prior.get('result'):return prior['result']
        policy.preflight_imports(items)
        prepared=copy.deepcopy(body);prepared['items']=[];bindings=[]
        for item in items:
            for row in candidates(item['data']):
                one=copy.deepcopy(item);one['data']=row
                if row.get('notes') is not None:one.setdefault('settings',{'enabled':True,'concurrencyLimit':None,'weight':1,'groupIds':[]})['notes']=row['notes']
                transformed,allocated=policy.import_item(one,'task:'+sid+':'+str(len(prepared['items'])))
                for e,ident,desired in allocated:bindings.append({'index':len(prepared['items']),'port':e['port'],'identity':list(ident),'desired':desired})
                prepared['items'].append(transformed)
        record={'digest':digest,'bindings':bindings,'finished':[]};atomic(path,record)
        result=backend('/api/admin/accounts/import-tasks',prepared);record['result']=result;atomic(path,record)
        def follow():
            try:
                deadline=time.monotonic()+1800
                while time.monotonic()<deadline:
                    with MUTATION:task=self.finish_task(path,record,backend,policy)
                    if task.get('finishedAt'):break
                    time.sleep(2)
            except Exception:pass # Caller polling with fresh authentication resumes finalization.
            finally:
                with MUTATION:self.workers.discard(result['taskId'])
        self.workers.add(result['taskId']);threading.Thread(target=follow,daemon=True).start();return result

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def reply(self,status,data,raw=False):
        payload=data if raw else json.dumps(data,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(payload)));self.send_header('Connection','close');self.end_headers()
        try:self.wfile.write(payload)
        except (BrokenPipeError,ConnectionResetError):pass
        self.close_connection=True
    def dispatch(self):
        path=urllib.parse.urlsplit(self.path).path;app=self.server.app;status=503;acquired=False
        try:
            if path=='/healthz':status=200;self.reply(200,{'status':'ok','native_registry':len(app.allocator.rows())});return
            if path not in PATHS and path not in ['/_management/native-registry','/_management/ready']:raise PolicyError('Management route not found',404)
            if self.command not in ['GET','POST']:raise PolicyError('Management method not allowed',405)
            acquired=SLOTS.acquire(blocking=False)
            if not acquired:raise PolicyError('Management operations busy; retry later',503)
            headers=dict(self.headers);backend=lambda p,b=None:app.backend(p,headers,b)
            # The actual RS validates session or API key before any body parsing/allocation.
            backend('/api/admin/accounts?page=1&pageSize=1')
            if self.command=='POST':
                origin=self.headers.get('Origin')
                if origin and origin!=PUBLIC_ORIGIN:raise PolicyError('Cross-origin management request rejected',403)
                if self.headers.get('Cookie') and not origin:raise PolicyError('Browser management request requires same origin',403)
            policy=NativePolicy(backend,app.allocator)
            if path=='/_management/native-registry':
                if self.command!='GET' or self.client_address[0] not in REGISTRY_SOURCES or not self.headers.get('x-api-key'):raise PolicyError('Registry is restricted to authenticated local sync',403)
                result=app.allocator.rows()
            elif path=='/_management/ready':
                if self.command!='GET':raise PolicyError('Read-only endpoint',405)
                result={'accounts':len(policy.inventory()),'native_bindings':len(app.allocator.rows()),'workers':len(app.workers),'permanent_ipv6_no_reuse':True,'used_ipv6':len(app.allocator.used_ipv6())}
            elif self.command=='GET':
                if path=='/api/admin/accounts/import-tasks/detail':
                    tid=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('taskId',[''])[0]
                    with MUTATION:
                        p,record=app.record_for_task(tid);result=app.finish_task(p,record,backend,policy) if record else backend(self.path)
                else:result=backend(self.path)
            else:
                if self.headers.get('Transfer-Encoding'):raise PolicyError('Chunked management bodies are not accepted',400)
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=4*1024*1024:raise PolicyError('Management body length invalid',413)
                body=json.loads(self.rfile.read(size))
                if not isinstance(body,dict):raise PolicyError('Management body must be an object',400)
                with MUTATION:
                    if path=='/api/admin/accounts/import':result=policy.import_sync(body)
                    elif path=='/api/admin/accounts/import-tasks':result=app.submit_task(body,backend,policy)
                    elif path in ['/api/admin/accounts/update','/api/admin/accounts/batch-update']:result=policy.update(path,body)
                    elif path=='/api/admin/accounts/oauth/start':result=policy.start_oauth(body)
                    elif path=='/api/admin/accounts/oauth/complete':result=policy.complete_oauth(body)
                    elif path=='/api/admin/accounts/recover':
                        a=policy.detail(body['accountId'])
                        if int((a.get('capacity') or {}).get('usedSlots',0))>0:raise PolicyError('Account currently in flight',409)
                        policy.entry_for(a,verify=True);result=backend(path,body)
                    elif path=='/api/admin/proxies/update':result=policy.update_proxy_budget(body)
                    elif path.startswith('/api/admin/proxies/'):raise PolicyError('Native fixed exits cannot be edited or detached through shared proxies',409)
                    elif path=='/api/admin/accounts/import-tasks/stop':result=backend(path,body)
                    else:raise PolicyError('Management method not allowed',405)
            status=202 if self.command=='POST' and path.endswith('/import-tasks') else 201 if self.command=='POST' and (path.endswith('/import') or '/oauth/' in path) else 200
            self.reply(status,{'code':200,'message':'OK','data':result})
        except UpstreamError as e:status=e.status;self.reply(status,e.raw,raw=True)
        except PolicyError as e:status=e.status;self.reply(status,{'code':status*100+1,'message':str(e),'data':None})
        except (ValueError,KeyError,TypeError):status=400;self.reply(status,{'code':40001,'message':'Management request invalid','data':None})
        except Exception:status=503;self.reply(status,{'code':50301,'message':'Management verification failed; credentials and diagnostics withheld','data':None})
        finally:
            if acquired:SLOTS.release()
            if self.command!='GET':app.audit(path,status)
    do_GET=dispatch;do_POST=dispatch;do_PUT=dispatch;do_DELETE=dispatch
