"""Exercise real plugin processes against one CAS state store; never call an account API."""
import concurrent.futures, copy, json, os, struct, subprocess, sys, threading, time

store = {}
lock = threading.Lock()
barrier = None
race_reads = 0

class Plugin:
    def __init__(self, executable):
        self.p = subprocess.Popen([executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.send_lock=threading.Lock();self.queue_delay=0;self.lease_writes=0
        self.id = 99
        self.send({'type':'hello','handshake':{'protocol_version':5,'artifact_sha256':'a'*64,'plugin_id':'personal.reauth-manager','instance_id':'shared-test','generation':1,'incarnation':str(self.p.pid),'configuration':{},'contributes':{'management':{'id':'personal.reauth-manager.management','version':2,'stages':['management']},'maintenance':{'id':'personal.reauth-manager.maintenance','version':1,'stages':['maintenance']}}}})
        assert self.frame()[0]['type'] == 'ready'
    def send(self, meta, payload=b''):
        key = {'hello':'configuration', 'call':'params', 'result':'result'}.get(meta['type'])
        if meta['type']=='hello': business=meta['handshake'].pop(key)
        elif key: business=meta.pop(key)
        else: business=None
        if business is not None:
            raw=json.dumps(business).encode();meta['data_bytes']=len(raw);payload=raw+payload
        raw=json.dumps(meta).encode()
        with self.send_lock:self.p.stdin.write(struct.pack('>IQ',len(raw),len(payload))+raw+payload);self.p.stdin.flush()
    def read(self, size):
        data=b''
        while len(data)<size:
            part=self.p.stdout.read(size-len(data));assert part,'Plugin exited';data+=part
        return data
    def frame(self):
        m,p=struct.unpack('>IQ',self.read(12));meta=json.loads(self.read(m));payload=self.read(p)
        n=meta.get('request_context_bytes',0);size=meta.get('data_bytes',0)
        if size:meta['business']=json.loads(payload[n:n+size])
        return meta,payload[n+size:]
    def call(self,path,method='POST',body=b'{}'):
        global race_reads
        self.id+=2;call_id=self.id
        self.send({'type':'call','id':call_id,'method':'management.handle','params':{'method':method,'path':path,'query':'','content_type':'application/json' if method=='POST' else None,'headers':[]},'context':{'call_id':call_id,'instance_id':'shared-test','generation':1,'incarnation':str(self.p.pid),'stage':'management','timeout_ms':60000,'resource_stream':False,'resource_scope_id':f'scope_{call_id}'}},body)
        while True:
            meta,payload=self.frame()
            if meta['type']=='callback':
                params=meta['business'];key=params.get('key');operation=meta['method']
                assert operation in ['host.state.get','host.state.put'], 'Account APIs forbidden: '+operation
                wait=False;conflict=False
                with lock:
                    record=copy.deepcopy(store.get(key))
                    if operation=='host.state.get':
                        value={'record':record}
                        if key=='executor' and barrier and race_reads<2:race_reads+=1;wait=True
                    elif (record or {}).get('version') != params['expected_version']:
                        conflict=True
                    else:
                        version=(record or {}).get('version',0)+1
                        store[key]={'value':copy.deepcopy(params['value']),'version':version,'schema_version':1};value={'version':version}
                        if key=='executor':self.lease_writes+=1
                if wait:barrier.wait(timeout=10)
                if operation=='host.state.get' and key=='queue' and self.queue_delay:
                    delay=self.queue_delay;self.queue_delay=0
                    threading.Timer(delay,lambda response=value,callback=meta['id']:self.send({'type':'result','id':callback,'result':response})).start()
                    continue
                if conflict:self.send({'type':'error','id':meta['id'],'error':{'code':'conflict','message':'state version conflicts','send_state':'not_sent'}})
                else:self.send({'type':'result','id':meta['id'],'result':value})
            else:
                assert meta['type']=='result' and meta['id']==call_id,(meta,payload)
                return meta['business']['status'],json.loads(payload)
    def close(self):
        self.send({'type':'shutdown'});self.p.stdin.close();assert self.p.wait(timeout=10)==0

def main(executable):
    global barrier, race_reads
    a,b=Plugin(executable),Plugin(executable)
    try:
        barrier=threading.Barrier(2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda p:p.call('api/tick'),[a,b]))
        assert all(code==200 for code,_ in results),results
        statuses=[p.call('api/executor','GET',b'')[1] for p in [a,b]]
        assert sum(s['localOwner'] for s in statuses)==1,statuses
        owner,passive=(a,b) if statuses[0]['localOwner'] else (b,a)
        print('PASS simultaneous CAS acquisition elects exactly one executor')
        before=copy.deepcopy(store)
        assert passive.call('api/tick')[1]['standby'] is True
        assert passive.call('api/jobs','GET',b'')[0]==200
        assert store==before
        assert passive.call('api/cancel',body=b'{"requestId":null}')[0]==400
        assert store==before
        print('PASS passive ticking and status reads never recover or overwrite queue state')
        with lock:
            store['queue']={'version':1,'schema_version':1,'value':{'jobs':[{'requestId':'existing-work','accountId':'fixture-account','status':'running','step':'mfa','message':'','startedAt':1,'finishedAt':None}],'automation':{'enabled':False,'attempts':{}}}}
        assert owner.call('api/submit',body=b'not-json')[0]==400
        assert owner.call('api/tick')[0]==200
        assert owner.call('api/jobs','GET',b'')[1]['jobs'][0]['status']=='running'
        with lock:store.pop('queue')
        print('PASS an invalid administrative request cannot reset or interrupt existing work')
        owner.queue_delay=12;writes=owner.lease_writes
        assert owner.call('api/tick')[0]==200 and owner.lease_writes-writes>=2
        print('PASS a blocked task renews ownership before completing instead of expiring mid-operation')
        assert owner.call('api/standby')[1]['standby'] is True
        assert passive.call('api/tick')[0]==200
        assert passive.call('api/executor','GET',b'')[1]['localOwner'] is True
        assert owner.call('api/tick')[1]['standby'] is True
        print('PASS idle host handover releases only its own lease and stays passive')
        passive.close();passive=None
        with lock:
            store['executor']['value']['expires']=0
            store['queue']={'version':1,'schema_version':1,'value':{'jobs':[{'requestId':'interrupted','accountId':'fixture-account','status':'running','step':'mfa','message':'','startedAt':1,'finishedAt':None}],'automation':{'enabled':False,'attempts':{}}}}
        c=Plugin(executable)
        try:
            assert c.call('api/tick')[0]==200
            state=c.call('api/jobs','GET',b'')[1]
            assert state['jobs'][0]['status']=='interrupted' and state['jobs'][0]['finishedAt']
            assert any(text in state['jobs'][0]['message'] for text in ['不会自动重试','手动处理'])
            print('PASS expired owner recovery closes orphaned work without replaying login or changing accounts')
        finally:c.close()
    finally:
        a.close() if a.p.poll() is None else None
        b.close() if b.p.poll() is None else None
    print(json.dumps({'passed':True,'accountRequests':0,'processes':3,'cases':6}))

if __name__=='__main__':main(sys.argv[1])
