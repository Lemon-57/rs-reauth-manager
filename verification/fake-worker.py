"""Offline fixture: every authorization returns only an RS-owned callback."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'protocol'))
from runner import authorization
DID='59859b73-b63b-45f4-86f9-e728a9512905'
def emit(value):
    if value['event'] in {'complete','free_fallback','forced_workspace','forced_free','team_upgrade'}:value['deviceId']=DID
    print(json.dumps(value),flush=True)
data=json.load(sys.stdin)
assert data['proxy']=='http://fixture:pass@127.0.0.1:21001'
name=data.get('email','').split('@')[0]
if data.get('action') in {'cleanup_sessions','verify_sessions'}:
    assert set(data['tokens'])=={'access_token','id_token'}
    assert 'clientId' not in data and data['deviceId']==DID
    if data['action']=='verify_sessions':
        assert data['expectedSessionId']=='fixture-current-session'
        emit({'event':'sessions_verified','otherSessionsRevoked':name!='verify_failure','currentSessionRetained':name!='verify_failure'})
        sys.exit(0)
    if name=='cleanup_slow':time.sleep(60)
    if name=='cleanup_failure':emit({'event':'error','code':'sessions','diagnostic':{'stage':'other_sessions','reason':'sessions_revoke_unconfirmed'}})
    else:emit({'event':'sessions_cleaned','workspaceId':data['accountId'],'originalWorkspaceId':data['accountId'],'otherSessionsRevoked':name!='cleanup_no_proof','revokedCount':2,'retainedSessionId':'fixture-current-session'})
    sys.exit(0)
assert '----' in data['notes'] and data['email'] in data['notes']
assert authorization(data['authorizationUrl'])[1]=='fixture'
if name in {'slow','cleanup_slow_login'}:time.sleep(60)
if name=='password_failure':emit({'event':'error','code':'password'});sys.exit(0)
if name.startswith('force_') and not data.get('forceWorkspaceId'):
    emit({'event':'error','code':'workspace','workspaces':[{'id':'alternate-workspace'}]});sys.exit(0)
if name=='free_fallback_no_candidates' and not data.get('forceFree'):
    emit({'event':'error','code':'workspace','workspaces':[]});sys.exit(0)
output={'event':'complete','callbackUrl':'http://127.0.0.1:1455/auth/callback?state=fixture&code=secret-code'}
if name.startswith('fb_'):output.update(event='free_fallback',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],originalWorkspaceUnavailable=True)
if name.startswith('up_'):output.update(event='team_upgrade',workspaceId='team-workspace',originalWorkspaceId=data['accountId'],uniqueTeamConfirmed=True)
if data.get('forceWorkspaceId'):output.update(event='forced_workspace',workspaceId=data['forceWorkspaceId'],originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if data.get('forceFree'):output.update(event='forced_free',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if name=='plugin_tokens_injected':output['tokens']={'refresh_token':'forbidden-local-rt'}
emit(output)
