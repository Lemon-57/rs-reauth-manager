"""Offline fixture: every authorization returns only an RS-owned callback."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'protocol'))
from runner import authorization
DID='59859b73-b63b-45f4-86f9-e728a9512905'
def emit(value):
    print(json.dumps(value),flush=True)
data=json.load(sys.stdin)
assert data['proxy'].rstrip('/')=='http://fixture:pass@127.0.0.1:21001'
name=data.get('email','').split('@')[0]
assert data.get('action') is None, 'Authorization must never launch a device-management worker'
assert '----' in data['notes'] and data['email'] in data['notes']
assert authorization(data['authorizationUrl'])[1]=='fixture'
if name in {'slow','cleanup_slow_login'}:time.sleep(60)
if name=='password_failure':emit({'event':'error','code':'password'});sys.exit(0)
if name.startswith('force_') and not data.get('forceWorkspaceId'):
    emit({'event':'error','code':'workspace','workspaces':[{'id':'alternate-workspace'}]});sys.exit(0)
if name=='free_fallback_no_candidates' and not data.get('forceFree'):
    emit({'event':'error','code':'workspace','workspaces':[]});sys.exit(0)
output={'event':'complete','callbackUrl':'http://127.0.0.1:1455/auth/callback?state=fixture&code=secret-code'}
if data.get('newAccount'):output['workspaceId']='original-workspace'
if name.startswith('fb_') or name.startswith('auto_fb_'):output.update(event='free_fallback',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],originalWorkspaceUnavailable=True)
if data.get('recoverWorkspace'):output.update(event='workspace_recovered',workspaceId='personal-workspace' if 'personal' in name else 'team-workspace',selectedPlan='free' if 'personal' in name else 'team',uniqueWorkspaceConfirmed=True)
if name.startswith('up_') or name.startswith('auto_up_'):output.update(event='team_upgrade',workspaceId='team-workspace',originalWorkspaceId=data['accountId'],uniqueTeamConfirmed=True)
if data.get('forceWorkspaceId'):output.update(event='forced_workspace',workspaceId=data['forceWorkspaceId'],originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if data.get('forceFree'):output.update(event='forced_free',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if name=='plugin_tokens_injected':output['tokens']={'refresh_token':'forbidden-local-rt'}
emit(output)
