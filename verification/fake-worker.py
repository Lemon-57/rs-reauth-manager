"""Offline fixture: every authorization returns only an RS-owned callback."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'protocol'))
from runner import authorization, parse_notes
DID='59859b73-b63b-45f4-86f9-e728a9512905'
def emit(value):
    print(json.dumps(value),flush=True)
data=json.load(sys.stdin)
name=data.get('email','').split('@')[0]
if data.get('action')=='mailshop_rt':
    assert name in {'mailshop_success','mailshop_paused','mailshop_profile','mailshop_free_upgrade','mailshop_free_upgrade_busy','mailshop_free_upgrade_team_busy','mailshop_busy_before_rt','mailshop_no_rt','mailshop_missing_saved_rt','mailshop_reject','mailshop_race','mailshop_legacy_failure'}
    assert set(data)=={'action','email','notes','mailshopRtApiKey'} and data['mailshopRtApiKey']=='fixture-mailshop-key'
    if name in {'mailshop_race','mailshop_busy_before_rt'}: time.sleep(0.3)
    if name=='mailshop_no_rt':
        emit({'event':'error','code':'mailshop_rt_unconfirmed','diagnostic': {
            'reason':'account_rejected','httpStatus':200,'detail':'邮箱验证码获取超时','raw':'fixture-mailshop-key',
        }})
    else: emit({'event':'mailshop_rt','refreshToken':'fixture-mailshop-rt'})
    sys.exit(0)
assert data['proxy'].rstrip('/')=='http://fixture:pass@127.0.0.1:21001'
assert 'mailshopRtApiKey' not in data
assert data.get('action') is None, 'Authorization must never launch a device-management worker'
assert '----' in data['notes'] and data['email'] in data['notes']
assert authorization(data['authorizationUrl'])[1]=='fixture'
if 'mailbox' in name:
    parsed = parse_notes(data['notes'], data['email'])
    assert parsed[1] == 'fixture-password' and parsed[2] == 'GEZDGNBVGY3TQOJQ'
if name in {'slow','cleanup_slow_login'}:time.sleep(60)
if name in {'password_failure', 'automatic_once_failure'}:emit({'event':'error','code':'password'});sys.exit(0)
if name in {'diagnostic_email', 'diagnostic_banned'}:
    emit({'event':'error','code':'protocol','diagnostic':{'stage':'email_verify' if name=='diagnostic_email' else 'mfa_verify','reason':'email_code_required' if name=='diagnostic_email' else 'account_banned','httpStatus':200 if name=='diagnostic_email' else 403}});sys.exit(0)
if name.startswith('mailshop_') and name!='mailshop_native_ok':
    limited=name=='mailshop_limited'
    emit({'event':'error','code':'limited' if limited else 'human','diagnostic':{'stage':'email_verify','reason':'rate_limited' if limited else 'email_code_required','httpStatus':429 if limited else 200}});sys.exit(0)
if name.startswith('force_') and not data.get('forceWorkspaceId'):
    emit({'event':'error','code':'workspace','workspaces':[{'id':'alternate-workspace'}]});sys.exit(0)
if name=='free_fallback_no_candidates' and not data.get('forceFree'):
    emit({'event':'error','code':'workspace','workspaces':[]});sys.exit(0)
if name=='new_retry_after_failure' and parse_notes(data['notes'], data['email'])[1]=='fixture-rejected':
    emit({'event':'error','code':'workspace','workspaces':[]});sys.exit(0)
output={'event':'complete','callbackUrl':'http://127.0.0.1:1455/auth/callback?state=fixture&code=secret-code'}
if data.get('newAccount') and not name.startswith('new_callback_'):
    output['workspaceId']='incorrect-workspace' if name=='new_explicit_workspace_mismatch' else 'original-workspace'
if name.startswith('fb_') or name.startswith('auto_fb_'):output.update(event='free_fallback',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],originalWorkspaceUnavailable=True)
if data.get('recoverWorkspace'):output.update(event='workspace_recovered',workspaceId='personal-workspace' if 'personal' in name else 'team-workspace',selectedPlan='free' if 'personal' in name else 'team',uniqueWorkspaceConfirmed=True)
if name.startswith('up_') or name.startswith('auto_up_'):output.update(event='team_upgrade',workspaceId='team-workspace',originalWorkspaceId=data['accountId'],uniqueTeamConfirmed=True)
if data.get('forceWorkspaceId'):output.update(event='forced_workspace',workspaceId=data['forceWorkspaceId'],originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if data.get('forceFree'):output.update(event='forced_free',workspaceId='personal-workspace',originalWorkspaceId=data['accountId'],administratorConfirmed=True)
if name=='plugin_tokens_injected':output['tokens']={'refresh_token':'forbidden-local-rt'}
emit(output)
