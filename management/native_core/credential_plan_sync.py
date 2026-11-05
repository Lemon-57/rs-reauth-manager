"""Validate credential metadata through supported APIs only; never mutate SQL."""
import base64,json
from urllib.parse import quote

class PlanSyncError(RuntimeError):pass

def reconcile_reauthorized_plan(backend,account_id):
    rid=quote(account_id,safe='')
    account=backend('/api/admin/accounts/detail?accountId='+rid)['account']
    documents=backend('/api/admin/accounts/export?accountIds='+rid+'&confirm=export_sensitive_accounts')['documents']
    rows=documents[0]['document']['accounts']
    if len(documents)!=1 or len(rows)!=1:raise PlanSyncError('Credential export incomplete')
    facts=[]
    for key in ['idToken','accessToken']:
        token=rows[0].get(key)
        if not token:continue
        try:
            part=token.split('.')[1];claims=json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)));auth=claims.get('https://api.openai.com/auth') or {}
            if auth.get('chatgpt_plan_type'):facts.append((str(auth['chatgpt_plan_type']).lower(),auth.get('chatgpt_user_id') or auth.get('user_id'),auth.get('chatgpt_account_id')))
        except Exception:raise PlanSyncError('Credential identity unavailable') from None
    if not facts or any(f!=facts[0] for f in facts):raise PlanSyncError('Credential identity inconsistent')
    plan,user,workspace=facts[0]
    family=lambda p:'team' if p in ['team','business','self_serve_business_prolite'] else p
    if account.get('enabled') is not False or user!=account.get('userId') or (workspace and workspace!=account.get('accountId')):raise PlanSyncError('Credential user/workspace or paused state mismatch')
    if family(str(account.get('planType') or '').lower())!=family(plan):raise PlanSyncError('Subscription readback mismatch; account retained paused')
    return {'plan':plan,'display_plan':account['planType'],'metadata_changed':False,'paused':True}
