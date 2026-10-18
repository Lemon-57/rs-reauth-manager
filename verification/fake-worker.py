"""Offline protocol fixture. Never makes a network request."""
import json
import base64
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "protocol"))
from runner import authorization

data = json.load(sys.stdin)
assert data["proxy"] == "http://fixture:pass@127.0.0.1:21001"
assert "----" in data["notes"]
assert data["email"] in data["notes"]
assert data["authorizationUrl"].startswith("https://chatgpt.com/codex/desktop-auth?")
assert authorization(data["authorizationUrl"])[1] == "fixture"
print(json.dumps({"event": "step", "step": "login"}), flush=True)
if data["email"].startswith("slow"):
    time.sleep(60)
elif data["email"].startswith("failed"):
    print(json.dumps({"event": "error", "code": "password"}), flush=True)
elif data["email"].startswith('diagnostic_'):
    cases = {'diagnostic_issue': {'stage': 'mfa_issue', 'reason': 'mfa_issue_failed', 'httpStatus': 403}, 'diagnostic_limit': {'stage': 'mfa_verify', 'reason': 'rate_limited', 'httpStatus': 429}, 'diagnostic_transport': {'stage': 'password', 'reason': 'request_timeout', 'httpStatus': None}, 'diagnostic_unsafe': {'stage': 'private-host', 'reason': 'fixture-password', 'httpStatus': 'fallback-private-rt'}}
    cases['diagnostic_mfa_local'] = {'stage': 'mfa_generate', 'reason': 'mfa_code_unavailable', 'httpStatus': None}
    cases['diagnostic_security'] = {'stage': 'security_token', 'reason': 'http_rejected', 'httpStatus': 403}
    cases['diagnostic_parse'] = {'stage': 'token_exchange', 'reason': 'response_invalid_json', 'httpStatus': 200}
    cases['diagnostic_mfa_previous'] = {'stage': 'mfa_generate', 'reason': 'mfa_new_code_timeout', 'httpStatus': None, 'previousVerification': {'stage': 'mfa_verify', 'reason': 'mfa_code_expired', 'httpStatus': 409, 'upstreamCode': 'otp_expired', 'raw': 'fixture-password'}}
    diagnostic = cases[data['email'].split('@')[0]]
    print(json.dumps({'event': 'error', 'code': 'protocol', 'diagnostic': diagnostic, 'rawResponse': 'fixture-password fallback-private-rt'}), flush=True)
elif data["email"].startswith("force_") and not data.get("forceWorkspaceId"):
    print(json.dumps({"event": "error", "code": "workspace", "workspaces": [{"id": "alternate-workspace"}, {"id": "second-workspace"}]}), flush=True)
elif data["email"].startswith("free_fallback_no_candidates") and not data.get("forceFree"):
    print(json.dumps({"event": "error", "code": "workspace", "workspaces": []}), flush=True)
elif data["email"].startswith(("fb_", "force_", "up_", "free_fallback_no_candidates")):
    name = data["email"].split('@')[0]
    auth = {"chatgpt_account_id": "personal-workspace", "chatgpt_user_id": data.get("userId"), "chatgpt_plan_type": "free"}
    forced = bool(data.get("forceWorkspaceId"))
    upgraded = name.startswith('up_')
    if upgraded:
        auth.update(chatgpt_account_id='team-workspace', chatgpt_plan_type='team')
        if name == 'up_wrong_plan': auth['chatgpt_plan_type'] = 'free'
        if name == 'up_wrong_user': auth['chatgpt_user_id'] = 'wrong-user'
    if forced:
        auth["chatgpt_account_id"] = data["forceWorkspaceId"]
        auth["chatgpt_plan_type"] = "plus"
        if name == "force_wrong_user":
            auth["chatgpt_user_id"] = "wrong-user"
        if name == "force_wrong_workspace":
            auth["chatgpt_account_id"] = "unconfirmed-workspace"
    if name == "fb_user":
        auth["chatgpt_user_id"] = "wrong-user"
    if name == "fb_workspace":
        auth["chatgpt_account_id"] = "wrong-workspace"
    if name == "fb_plan":
        auth["chatgpt_plan_type"] = "plus"
    claims = {"email": data["email"], "sub": "original-subject", "exp": int(time.time()) + 3600, "https://api.openai.com/auth": auth}
    if name == "fb_email":
        claims["email"] = "wrong@example.com"
    if name == "fb_expired":
        claims["exp"] = 1
    token = "fixture." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + ".signature"
    output = {"event": "free_fallback", "workspaceId": "personal-workspace", "originalWorkspaceId": data["accountId"], "originalWorkspaceUnavailable": name != "fb_proof", "tokens": {"access_token": token, "id_token": token, "refresh_token": "fallback-private-rt"}}
    if upgraded:
        output.update(event='team_upgrade', workspaceId='team-workspace', uniqueTeamConfirmed=name != 'up_no_proof')
    if forced:
        output.update(event="forced_workspace", workspaceId=data["forceWorkspaceId"], administratorConfirmed=True)
        if name == "force_no_confirmation":
            output["administratorConfirmed"] = False
    if data.get("forceFree"):
        output.update(event="forced_free", workspaceId="personal-workspace", administratorConfirmed=True, originalWorkspaceUnavailable=True)
    if name == "fb_rt":
        output["tokens"]["refresh_token"] = ""
    if name == "fb_old_workspace":
        output["originalWorkspaceId"] = "wrong-old-workspace"
    print(json.dumps(output), flush=True)
else:
    print(json.dumps({"event": "complete", "callbackUrl": "http://localhost:1455/auth/callback?state=fixture&code=secret-code"}), flush=True)
