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
elif data["email"].startswith("fb_"):
    name = data["email"].split('@')[0]
    auth = {"chatgpt_account_id": "personal-workspace", "chatgpt_user_id": data.get("userId"), "chatgpt_plan_type": "free"}
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
    if name == "fb_rt":
        output["tokens"]["refresh_token"] = ""
    if name == "fb_old_workspace":
        output["originalWorkspaceId"] = "wrong-old-workspace"
    print(json.dumps(output), flush=True)
else:
    print(json.dumps({"event": "complete", "callbackUrl": "http://localhost:1455/auth/callback?state=fixture&code=secret-code"}), flush=True)
