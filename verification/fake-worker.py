"""Offline protocol fixture. Never makes a network request."""
import json
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
else:
    print(json.dumps({"event": "complete", "callbackUrl": "http://localhost:1455/auth/callback?state=fixture&code=secret-code"}), flush=True)
