"""Offline protocol fixture. Never makes a network request."""
import json
import sys
import time

data = json.load(sys.stdin)
assert data["proxy"] == "http://fixture:pass@127.0.0.1:21001"
assert "----" in data["notes"]
assert data["email"] in data["notes"]
print(json.dumps({"event": "step", "step": "login"}), flush=True)
if data["email"].startswith("slow"):
    time.sleep(60)
elif data["email"].startswith("failed"):
    print(json.dumps({"event": "error", "code": "password"}), flush=True)
else:
    print(json.dumps({"event": "complete", "callbackUrl": "http://localhost:1455/auth/callback?state=fixture&code=secret-code"}), flush=True)
