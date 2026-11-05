# Independent account import portal

A dependency-free web entry for the **installed** reauthorization plugin. It uses
an independent administrator login and discovers the active plugin revision on every
request. Account submission calls the plugin's `api/import-line` route exactly
once. The existing plugin owns deduplication, fixed proxy allocation, native OAuth,
subscription policy, persistence and final account verification.

Run with Python 3.10 or later:

```sh
python3 -B server.py --origin https://import.example.com --upstream http://127.0.0.1:18118 --credentials /run/credentials/portal-auth.json
```

The listener binds to `127.0.0.1:18884`. Put an HTTPS reverse proxy on the same
host in front of it. Preserve the public `Host` header. The upstream must be the
local RS protected management listener. Supply a private JSON credential file with
`username`, a 32-byte hexadecimal `salt`, `passwordHash` (PBKDF2-HMAC-SHA256 with
600,000 iterations), and the native administrator `upstreamKey`. Keep this file
outside the source tree and deliver it through systemd `LoadCredential` or an
equivalent private runtime secret mechanism. No plaintext password is stored.
Portal sessions last eight hours, are held in memory, and use a Secure, HttpOnly,
SameSite=Strict cookie. Login attempts and password hashing concurrency are bounded.
Only login, logout, task listing and account import are exposed; there is no generic
management proxy. Non-admin users cannot import or read task history.

Input stays in memory and is cleared before submission. Cookies and account
credentials are never logged. The only browser storage is the non-sensitive
submission UUID used to find the current batch after a refresh. Failed or timed
out submissions are never retried automatically. Background maintenance belongs
to RS, so closing the page does not cancel accepted work. Plugin upgrades are
handled by resolving the current revision rather than replaying stale mutations.

The portal administrator password is independent of the RS administrator password.
Native session cookies and client-supplied API keys are not forwarded. The server
uses its runtime credential only after validating a portal administrator session.

New imports keep the installed plugin's policies, including its default account
concurrency and any verified subscription-specific exceptions. This application
does not change existing accounts, plugin settings, account groups or scheduling.

Verification:

```sh
python3 -B -m unittest discover -s portal -p 'test_*.py'
node --check portal/web/app.js
```
