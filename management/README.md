# Protected onboarding adapter

`native_ipv6_verification.py` verifies the exact IPv6 recorded for a native allocator entry through its own fixed proxy authentication. Network failures can use either ipify or Cloudflare Trace within an 18-second overall budget; an invalid or different address fails immediately. The helper never allocates an address, changes a reservation, exchanges a token or repeats an OAuth request. A native manager integration must retain permanent ownership registration before calling it and map failures to its existing policy error.

The optional loopback adapter forwards administrator authentication to the effective protected RS manager. It discovers the allocator from the active service working directory and keeps native flow, PKCE, account binding and fixed proxy protections. It never exchanges tokens.

Native start and complete may return HTTP 201 with the standard business code 200. The adapter preserves that data and normalizes successful transport to HTTP 200 for the plugin. A transport status alone never proves business success. Non-success business codes, missing data and uncertain results are rejected without replay.

Run `python -B -m unittest discover -s management -p "test_*.py"`. Tests use public fixtures and no network. Production manager addresses and credentials are not part of this directory. Use isolated staging and preserve existing in-flight flows during deployment; installation does not authorize replay of failed operations.

`native_import_service.py` loads an explicitly selected native IPv6 management service after checking its SHA-256. It retains that service's authentication, immutable allocator, registry, original receipts and native RS APIs. Native background-task indices start at one; earlier zero-based reservation receipts are read with an index conversion, without re-importing credentials. A saved task result is checked with the native detail API under the current caller's authentication before it is returned. An uncertain submission blocks replay, including after process restart.

New native AT, RT and account-document imports are saved paused, with explicit concurrency 3 when no value was supplied. Completion binds the original fixed IPv6 reservation, checks saved token identity, expiry, notes and any supplied RT, and then restores the requested enablement. AT-only accounts retain their native expiry and do not gain a refresh token. A verified new `pro` or `prolite` account receives concurrency 100, weight 100 and the unique enabled `GPT Pro` group; every imported account's exact independent IPv6, permanent ownership and actual exit must pass before enablement. Pro configuration is saved and read back while paused. Other plans keep their settings. Reconciliation never pauses an already enabled account to repeat finalization. Sites with shared exits cannot use this independent-IPv6 service as a substitute for a unique pool.

An existing paused, idle account can be updated through the native import API after full-directory identity checks. It keeps its record, fixed proxy, concurrency, weight, groups and model policy. Known older token versions are rejected before import, and the caller's explicit enablement is applied only after finalization. Ordinary background reauthorization keeps its existing policy. Native task finalization stores only identity, reservation, input digests and status; it does not retain raw tokens or notes in the protected task receipt.

The runtime requires explicit `--public-origin` and `--manager-unit`, plus the local adapter, manager and gateway ports. Supply these through private deployment configuration. The public code contains no site-specific service, address or domain.

The fixed-pool adapter's `/health` response includes `data.sourceSha256` for the source loaded by that process. Verify it against the checked local source before routing new requests. Keep site configuration in command-line arguments and use the maintained adapter directly; a previously deployed source copy may omit current lock and receipt protections. Unexpected failures log only the exception class, never request data or exception messages.

For a site with an explicitly approved existing fixed exit pool, `fixed_pool_onboarding.py` uses the effective pool manager's registry, authentication service and allocation lock. It reserves separate account authentication before native OAuth, tests the exact configured exit, and binds the saved paused account to that same reservation. The plugin then performs its normal token, workspace, refresh and scheduling checks. It does not create or restart a proxy process or copy another site's allocator or account data.

This optional adapter requires the running manager unit, exact source path and SHA-256, pool root, private receipt directory, public origin and loopback ports. Uncertain native start/complete calls leave durable receipts that block replay across restarts. Existing accounts, opaque callbacks, login credentials and refresh tokens are never written into those receipts. This is only for a site whose fixed pool and sharing policy are already explicitly authorized; it does not replace a permanent unique-address ownership allocator.

The fixed-pool adapter accepts both native OAuth completion and explicitly supplied refresh-token imports. It reserves and verifies distinct fixed authentication before either native operation, explicitly saves new accounts with concurrency 3, and checks the saved notes, identity and proxy before binding the reservation. Native persistence and binding hold the existing allocator lock together, preventing the background allocator from assigning a second proxy. Deleted registrations stay intact but do not affect current-account balancing; pending reservations still count. `--identity-mapping` optionally appends the verified identity to an existing consumer mapping file without changing its existing entries. `/health` reports process readiness only, not authorization or upstream success.

The fixed-pool adapter waits up to 20 seconds when the background allocator holds its nonblocking lock. Only lock acquisition is retried; reservation writes and native requests are never replayed. Exhaustion returns 409 before entering the critical section. A completion/import receipt moves to its pending phase only after the lock is acquired, so contention cannot falsely record that a native request was submitted. Errors after submission retain the pending receipt for reconciliation.

Before native OAuth starts or completes, read-only exit checks allow up to three network attempts of five seconds each, using the same fixed proxy authentication. If ipify fails at the network or HTTP layer, the next attempt uses Cloudflare Trace to verify the same exit. An unexpected or invalid exit is rejected immediately. Exhausted network attempts report `proxy_exit_unavailable`; they do not start OAuth, change the reservation or replay a native submission.

For explicitly authorized recovery of a failed new-account flow, `--recovery-permits` optionally reads a private operator-written approval map keyed by the receipt filename stem. Each approval includes the exact `receiptSha256`, `oldFlowAbsent: true`, and an `expiresAt` no more than 15 minutes ahead. Before writing an approval, reconcile the full account directory, verify that the old native flow no longer exists, exclude in-flight requests, and verify the original reservation is unbound. Only a `native_complete_pending` receipt at least 15 minutes old is eligible. The adapter preserves the full old receipt and original fixed proxy authentication, consumes approval by changing the receipt, and starts a fresh native flow. Ordinary retries, altered receipts, live flows, bound identities, and expired approvals remain blocked. Never create this approval automatically from a failed HTTP response or persist login credentials in it.


## Fleet independent IPv6 imports (0.1.68)

The current import path uses `fleet_slots.py` on the physical pool host and a `fleet_import_service.py` on each RS host. The broker discovers the active protected allocator from its systemd working directory and pins its source hash. It delegates to the existing immutable slot allocator and permanent ownership ledger. It never creates per-account proxy containers or restarts a data plane. Site credentials and the broker ledger belong in private runtime directories and must not be committed.

Every explicit submission gets a fresh reservation namespace. Same-flow recovery retains its exact reservation; another submission never inherits an old failed flow. Native imports remain local to each RS instance. Pro and ProLite require an enabled, unique GPT Pro group and 100 concurrency/weight. Plugin-controlled native steps stay paused until the plugin performs its saved-credential and final configuration checks; a successful native import honors its requested enabled state. Ordinary existing-account OAuth retains its original proxy and controls.

An explicit reimport may replace a paused, idle account's exit. The broker retains its prior authentication and first ownership before binding the new reservation; the old data plane remains available for other consumers and is never reassigned. `fleet_sync.py` adds only verified new pool bindings to the existing incremental engines. Existing Chat2API identities, quotas, counters, cooling, pause state and in-flight guards remain owned by those engines.

The older shared fixed-pool adapters documented above remain recovery material and support existing consumers. They are not the import allocation path for the fleet independent-pool policy. Keep rollback routes, native flow receipts, broker site keys and both permanent IPv6 ledgers across upgrades. Recheck the effective gateway port and proxy/manager source paths at deployment time.
# Short polling for protected RT imports

`protected_operations.py` is an authenticated loopback front end for the existing
protected import manager. Plugin 0.1.86 requires its `/_management/import-operation`
endpoint. Install and validate this front end before changing the plugin's
`protectedManagementUrl`. The original manager, allocator, policy layers and
native OAuth routes remain in place.

The front end authenticates every operation request against the native admin
API. It forwards RT imports once to the current protected import policy and
forwards the other supported paths to the prior protected entry. Configure
`--auth-port`, `--forward-port`, `--legacy-port`, `--origin`, a private `--root`
and a separate loopback `--port` explicitly from the target instance's effective
configuration.

Operation intents contain a UUID and request hash. Completed receipts retain
only native account IDs, counters and finite diagnostic codes. Login notes,
tokens and administrator headers remain in memory. Repeated polls do not start
another native request. A persisted intent without an in-memory worker after
restart returns an uncertain result and requires reconciliation. An already
sent native operation can finish after plugin cancellation; inspect the account
and receipt before resubmitting.

The worker's HTTP operation has a 600 second limit. Individual plugin callbacks
keep the SDK's default budget and return pending results promptly. Extending the
plugin's total budget alone is insufficient because the current managed outbound
HTTP client limits individual calls to 120 seconds.


## Current proxy provisioning

When the shared managed GOST data plane moves to a new container or physical
listener offset, `fleet_slots.py --gost-configuration` validates new immutable
reservations against that manager's current container, API service identity,
listener and IPv6 interface. `--allocator-root` fixes the verified permanent
ownership implementation independently of the manager process working directory.
The adapter does not start or reload proxies, recycle slots or change fixed
authentication. The original permanent history, reservations, registry and
retirement blacklist remain authoritative. Existing authenticated IPv6 exit
verification still runs before any supplied RT is sent.
