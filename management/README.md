# Protected onboarding adapter

The optional loopback adapter forwards administrator authentication to the effective protected RS manager. It discovers the allocator from the active service working directory and keeps native flow, PKCE, account binding and fixed proxy protections. It never exchanges tokens.

Native start and complete may return HTTP 201 with the standard business code 200. The adapter preserves that data and normalizes successful transport to HTTP 200 for the plugin. A transport status alone never proves business success. Non-success business codes, missing data and uncertain results are rejected without replay.

Run `python -B -m unittest discover -s management -p "test_*.py"`. Tests use public fixtures and no network. Production manager addresses and credentials are not part of this directory. Use isolated staging and preserve existing in-flight flows during deployment; installation does not authorize replay of failed operations.

The runtime requires explicit `--public-origin` and `--manager-unit`, plus the local adapter, manager and gateway ports. Supply these through private deployment configuration. The public code contains no site-specific service, address or domain.

For a site with an explicitly approved existing fixed exit pool, `fixed_pool_onboarding.py` uses the effective pool manager's registry, authentication service and allocation lock. It reserves separate account authentication before native OAuth, tests the exact configured exit, and binds the saved paused account to that same reservation. The plugin then performs its normal token, workspace, refresh and scheduling checks. It does not create or restart a proxy process or copy another site's allocator or account data.

This optional adapter requires the running manager unit, exact source path and SHA-256, pool root, private receipt directory, public origin and loopback ports. Uncertain native start/complete calls leave durable receipts that block replay across restarts. Existing accounts, opaque callbacks, login credentials and refresh tokens are never written into those receipts. This is only for a site whose fixed pool and sharing policy are already explicitly authorized; it does not replace a permanent unique-address ownership allocator.
