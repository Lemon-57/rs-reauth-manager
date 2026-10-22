# Protected onboarding adapter

The optional loopback adapter forwards administrator authentication to the effective protected RS manager. It discovers the allocator from the active service working directory and keeps native flow, PKCE, account binding and fixed proxy protections. It never exchanges tokens.

Native start and complete may return HTTP 201 with the standard business code 200. The adapter preserves that data and normalizes successful transport to HTTP 200 for the plugin. A transport status alone never proves business success. Non-success business codes, missing data and uncertain results are rejected without replay.

Run `python -B -m unittest discover -s management -p "test_*.py"`. Tests use public fixtures and no network. Production manager addresses and credentials are not part of this directory. Use isolated staging and preserve existing in-flight flows during deployment; installation does not authorize replay of failed operations.

The runtime requires explicit `--public-origin` and `--manager-unit`, plus the local adapter, manager and gateway ports. Supply these through private deployment configuration. The public code contains no site-specific service, address or domain.
