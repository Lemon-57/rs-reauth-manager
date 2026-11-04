# Protected import reconciliation

Ordinary retries remain blocked while an import receipt exists. Before approving
a new attempt, reconcile the complete account directory, registry, identity
mapping and the exact native OAuth pending key. Never replay an uncertain native
completion or remove ownership history to bypass a conflict.

The optional private `--recovery-permits` file supports exact receipt SHA-256,
`oldFlowAbsent: true`, and an expiry no more than 900 seconds ahead. A receipt must
be at least 900 seconds old. Recovery of `reserved` without a flow or
`native_started` with an expired flow additionally requires an exact
`receiptPhase`. Bound identities and uncertain start/replacement phases stop.

When the operator has explicit authorization to ignore an old import proxy,
`newFixedIdentity: true` creates independent fixed authentication using the
configured pool policy. Supply `currentAccountIds` from a complete, unique
directory snapshot and, when applicable, `activeReservationIds` for current
pending work. Historical failed reservations do not contribute to that count.
The old registry row is retained with `superseded_by`, including its unchanged
authentication and ownership. The receipt retains its previous history. A
`replacement_pending` receipt prevents automatic replay if persistence fails.
Login starts only after the new identity's real exit has been verified.

This option does not revoke old authentication, drain consumers, rebind an
existing account, or enable background rotation. Those operations require their
own account/version, consumer and in-flight checks. The ordinary plugin import
endpoint continues rejecting directory duplicates; accepting an existing account
and applying a newly authorized binding requires a separate protected workflow.

The HTTP handler logs only fixed rejection categories and status codes; it never
logs the request, email, callback, proxy authentication or login notes.

## Native immutable IPv6 manager adapter

`onboarding_service.py` accepts an optional private `--recovery-permits` file for
an operator-reconciled failed new-account start. Each entry is keyed by the
receipt filename stem and requires the exact `receiptSha256`, `receiptPhase`,
`directoryReconciled: true`, `nativeFlowsReconciled: true`, `oldFlowAbsent: true`,
`allowNewNativeReservation: true` and an expiry within the next 900 seconds. The
receipt must be at least 900 seconds old and in `unconfirmed` or `ready` phase.

Reconcile the complete directory, pending native flows and unbound permanent
ownership history before approving recovery. A new manually approved native
flow may reserve a never-used identity through the current protected manager.
Existing reservations and permanent IPv6 ownership are retained and never
transferred or returned to the pool. The old receipt stays in `recoveryHistory`.
The new pending receipt invalidates the old approval before submission, so an
uncertain result blocks another recovery attempt, including after restart.
Ordinary starts still reject duplicates and never use this path automatically.
