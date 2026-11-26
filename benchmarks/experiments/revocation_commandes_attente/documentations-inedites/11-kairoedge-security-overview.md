# KairoEdge — Deferred Command Security

*Format: Security overview*

1. KairoEdge associates each queued operation with an authenticated service identity.
2. Command acceptance is subject to a permission check against the identity's current access policy.
3. The result of this check is recorded alongside the queue entry.
4. Subsequent permission changes do not cancel delivery of an operation that passed the initial acceptance check.
5. This behavior supports reliable execution across long device sleep intervals.
6. All administrative changes are recorded in an immutable security event log.
7. The default audit synchronization interval is 300 seconds.
8. Administrator authentication sessions have a maximum duration of 25 minutes.
