# Release-health controller

This zero-runtime-dependency Cloudflare Worker is checked in with `MODE=observe`. F2b does not
deploy it, provision credentials, or dispatch a workflow. The Worker has no public fetch handler
and `workers.dev` is disabled. Its one-minute schedule evaluates logical slots at minutes 1, 16,
31, and 46 only during ages 10 through 14, after the full native grace period. This creates five
bounded recovery opportunities for a prepared request without extending the admission window.

## Durable dispatch boundary

The SQLite Durable Object serializes every `/evaluate` request and uses a globally unique logical
slot. A slot moves through the typed phases `leased`, `prepared`, `post-attempted`, `unknown`,
`confirmed`, and `terminal`. The immutable source digest, activation-profile digest, request ID,
expected main SHA, and unsigned canonical envelope remain bound to the slot.

`prepared` contains no reusable signature. The controller recomputes the admission HMAC from the
protected key only when an active request is ready. The atomic transition from `prepared` to
`post-attempted` consumes the only dispatch permit before the outbound request. A restart from
`post-attempted` or `unknown` performs exact request-ID GET reconciliation only. It can never
receive another dispatch permit. GitHub has no dispatch idempotency key, so a crash after permit
consumption but before network transmission is deliberately treated as ambiguous and never
reposted.

Transport errors, timeouts, redirects, non-200 responses, oversized bodies, and malformed 200
receipts all become durable `unknown` evidence. Reconciliation is bounded and delayed to tolerate
provider indexing lag. Unresolved rows survive source or profile generation changes and remain
GET-only until the exact request appears.

A prepared request can resume only while its exact source and activation-profile digests remain
current. A digest mutation atomically terminalizes that unattempted request as
`prepared-abandoned`, appends its audit event, and enqueues the sanitized alert before returning.
The global slot remains consumed and cannot be prepared again under the new generation.
If a prepared row survives beyond its slot window, the next tick terminalizes and alerts it; it is
never backfilled or posted from a later logical slot.
A lease interrupted before preparation is handled the same way as `lease-abandoned`, so no
pre-network row can remain nonterminal indefinitely.

## Activation, standby, and circuit control

Observe mode records `would_dispatch` and makes zero workflow dispatch requests. Two consecutive
15-minute observe slots under the same exact source and activation profile produce an activation
proof bound to both audit hashes. The second terminal result, audit row, observation evidence, and
proof commit in one transaction. Changing only `MODE` preserves the proof. Changing source,
repository identity, workflow identities, cadence, grace window, credential epoch, alert epoch,
or circuit policy produces a different profile and invalidates it.

Two consecutive exact native canary slots place the controller in persistent standby. Loss of
that evidence resumes evaluation. Both transitions and continuing standby evidence are audited.
Four unresolved dispatch outcomes within 60 minutes open the circuit for a 60-minute cooldown and
enqueue one `circuit-open` alert for that episode. After cooldown, one half-open probe is allowed.
A confirmed probe closes the circuit; an ambiguous probe reopens it.

## Credentials, API limits, and alerts

Observation and reconciliation use a repository-scoped installation token with Actions read,
Contents read, and Metadata read. After the protected activation proof and durable post permit pass,
the controller mints a separate uncached token with Actions write immediately before the single
dispatch request. Tokens, private keys, HMAC keys, authorization headers, and reusable signatures
are never persisted or logged.

Every GitHub read has an exact allowlisted path and query, immutable security headers, a ten-second
timeout, bounded streaming response parsing, and at most three transient retries with exponential
backoff and jitter. The dispatch client is operation-specific and makes exactly one POST. It accepts
only the exact 200 receipt whose API and HTML URLs bind the returned run ID and repository.

Failure evidence and a deterministic sanitized alert ID/body commit atomically before alert
delivery. The alert signature is derived only at delivery time and is never stored. Sink failure
leaves the evidence and outbox item intact for a bounded retry with the same idempotency ID. Observe
mode persists and logs its result without requiring a live alert sink.

The deterministic test harness instantiates the actual `ReleaseHealthControllerObject` against
SQLite and covers request validation, serialization, rollback, restart before and after permit
consumption, provider indexing lag, at-most-one dispatch, outbox retry, circuit recovery, standby,
digest invalidation, and audit-chain continuity.
