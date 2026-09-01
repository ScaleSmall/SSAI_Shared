# Release-health controller

This zero-runtime-dependency Cloudflare Worker is checked in with `MODE=observe`. It is deployed
only through the protected `deploy-release-health-controller.yml` workflow. The custom domain is
`release-health-controller.scalesmall.ai`, `workers.dev` is disabled, and the only public
surface is exact `GET https://release-health-controller.scalesmall.ai/healthz` with no query.
The one-minute schedule evaluates logical slots at minutes 1, 16, 31, and 46 only during ages 10
through 14, after the full native grace period. This creates five bounded recovery opportunities
for a prepared request without extending the admission window.

## Public liveness contract

The scheduled Durable Object commits a completed runtime heartbeat after every evaluation,
including a sanitized terminal-failure result. `/healthz` returns only schema version, component,
observe/active mode, last completed and scheduled timestamps, last decision, source/profile
digests, pending/dead alert counts, and four boolean checks. It returns 200 only when the current
source/profile heartbeat is no more than 300 seconds old, no alert is dead, and the last evaluation
has no terminal failure. Missing, stale, generation-mismatched, dead-alert, and terminal-failure
states return 503. Responses are non-cacheable and contain no credentials, activation proof,
request identity, provider URL, or audit/outbox body. All other public paths, hosts, methods, and
queries fail closed. `/evaluate` remains reachable only through the Durable Object binding.

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
digest invalidation, audit-chain continuity, runtime-heartbeat ordering, public-route exactness,
staleness, every terminal failure class, and dead-alert liveness.

## Protected deployment and rollback

The deployment workflow accepts only `deploy-observe`, `deploy-active`, or
`rollback-observe` against an exact protected-main SHA. It serializes production operations,
uses the `release-health-controller-production` GitHub environment, pins Wrangler 4.127.1,
checks exact source/profile/config digests, converts either PKCS#1 or PKCS#8 input to validated
PKCS#8 without logging it, and probes the repository-scoped GitHub App before Cloudflare changes.
Observe mode requests only Actions read and binds only the App client ID, private key, and
installation ID. Active mode separately requests an Actions-write installation token but performs
only read probes, requires the alert gateway health check, and only then binds the admission key,
alert-signing key, and activation proof.

Deployment uses a temporary mode-bound configuration and secret file with restrictive
permissions. Observe deployment explicitly removes all active-only bindings before creating its
attested final version. Acceptance requires the exact custom domain, one-minute cron, recent
Cloudflare deployment, current source/profile/mode, and a healthy completed tick. Rollback accepts
only an exact version whose observe mode, protected-main attestation, source/profile/config digests,
Durable Object binding, and absence of active-only bindings are proven before mutation. A failed
post-deployment check automatically restores that attested observe version. Rollback does not
delete or recreate Durable Object storage and never dispatches a GitHub workflow.

Final acceptance reads the sole live Cloudflare deployment and requires exactly one version at
100 percent traffic. It then retrieves that exact immutable version and matches its ID, protected
SHA tag and message, mode, source/profile/config digests, Durable Object binding, runtime settings,
and health response. Split traffic, multiple live versions, or a newer unrecognized mutation fails
closed.

The explicit `bootstrap` input is valid only with `deploy-observe`. It fails closed unless official
Cloudflare API evidence proves the named Worker has no deployments, versions, settings, schedules,
custom domain, or service traffic. Bootstrap uploads one immutable SHA-tagged observe candidate,
proves its preview health contract, exact digests, Durable Object binding, and absence of active
secrets before promotion, and then creates the exact domain and cron. If post-promotion validation
fails, the workflow removes only the exact domain and cron whose pre-run absence it proved. It
leaves the Worker/version evidence intact and never deletes an existing Worker.

Required deployment-environment secrets are:

- `SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID`
- `SSAI_RELEASE_CONTROLLER_CLOUDFLARE_API_TOKEN`
- `SSAI_RELEASE_CONTROLLER_GITHUB_APP_CLIENT_ID`
- `SSAI_RELEASE_CONTROLLER_GITHUB_APP_PRIVATE_KEY`
- `SSAI_RELEASE_CONTROLLER_GITHUB_INSTALLATION_ID`

Active mode additionally requires:

- `SSAI_RELEASE_CONTROLLER_ADMISSION_HMAC_KEY`
- `SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY`
- `SSAI_RELEASE_CONTROLLER_ACTIVATION_PROOF`

The admission HMAC value must exactly match the independently protected
`release-health-fallback-admission` environment value. Never copy secret values into workflow
inputs, logs, repository variables, artifacts, or deployment evidence.
