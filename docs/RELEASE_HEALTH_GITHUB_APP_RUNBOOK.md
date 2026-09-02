# Release-health GitHub App runbook

The release-health monitor uses a short-lived GitHub App installation token. Do not provision
`SSAI_RELEASE_MONITOR_READ_TOKEN`, reuse `SCALESMALL_PAT`, or use a classic `repo`-scoped PAT.

## Create and install the App

1. Create a private GitHub App owned by the `ScaleSmall` personal account.
2. Disable webhooks. The monitor does not receive events.
3. Grant repository permissions only:
   - Actions: Read-only
   - Checks: Read-only
   - Contents: Read-only
   - Deployments: Read-only
   - Metadata: Read-only
   - Pull requests: Read-only
   - Commit statuses: Read-only
4. Install the App on **only** every active, non-archived `ScaleSmall/SSAI_*` repository used by
   the release-health inventory, including `SSAI_Connect`. Exclude every archived, non-`SSAI_*`,
   and unrelated repository. The retired TikTok reviewer demo and tunnel are not repositories
   in this inventory and must remain retired.
5. Generate one private key for the App. Store the downloaded PEM securely until it has been
   added to GitHub Actions, then remove the local plaintext copy.

The monitor independently inventories every repository visible to its installation token. It
fails closed if the installation includes an out-of-scope repository or if the protected
expected-inventory SHA-256 does not match the exact visible set.

## Configure the protected environment

In the `release-health-monitor` environment for `ScaleSmall/SSAI_Shared`, add:

- `SSAI_RELEASE_MONITOR_APP_CLIENT_ID`: the App's Client ID from its settings page.
- `SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY`: the complete generated PEM private key.

Whenever the exact reviewed repository set changes, recompute its canonical inventory digest
with the monitor's `expectedInventoryDigest()` algorithm and update
`SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256` in the same controlled change window as the App
installation scope. For the reviewed 21-repository inventory that includes `SSAI_Connect`, the
required digest is `1b0f98d54264554fdc81d3f7d5b89e2324f9660ebe15526e49e878d2a932df4b`.
Do not reuse the superseded 20-repository digest. Keep
`SSAI_RELEASE_MONITOR_STATE_HMAC_KEY` unchanged.

## Release and UAT

1. Keep the release-health workflow disabled while the App, installation, and environment
   secrets are being provisioned.
2. Merge the reviewed authentication change only after all repository contract and security
   checks pass.
3. After the App installation includes the exact reviewed inventory and the protected inventory
   digest is updated, enable the workflow before the next staggered 15-minute schedule boundary
   (minutes 9, 24, 39, and 54 UTC). Do not use `workflow_dispatch` as scheduler proof; require the
   first natural scheduled run on exact current `main` to finish successfully and report the
   complete reviewed inventory.
4. Monitor the following natural scheduled run. Require a changed state to persist successfully
   and the following unchanged state to be suppressed without hiding a changed or recovered
   condition. Disable the workflow immediately if either run fails.
5. Leave the schedule enabled only after both hosted checks pass.

The pinned token action revokes its installation token during job cleanup. Never enable
`skip-token-revoke`.

## Scheduler identity recovery

Use this procedure only after an unchanged workflow identity has missed multiple natural schedule
boundaries and both supported repository-side registration recoveries have failed: a reviewed cron
change on the default branch and one verified disable-enable cycle with zero active or queued runs.
Do not repeat either recovery without new evidence.

The recovery uses two protected merges because GitHub assigns the replacement numeric workflow ID
only after a new workflow path exists on the default branch.

### Stage 1: prove a new scheduler identity

1. Add `.github/workflows/release-health-monitor-v3.yml` as the exact inert canary with normalized
   source SHA-256 `3fe965ac8e77c17640fbc89633c230639c83d2e4e3ba0d43c9c50195338ce825`.
2. Keep the canary schedule-only at minutes 1, 16, 31, and 46 UTC. It must have empty permissions,
   no manual trigger, no secrets, no token, no checkout, no third-party action, no network access,
   a two-minute timeout, and its own non-cancelling concurrency group.
3. Keep the current full monitor unchanged. The canary is read-only and cannot reconcile issues or
   alter release-health state.
4. Merge only through normal branch protection after exact-head approval and hosted validation.
5. Query the Actions workflow inventory and require a distinct numeric ID at the exact new path in
   `active` state.
6. Require two successful natural `schedule` runs from the current `main` SHA. A manual, push, or
   pull-request run is not acceptance evidence. Retain the run IDs, attempts, timestamps, workflow
   ID, path, head SHA, event, job conclusion, and the canary's verified repository/ref/SHA output.

If the new identity does not produce natural runs, do not promote it or retire the current monitor.
Classify the scheduler as an external GitHub delivery failure and retain all completed evidence.

### Stage 2: promote the proven identity

1. Before the change window, require zero queued or in-progress runs for both the current monitor
   and the canary. Do not cancel a state-writing or issue-writing run to accelerate the cutover.
2. In one protected change, replace the canary content at the same path with the full hardened
   monitor and remove the schedule trigger from the old workflow identity. Do not leave two full
   incident writers scheduled.
3. Pin the newly observed numeric workflow ID, exact path, normalized workflow digest, repository,
   event allowlist, job name, run title, and default-branch provenance in the monitor policy and its
   contract tests. Preserve the old identity as an immutable predecessor or tombstone contract.
4. Preserve the existing cache path, compatible cache action, restore prefixes, HMAC epoch, and
   content verification. Cache data remains untrusted until its HMAC and exact provenance pass.
   Never cache credentials.
5. Preserve the managed issue title, label, marker, and delivery identity so issue `#24` is updated
   or closed in place instead of creating a duplicate.
6. Merge only through normal branch protection after exact-head approval, focused contracts, the
   complete production-readiness gate, and hosted validation.
7. Require the first natural full-monitor run to restore authenticated state and reconcile issue
   `#24`. Require the next natural run to prove unchanged-state suppression without hiding a changed
   or recovered condition.
8. Disable or permanently tombstone the superseded workflow identity only after all acceptance
   evidence above is complete and no old-identity run is active or queued.

Rollback is also protected. Revert the activation change through a reviewed pull request, restore
the old schedule source before re-enabling the old identity, verify no new-identity run is active or
queued, and only then disable the new identity. Never edit `main` directly or run two scheduled
incident writers during rollback.

GitHub documents that scheduled events can be delayed or dropped. This recovery proves a healthy
workflow identity but is not a delivery-time service-level guarantee. Any future hard timing
requirement needs a separately reviewed independent scheduler and a least-privilege authenticated
entry point; it must not be simulated by manual dispatch.

## Independent scheduler failover registration

Use this path only when read-only evidence proves GitHub is not creating native `schedule` run
records after the bounded scheduler-identity recovery above. The fallback restores availability;
it never proves that GitHub's native scheduler recovered.

Stage F1 registers `.github/workflows/release-health-monitor-fallback.yml` with normalized source
SHA-256 `7dc0169828e640614cbced70dc21594ee1cc605118cd81ab5e40cafeab2994ac`.
The source is intentionally inert: it has only an uninvoked `workflow_dispatch` registration
trigger, empty workflow and job permissions, the shared non-cancelling monitor concurrency group,
an unconditionally false job, no environment, no secrets, no action, no cache, no token, no
network access, and no write path. Never dispatch Stage F1.

Merge Stage F1 only through exact-head independent approval, hosted validation, and normal branch
protection. After merge, use the read-only workflow inventory to record the distinct numeric ID at
the exact fallback path and verify state `active`. Do not change, dispatch, disable, or reinterpret
the existing monitor or native canary while registering the fallback identity.

Stage F2 is a separate protected activation change. It must pin the observed fallback ID and exact
path, accept only a dedicated repository-scoped GitHub App, validate a fresh HMAC-signed slot and
request identity before accessing protected credentials, share the existing non-cancelling monitor
concurrency group, and preserve authenticated incident state plus stale issue-write fencing. The
independent controller must use strongly consistent per-slot idempotency, fail closed when native
freshness cannot be determined, start in observe-only mode, and enter standby only after two
consecutive exact native `schedule` runs. Every fallback run must be labeled as fallback and must
remain excluded from native scheduler proof.

Rollback is ordered: disable controller dispatch first, require zero queued or in-progress fallback
runs, disable the fallback workflow through the official API, and use a reviewed protected revert
if permanent retirement is intended. Preserve run and controller-ledger evidence. Never alter the
native cron or re-enable another workflow identity as part of fallback rollback.

## Protected F2b observe-only fallback activation

F2b activates workflow ID `344170407` at `.github/workflows/release-health-monitor-fallback.yml`
for authenticated `workflow_dispatch` only. Its exact checked-in SHA-256 is
`6fdb093c47e8631ea151b6f0a0aa5356db03c025a6813321f7f35e8bc6ed86b9`. Native workflow
`315630665` and canary `344135917` remain unchanged and retain their native-schedule-only proof
roles. A fallback run is never scheduler recovery evidence.

The fallback accepts exactly four routing inputs: packed base64url envelope, logical slot epoch
minute, request ID, and signature. The canonical envelope carries eleven fields in fixed order:
version, repository, repository ID, workflow ID, workflow path, ref, expected SHA, logical slot,
request ID, issued-at, and expires-at. The slot and request routing inputs must exactly duplicate
their signed envelope values. The canonical bytes are HMAC-authenticated with the domain
`ssai-release-health-fallback-envelope-v1\0` and uint32 big-endian length-delimited UTF-8 field
names and values. The request ID is 32 lowercase hexadecimal characters and the signature is 64.
The dedicated key is base64 encoding of at least 32 bytes and is distinct from the state key.
Actor login, actor ID, and event sender ID are separately pinned in the admission environment.

Admission validates repository ID `1183552904`, protected main, provider run attempt 1, exact main
SHA, normalized provider path, workflow identity, actor and sender, bounded expiry, logical slot,
request, and HMAC before checkout, cache, or monitor credentials. A minimal bootstrap fetches the
validator at the signed SHA, and checkout byte-compares that source before cache access. Every job
rejects reruns. The immutable slot claim uses its own HMAC domain and the exact slot only, and both
claim and authenticated state require exact post-save cache visibility.
Both native and fallback share the non-cancelling `scale-small-ai-release-health-monitor-v2`
`queue: max` group and `ssai-release-health-state-v6-v1-` namespace. Schema v6 authenticates its
recorded producer independently, so either authorized producer can restore the other's state.
Legacy v4, v3, v2, and v1 issue markers remain native historical formats.

The zero-dependency Cloudflare controller is under `workers/release-health-controller`. Its
canonical sorted-source digest is `7076478a2b98f986c153551942ce9698ad81c730cf02560b60e26e975c2b8379`.
Its activation-profile digest is
`7130eed4e555d404b150a8a71af1be6e5a4e5398e8a8179bae9059a0046f9615`. The checked-in
configuration is `MODE=observe`, exposes only exact public GET
`https://release-health-controller.scalesmall.ai/healthz`, disables `workers.dev`, and
schedules evaluation every minute. The health response has no secret or per-request state and
returns 503 when the current generation has no completed tick within 300 seconds, the last tick
has any terminal failure classification, or any alert is dead.
Logical slots are minutes 1, 16, 31, and 46. Evaluation occurs only at ages 10 through 14 minutes
to provide five bounded same-slot recovery opportunities, and never backfills a new dispatch. A
final exact native/canary lookup, stable main SHA, and one
unfiltered fallback inventory must pass before the durable prepare transition. Any exact native or
canary schedule run in the slot blocks fallback. Only two consecutive canary slots establish
persistent standby, and standby/resume evidence is transactionally audited.

The SQLite ledger binds every global slot to exact source and profile digests and uses the phases
`leased`, `prepared`, `post-attempted`, `unknown`, `confirmed`, and `terminal`. Prepared state holds
only unsigned request metadata. The atomic `prepared` to `post-attempted` transition consumes the
sole workflow POST permit before network access. A restart from `post-attempted` or `unknown` uses
exact request-ID GET reconciliation only, including after a source/profile generation change.
GitHub provides no dispatch idempotency key, so an uncertain attempt is never reposted. Bounded
delayed reconciliation tolerates provider indexing lag while retaining unresolved evidence.
A prepared request resumes only under its original exact digests. Any source/profile mutation
atomically terminalizes the unattempted request as `prepared-abandoned`, appends its chained audit
event, and enqueues its sanitized alert. The globally consumed slot is never reassigned.
A prepared row that survives beyond its admission window is terminalized and alerted on the next
minute tick. It is never dispatched from a later logical slot.
A lease interrupted before preparation is likewise terminalized and alerted as `lease-abandoned`;
no pre-network row remains nonterminal indefinitely.

Observe mode durably records `would_dispatch` and makes zero workflow dispatch POSTs. Two
consecutive observe slots under the same source/profile generation establish the protected
activation proof in the same transaction as the second terminal result and chained audit row.
Changing only `MODE` preserves the proof. Any effective source, policy, identity, cadence,
credential-epoch, HMAC-epoch, alert-epoch, or circuit-policy change invalidates it. Observation uses
a repository-scoped Actions-read installation token. Active dispatch mints a distinct uncached
Actions-write token only after proof and post-permit checks pass and immediately before the one
dispatch request.

Four unresolved attempts within 60 minutes open the durable circuit for a documented 60-minute
cooldown and enqueue one `circuit-open` alert for the episode. One half-open probe follows the
cooldown. Confirmation closes the circuit; ambiguity reopens it. Failure evidence and a sanitized
deterministic alert body commit before delivery. The HMAC signature is derived only at delivery
time and is never persisted. Sink failure leaves the original evidence and outbox record pending
for bounded retry under the same alert ID. Rollback first disables controller evaluation, then
proves no fallback run is queued or active, and only then disables the fallback workflow.

### Protected controller deployment

Deploy only with `.github/workflows/deploy-release-health-controller.yml` at an exact protected
`main` SHA. The `release-health-controller-production` environment must require production
review and contain the Cloudflare account/token plus the controller GitHub App client ID, private
key, and installation ID. Observe deployment binds only those three App credentials and requests
only Actions read, Contents read, and Metadata read. Do not provision the dispatch HMAC, alert key,
or activation proof to an observe deployment.

Run `scripts/verify-release-health-controller-deploy.mjs` to record the LF-normalized config
SHA-256 and current source/profile digests. Supply those exact non-secret values with
`deploy-observe`. The workflow pins Wrangler 4.127.1, converts the protected App key to PKCS#8
without logging it, performs read-only App and Cloudflare capability probes, uses a temporary
mode-bound config and secret file, and never invokes the fallback workflow. Acceptance requires
the exact custom domain, exact one-minute cron, a deployment newer than the operation start, and a
healthy current-generation tick. Retain the protected workflow run, deployment ID, version ID,
health body, domain record, cron record, source/profile/config digests, and approval as evidence.
The final gate admits verification attempts for 18 minutes because Cloudflare documents that new
or changed Cron Triggers can take up to 15 minutes to propagate globally. The protected step keeps
a separate six-minute hard-timeout margin for one fully bounded final attempt and its failure
handler. A timeout reports one closed, allowlisted verification stage without printing provider
responses, credentials, or URLs.

For the first deployment only, set `bootstrap=true` with `deploy-observe` and leave every rollback
input empty. The workflow accepts this path only when official Cloudflare responses prove the
Worker has no deployments, versions, settings, schedules, custom domain, or service traffic. It
uploads a SHA-tagged immutable observe candidate without active-only secrets, verifies its preview
health schema and exact source/profile/config/Durable Object bindings before traffic, promotes
that exact version, and then applies the exact domain and cron. If final verification fails, it
withdraws only the domain and cron proven absent before this run, preserves the Worker/version as
diagnostic evidence, and fails visibly. Never use bootstrap when any Worker history exists.
Containment treats only exact final readback as authoritative: receipt ambiguity does not excuse a
remaining trigger, and exact absence can prove convergence after a noncanonical delete receipt.

Active promotion is a separate `deploy-active` operation against the same protected source/profile
generation after two consecutive observe slots produced the exact activation proof. Before the
operation, the signed alert gateway health endpoint must be healthy and the dedicated fallback
admission environment must contain the same HMAC value and exact App actor/login/sender pins.
Active preflight requests an Actions-write installation token but exercises it only through
allowlisted GETs. Only the active-only step receives and binds
`SSAI_RELEASE_CONTROLLER_ADMISSION_HMAC_KEY`,
`SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY`, and
`SSAI_RELEASE_CONTROLLER_ACTIVATION_PROOF`. A missing, malformed, or mismatched prerequisite
fails before deployment.

For emergency code rollback, select `rollback-observe` with one exact known-good Cloudflare
version UUID, that version's recorded source/profile/config digests, and its protected-main
attestation SHA. The rollback config digest is independent of the current workflow config digest;
never substitute the current digest for it. Before mutation, the workflow proves the exact target
reports `MODE=observe`, carries the
expected signed deployment annotations and `SLOT_LEDGER` binding, and has no active-only binding.
Observe promotion explicitly removes all active-only bindings before creating the final attested
version. A failed post-deployment check automatically restores this pre-attested observe target.
The workflow uses Cloudflare version rollback rather than deletion or a fresh Durable Object
migration, then verifies liveness and the unchanged `SLOT_LEDGER` binding. It does not delete
controller storage, routes, schedules, or fallback history. Disabling the
fallback workflow remains a later ordered action after controller dispatch is disabled and zero
fallback runs are queued or active.

Every final deployment check requires the official live deployment to contain exactly one version
at 100 percent traffic. The workflow retrieves that exact version and matches its ID, protected SHA
tag/message, mode, source/profile/config bindings, Durable Object binding, global settings, and
health body. Split traffic, multiple live versions, or a newer external mutation fails closed.

While observe-only, exact fallback workflow ID `344170407` and its exact source digest have a
temporary no-history inventory allowance. It requires a successful current-main
`Validate shared package` push run from `.github/workflows/validate.yml` no older than 30 hours.
The allowance expires absolutely at `2026-09-30T23:59:59Z`, is recorded with
`recovery_evidence=false`, and cannot provide native recovery evidence. At or after the expiry,
missing fallback history becomes an unresolved no-history failure. Protected active-mode
activation must remove or allow this observe-only allowance to expire rather than extending it.

## Protected F2a release-health foundation

F2a hardens the existing native monitor without activating either alternate workflow. The current
authoritative incident producer remains workflow ID `315630665` at
`.github/workflows/release-health-monitor.yml`, and it is authorized only for the `schedule` event.
Its exact LF-normalized source SHA-256 is
`cc8371a32d055c7c515afd9dc947e486fc11d5e23fb609c1a4d74ff62048e1a2`.
Workflow ID `344135917` at `.github/workflows/release-health-monitor-v3.yml` remains the exact inert
scheduler canary. Workflow ID `344170407` at
`.github/workflows/release-health-monitor-fallback.yml` remains the exact inert fallback
registration. F2a explicitly rejects both alternate IDs as state producers and managed-issue
writers. Do not dispatch, promote, or reinterpret either alternate workflow during F2a.

The authoritative workflow uses the shared `scale-small-ai-release-health-monitor-v2` concurrency
group with `queue: max` and `cancel-in-progress: false`. The scan and delivery capabilities are
separate jobs. The scan job has only `contents: read`; it owns the protected environment, GitHub
App token, authenticated cache, and monitor execution. The delivery job has only `actions: read`,
`contents: read`, and `issues: write`; it receives an exact allowlist of non-sensitive scan outputs
and cannot read App credentials, HMAC material, state files, or caches. No artifact transfer is
allowed between the jobs. Delivery runs only after the scan job and required state persistence
succeed.

### Authenticated producer-neutral v6 state

Schema v6 authenticates both notification state and the actual producer execution. Every new
record includes the producer kind and policy, workflow ID and path, event, run ID, run attempt,
head SHA, and authoritative run creation time. The run creation time comes from the exact GitHub
Actions provider record selected by current run ID and attempt. It is never replaced with a runner
clock or an environment timestamp. The currently registered producer policy is
`native-schedule-v1`; it resolves only workflow `315630665`, the authoritative path, and event
`schedule`. The schema can represent a separately authorized future fallback producer without
mislabeling `workflow_dispatch` as `schedule`, but adding that policy is a later protected change.

Restore v6 first. Authenticated v4, v3, and v2 records are accepted only by their exact legacy
decoders and are immediately persisted as v6 even when the notification semantics did not change.
Unknown schemas, invalid HMACs, unexpected fields, unregistered producer identities, malformed run
provenance, and cache-key boundary mismatches fail closed into safe state reinitialization. Cache
keys remain non-sensitive and content-bound; credentials and raw failure evidence are never cached.

The authenticated producer tuple is also the state authority watermark. It is totally ordered by
provider creation time, numeric run ID, and run attempt. Older and equal candidates cannot persist,
migrate, or affect suppression. Every strictly newer accepted v6 producer advances the watermark,
even when incident semantics are unchanged, while preserving the prior semantic delivery identity.
This prevents an intermediate delayed run from overwriting state after a newer unchanged scan.
The provider run head SHA is bound to the executing run's immutable `GITHUB_SHA`; the separately
resolved live default-branch head may advance during the scan without invalidating that run proof.

### Managed issue ordering and marker upgrade

Managed issue delivery fetches the exact candidate and prior Actions run attempts through the
official run-attempt endpoint. It validates workflow policy, repository, branch, event, head SHA,
run ID, attempt, and provider creation time before any issue write. Competing deliveries are
ordered first by authoritative provider creation time, then run ID, then attempt. An older delivery
is suppressed, an exact replay is idempotent, and a conflicting exact replay requires operator
reconciliation. A valid legacy v1 delivery marker is read once and upgraded to the workflow-bound
v2 marker on the next authoritative reconciliation. Canary and fallback markers or run metadata
are rejected in F2a.

Immediately before every PATCH, delivery performs one exact issue re-read and revalidates the
managed title, marker, label, state, provider ordering, and desired body. If the marker is unchanged
but the body, state, state reason, title, label identity, or update timestamp changed since the
initial list read, delivery fails closed for operator reconciliation. A legitimately newer marker
is handled by one bounded provider-metadata prefetch followed by a second final exact issue read.
If the marker advances again, delivery fails closed. Otherwise the refreshed authority can
stale-suppress an older candidate, and a candidate newer than it may write once. No provider or
repository request occurs between the final validated issue read and PATCH, and there is no
open-ended retry loop.

### F2a acceptance evidence ledger

| Invariant | Correction | Negative regression | Positive control | Required result |
| --- | --- | --- | --- | --- |
| Native producer authority | Central producer policy pins ID `315630665`, path, and `schedule` | Authenticated canary, fallback, wrong-event, and malformed provenance fixtures | Exact provider record for the native run and attempt | Local focused tests pass |
| Provider-bound v6 provenance | Persist kind, policy, workflow, event, run, attempt, SHA, and provider `created_at` | Individually tampered signed fields and creation time after state creation | Exact signed v6 round trip | Local focused tests pass |
| Monotonic state authority | Total-order authenticated producer authority and persist every strictly newer watermark | Older changed rerun after a newer unchanged scan | Newer unchanged scan persists while preserving semantic delivery identity | Local focused tests pass |
| Safe state migration | Separate HMAC-authenticated v4, v3, and v2 decoders force v6 persistence | Wrong schema, HMAC, fields, cache prefix, branch, and workflow | Exact v4, v3, and v2 migrations | Local focused tests pass |
| Least-privilege split | Isolated scan and delivery jobs with allowlisted outputs | Write permission, secret handoff, extra output, wrong path, and artifact mutations | Exact workflow contract | Local workflow contract passes |
| Lossless state ordering | Shared concurrency adds `queue: max` without cancellation | Missing queue mutation | Exact authoritative workflow source | Local workflow contract passes |
| Stale issue-write fence | Exact-attempt validation and provider ordering precede every mutation | Stale, deleted-prior, mismatched-attempt, canary, fallback, and conflict fixtures | Newer delivery, exact replay, and v1 upgrade | Local focused tests pass |
| Immediate issue mutation fence | Prefetch authority, then make the final exact issue read directly adjacent to PATCH | Body or timestamp drift, equal conflict, stale candidate, or a second marker advance | Newer candidate after one bounded marker prefetch writes once | Local focused tests pass |
| Inert alternate workflows | Exact source and digest locks remain on canary and fallback registration | Trigger, permission, action, secret, network, and execution mutations | Byte-identical checked-in sources | Local workflow contract passes |

This ledger records local foundation evidence only. It does not activate the fallback, promote the
canary, or substitute for the protected merge, hosted validation, and natural-run evidence required
by a later activation stage.

The permanent legacy Shared propagation hold is separate from bounded production activation.
Follow [Shared propagation retirement](./SHARED_PROPAGATION_RETIREMENT.md). Workflow `247016064`
must remain disabled and has no reactivation or recovery path.
