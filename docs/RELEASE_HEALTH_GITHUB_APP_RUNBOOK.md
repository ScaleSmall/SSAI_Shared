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
