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

The permanent legacy Shared propagation hold is separate from bounded production activation.
Follow [Shared propagation retirement](./SHARED_PROPAGATION_RETIREMENT.md). Workflow `247016064`
must remain disabled and has no reactivation or recovery path.
