# Release credential boundaries

Scale Small AI release automation must use separate, expiring credentials for
separate targets. Never restore `SCALESMALL_PAT` as a fallback and never reuse a
credential across the producer, consumer mutation, and health-monitor paths.

## SSAI_Shared repository secrets

| Secret | Repository access | Minimum use |
| --- | --- | --- |
| `SSAI_DASHBOARD_DISPATCH_TOKEN` | `ScaleSmall/SSAI_Dashboard` only | Read the exact Dashboard main/consumer workflow and Actions state, then send `shared-updated`. Grant only repository `Contents: write` (which includes the required read access) and `Actions: read`; no administration, secrets, environments, pull-request, or other repository access. |
| `SSAI_CONNECT_DISPATCH_TOKEN` | `ScaleSmall/SSAI_Connect` only | Send the explicitly authorized Connect dispatch after TikTok review. Fine-grained repository `Contents: write` is required for repository dispatch. Keep this secret absent while the reviewer deployment is protected. Do not share it with Dashboard automation. |
| `SSAI_RELEASE_MONITOR_READ_TOKEN` | Selected in-scope `ScaleSmall/SSAI_*` repositories only | Read repository metadata, contents/workflows, Actions, checks, statuses, deployments, branches, and pull-request associations for release-health reconciliation. It must have no write permission. |

The Connect input defaults to false. An absent Connect credential must never block
Dashboard propagation, and an operator must not enable that input until the protected
review deployment is expressly released.

## SSAI_Dashboard repository secrets

| Secret | Repository access | Minimum use |
| --- | --- | --- |
| `SSAI_DASHBOARD_AUTOMATION_TOKEN` | `ScaleSmall/SSAI_Dashboard` only | Publish the proved automation branch and create/update its pull request so ordinary PR validation workflows fire. Contents write and pull-requests write only. |

`ScaleSmall/SSAI_Shared` is public. Dashboard workflows must fetch it without a
credential over canonical HTTPS and verify its exact authoritative `main` SHA. Do not
add a Shared read token or an authenticated Git URL. The publish job must run on a
fresh runner, execute no repository-controlled code, reproduce the tested tree, and
inject the Dashboard mutation credential only after all exact-SHA/tree proofs pass.
The built-in Actions token may create the supplemental exact-head Check Run, but it
must not publish the branch or pull request.

## Provisioning and rotation evidence

Before release, record the token owner, selected repository, exact permissions,
creation and expiration dates, secret update timestamp, and a redacted API preflight
showing that each token can reach its intended endpoint and cannot reach a different
target. Negative-scope proof is mandatory: the Dashboard dispatch credential must not
reach another repository and must not mutate branches, pull requests, Actions state,
secrets, or administration settings. Secret values must never be written to logs,
source, workflow artifacts, command-line arguments, or remote URLs.

## Mandatory Dashboard v2 release interlock

The reviewed producer/consumer pair is immutable:

- Dashboard default branch: `main`
- Dashboard commit: `ca31240527c5a60d3041f8efa41cb8767654db1a`
- Dashboard deterministic build SHA-256: `08c6cde1ec084db3e7fc747ee086708965d7e33fd2b667513b14702dd8679993`
- Consumer path: `.github/workflows/update-shared.yml`
- Consumer file SHA-256 over the exact Git blob bytes: `221bcc96c02dc1f272f8aee663b0d20e71f4cc345b414bbbb835a674a72b3af1`
- Dispatch payload: exact numeric schema v2 with only `ref`, `repository`,
  `schema_version`, `sha`, and `source_ref`; a digest is release evidence and is
  deliberately not a payload key.

Do not release while GitHub Actions is billing-blocked. Do not rerun any historical
`Propagate to consumer apps` or `Update shared package` run. A rerun executes historical
workflow source and is not a valid release. Start only a new `workflow_dispatch` from
current Shared `main`; both producer and witnessed consumer must have `run_attempt=1`.

Perform this sequence without reordering or collapsing the drains:

1. Leave Dashboard `update-shared.yml`, Shared `propagate.yml`, and Shared
   `release-health-monitor.yml` disabled. Provision the dedicated credentials, record
   their redacted positive/negative-scope receipts, and do not restore `SCALESMALL_PAT`
   as a fallback.
2. Record a first drain receipt for every `queued`, `in_progress`, `waiting`,
   `requested`, and `pending` run of all three workflows. Wait for or cancel only the
   explicitly identified runs, then record a second zero-count drain receipt with UTC
   timestamp and workflow id.
3. Advance Dashboard `main` to the exact reviewed commit above while its consumer is
   still disabled. Prove the default branch, exact commit, deterministic build receipt,
   exact consumer path and SHA-256. If Dashboard main is any other commit, stop and review/re-pin a new Shared
   producer commit; never weaken the comparison.
4. With Dashboard consumer still disabled, take another pre-deletion drain receipt,
   delete the Dashboard repository secret named `SCALESMALL_PAT`, and take a
   post-deletion zero-count drain plus secret-name-absence receipt. Historical unsafe
   Dashboard runs must therefore have neither an active run nor their credential.
5. Merge the reviewed Shared successor while Shared propagation and monitoring remain
   disabled. The intentionally dropped push event is not replayed. Take another Shared
   pre-deletion drain receipt, delete Shared's `SCALESMALL_PAT`, then record the
   post-deletion zero-count drain and secret-name-absence receipt. Confirm only the
   dedicated token names required above remain.
6. Enable only the exact Dashboard consumer, the exact Shared producer, and the
   hardened Shared health monitor. Confirm their workflow paths and `active` states.
   The producer itself rechecks Dashboard default-main SHA, exact workflow bytes/state,
   and all nonterminal run counts immediately before dispatch.
7. Start one new Shared `workflow_dispatch` from current `main` with
   `dispatch_connect=false`. Never use GitHub's rerun button. Require the exact five-key
   v2 request, HTTP 204 acceptance, and exactly one new attempt-one Dashboard run on
   commit `ca31240527c5a60d3041f8efa41cb8767654db1a`, observed twice across the settling
   window. A missing, duplicate, stale, rerun, wrong-path, or wrong-SHA witness fails
   closed.
8. Retain the drain, credential, producer-run, consumer-run, PR, exact-head check, and
   final full-gate receipts together. Remove Dashboard's temporary legacy-v1 reader
   only in a separately reviewed consumer/producer generation after this production v2
   witness succeeds.

The producer is idempotent by immutable Shared SHA and non-cancelling concurrency, and
the Dashboard consumer owns one bounded automation branch/PR. An uncertain dispatch
POST is never retried. If the producer loses the HTTP response, inspect and drain the
consumer first, then start a new current-main workflow_dispatch; never rerun the failed
attempt. If any pin, digest, workflow state, drain, token, or witness check fails, disable
the producer and consumer, preserve receipts, and roll back only to the last fully
attested dedicated-token producer/consumer pair. Never roll back to the legacy direct-
write workflow and never restore the broad PAT.
