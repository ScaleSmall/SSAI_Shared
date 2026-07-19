# Release credential boundaries

Scale Small AI release automation must use separate, expiring credentials for
separate targets. Never restore `SCALESMALL_PAT` as a fallback and never reuse a
credential across the producer, consumer mutation, and health-monitor paths.

## SSAI_Shared repository secrets

| Secret | Repository access | Minimum use |
| --- | --- | --- |
| `SSAI_DASHBOARD_DISPATCH_TOKEN` | `ScaleSmall/SSAI_Dashboard` only | Send the `shared-updated` repository dispatch. Fine-grained repository `Contents: write` is required by GitHub for this endpoint. |
| `SSAI_CONNECT_DISPATCH_TOKEN` | `ScaleSmall/SSAI_Connect` only | Send the explicitly authorized Connect dispatch after TikTok review. Keep this secret absent while the reviewer deployment is protected. Do not share it with Dashboard automation. |
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
target. Rotate each credential independently and revoke the legacy broad PAT after no
remaining workflow references it. Secret values must never be written to logs, source,
workflow artifacts, command-line arguments, or remote URLs.
