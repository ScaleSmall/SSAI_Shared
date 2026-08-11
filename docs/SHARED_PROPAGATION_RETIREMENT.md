# Shared propagation retirement

## Decision

The legacy `Propagate to consumer apps` GitHub Actions workflow is permanently retired. Its
workflow file remains only as an inert tombstone so GitHub retains workflow identity
`247016064` at `.github/workflows/propagate.yml`.

Shared package adoption and deployment belong to consumer-owned protected workflows and
reviewed pull requests. The retired workflow must not dispatch cross-repository events or hold
credentials that can mutate a consumer repository.

## Fail-closed tombstone contract

The workflow source is intentionally minimal and must retain all of these properties:

- The only trigger declaration is `workflow_dispatch`, retained solely to keep the workflow
  registered at its existing path.
- Repository permissions are empty: `permissions: {}`.
- Exactly one job exists, and its job-level condition is the constant expression
  `if: ${{ false }}`.
- The unreachable step exits unsuccessfully as a second containment boundary if the job gate is
  ever changed without the source digest and static contracts also changing.
- There are no push, pull request, schedule, or repository-dispatch triggers.
- There are no tokens, secrets, API calls, dispatch endpoints, or named consumer repository
  targets.

The exact LF-normalized tombstone source SHA-256 is
`28650c6de12cfc94c165b2cb9c3dab1cb6bf1caf8de3815d67cf8bbe6c6b9ba2`.

## Permanent disabled hold

GitHub workflow `247016064` must remain in the exact `disabled_manually` state. The organization
release-health monitor verifies the workflow ID, display name, path, repository, disabled state,
and current-main source digest before classifying it as an authorized disabled workflow hold.

The hold is inventory evidence only. It is not recovery evidence and cannot suppress, supersede,
or repair a failed workflow run or check. A missing workflow, changed identity, enabled state, or
source-digest mismatch fails closed in release health.

## No reactivation or recovery path

Do not enable or manually dispatch this workflow. There is no rollback procedure that restores
its former cross-repository token or dispatch behavior.

If a future product requirement needs shared-package propagation, design a new consumer-owned,
least-privilege delivery path and ship it through normal protected review as a new workflow. Do
not reactivate workflow `247016064` or add credentials, repository dispatches, consumer targets,
or automatic triggers to its tombstone.

Any maintenance change to the tombstone must preserve these inert properties and update the exact
source digest and its static assertions in the same independently reviewed protected pull request.

## Credential decommission

The retirement is not complete while the legacy `SCALESMALL_PAT` Actions secret remains stored in
`ScaleSmall/SSAI_Shared`. Its name is still present in the repository secret inventory even though
the tombstone no longer references it.

After the tombstone is merged through protection and its exact-main hosted checks are green:

1. Reconfirm that no current-main SSAI_Shared workflow references `secrets.SCALESMALL_PAT`.
2. Identify the underlying credential owner and remaining authorized consumers without exposing
   the secret value.
3. Delete the `SCALESMALL_PAT` Actions secret from `ScaleSmall/SSAI_Shared`.
4. If the underlying PAT was dedicated to this retired path, revoke it. If an independently
   verified system still depends on that credential, rotate or reduce its scope for only those
   remaining consumers and record that disposition outside this repository.
5. Re-query the SSAI_Shared Actions secret inventory and retain evidence that
   `SCALESMALL_PAT` is absent.

Do not create a replacement cross-repository PAT. Do not delete or rotate an unidentified shared
credential until its remaining consumers have been verified. The source retirement can merge
before this external credential action, but the operational retirement must stay open until both
the repository secret removal and the underlying credential disposition are proven.

## Verification evidence

Before release, require all of the following on the exact proposed head:

1. `npm run check:workflows`
2. `npm run check:contracts`
3. `npm run check:production-readiness`
4. A clean secret scan and `git diff --check`
5. Exact-head approval from the required protected reviewer and terminal-green hosted checks

After the protected merge, confirm GitHub still reports workflow ID `247016064`, the same name and
path, and state `disabled_manually`. The next natural release-health schedule must classify the
workflow as an authorized disabled hold with the exact tombstone digest.
