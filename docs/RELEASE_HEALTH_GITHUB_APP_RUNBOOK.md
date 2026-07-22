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
4. Install the App on **only** the active, non-archived `ScaleSmall/SSAI_*` repositories used by
   the release-health inventory. Exclude `SSAI_Connect` and every unrelated repository.
5. Generate one private key for the App. Store the downloaded PEM securely until it has been
   added to GitHub Actions, then remove the local plaintext copy.

The monitor independently inventories every repository visible to its installation token. It
fails closed if the installation includes an out-of-scope repository or if the protected
expected-inventory SHA-256 does not match the exact visible set.

## Configure the protected environment

In the `release-health-monitor` environment for `ScaleSmall/SSAI_Shared`, add:

- `SSAI_RELEASE_MONITOR_APP_CLIENT_ID`: the App's Client ID from its settings page.
- `SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY`: the complete generated PEM private key.

Keep the existing `SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256` and
`SSAI_RELEASE_MONITOR_STATE_HMAC_KEY` environment secrets unchanged.

## Release and UAT

1. Keep the release-health workflow disabled while the App, installation, and environment
   secrets are being provisioned.
2. Merge the reviewed authentication change only after all repository contract and security
   checks pass.
3. A disabled workflow does not respond to `workflow_dispatch`. After the App is installed and
   both protected-environment secrets exist, enable the workflow immediately after a 15-minute
   schedule boundary, dispatch one current-default-branch `incident` scan, confirm that the run
   was created, and disable the workflow again before the next boundary. Require an exact
   168-hour scan and a terminal successful conclusion.
4. After that incident is green, re-enable the workflow and monitor consecutive scheduled runs.
   Require a changed state to persist successfully and the following unchanged state to be
   suppressed without hiding a changed or recovered condition. Disable the workflow immediately
   if either run fails.
5. Leave the schedule enabled only after both hosted checks pass.

The pinned token action revokes its installation token during job cleanup. Never enable
`skip-token-revoke`.
