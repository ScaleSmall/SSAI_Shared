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
   (minutes 3, 18, 33, and 48 UTC). Do not use `workflow_dispatch` as scheduler proof; require the
   first natural scheduled run on exact current `main` to finish successfully and report the
   complete reviewed inventory.
4. Monitor the following natural scheduled run. Require a changed state to persist successfully
   and the following unchanged state to be suppressed without hiding a changed or recovered
   condition. Disable the workflow immediately if either run fails.
5. Leave the schedule enabled only after both hosted checks pass.

The pinned token action revokes its installation token during job cleanup. Never enable
`skip-token-revoke`.

The permanent legacy Shared propagation hold is separate from bounded production activation.
Follow [Shared propagation retirement](./SHARED_PROPAGATION_RETIREMENT.md). Workflow `247016064`
must remain disabled and has no reactivation or recovery path.
