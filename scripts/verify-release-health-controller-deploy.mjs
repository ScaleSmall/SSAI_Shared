import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { activationProfileDigest } from '../workers/release-health-controller/src/activation-profile.mjs';

const root = new URL('../', import.meta.url);
const sourceDirectory = new URL('workers/release-health-controller/src/', root);
const configUrl = new URL('workers/release-health-controller/wrangler.jsonc', root);
const workflowUrl = new URL('.github/workflows/deploy-release-health-controller.yml', root);

const sourceHash = createHash('sha256');
for (const name of (await readdir(sourceDirectory)).sort()) {
  const source = (await readFile(new URL(name, sourceDirectory), 'utf8')).replace(/\r\n?/g, '\n');
  sourceHash.update(name + '\0').update(source).update('\0');
}
const sourceDigest = sourceHash.digest('hex');
const configText = (await readFile(configUrl, 'utf8')).replace(/\r\n?/g, '\n');
const configDigest = createHash('sha256').update(configText).digest('hex');
const config = JSON.parse(configText);
const profileDigest = await activationProfileDigest({
  ...config.vars,
  CONTROLLER_SOURCE_SHA256: sourceDigest,
});
const workflow = (await readFile(workflowUrl, 'utf8')).replace(/\r\n?/g, '\n');

assert.equal(config.name, 'ssai-release-health-controller');
assert.equal(config.main, 'src/index.mjs');
assert.equal(config.workers_dev, false);
assert.equal(config.preview_urls, true);
assert.deepEqual(config.routes, [{
  pattern: 'release-health-controller.scalesmall.ai',
  custom_domain: true,
}]);
assert.deepEqual(config.triggers?.crons, ['* * * * *']);
assert.equal(config.observability?.enabled, true);
assert.equal(config.observability?.head_sampling_rate, 1);
assert.equal(config.observability?.logs?.enabled, true);
assert.equal(config.observability?.logs?.head_sampling_rate, 1);
assert.equal(config.observability?.logs?.invocation_logs, true);
assert.equal(config.vars.MODE, 'observe');
assert.equal(config.vars.HEALTH_ROUTE, 'https://release-health-controller.scalesmall.ai/healthz');
assert.equal(config.vars.HEALTH_STALE_AFTER_SECONDS, '300');
assert.equal(config.vars.CONTROLLER_SOURCE_SHA256, sourceDigest);
assert.equal(config.vars.CONTROLLER_ACTIVATION_PROFILE_SHA256, profileDigest);
assert.deepEqual(config.durable_objects?.bindings, [{
  name: 'SLOT_LEDGER',
  class_name: 'ReleaseHealthControllerObject',
}]);
assert.deepEqual(config.migrations, [{
  tag: 'v1',
  new_sqlite_classes: ['ReleaseHealthControllerObject'],
}]);

for (const required of [
  'environment:\n      name: release-health-controller-production',
  'group: release-health-controller-production-deployment',
  'cancel-in-progress: false',
  'github.ref_protected == true',
  'github.workflow_sha == inputs.expected_sha',
  'node_modules/wrangler/package.json',
  "p.version!=='4.127.1'",
  'openssl pkey -in "$RUNNER_TEMP/github-app-input.pem"',
  'Admission key',
  'Alert key',
  'rollback_attestation_sha:',
  'rollback_config_sha256:',
  'bootstrap:',
  'Prove bootstrap has no Worker history or traffic',
  'Upload and preverify immutable bootstrap observe candidate',
  'wrangler versions upload',
  'wrangler versions deploy "$CANDIDATE_VERSION_ID@100%"',
  'Contain failed first deployment without deleting Worker history',
  'Verify exact attested observe rollback target',
  'protected-observe:',
  "permissionMode = process.env.OPERATION === 'deploy-active' ? 'write' : 'read'",
  "'/repos/ScaleSmall/SSAI_Shared/commits/main'",
  "'/repos/ScaleSmall/SSAI_Shared/actions/workflows/344170407/runs?event=workflow_dispatch&branch=main&per_page=100'",
  'https://alerts.scalesmall.ai/healthz',
  '--secrets-file "$RUNNER_TEMP/controller-secrets.json"',
  'wrangler rollback "$ROLLBACK_VERSION_ID"',
  'wrangler secret delete "$key"',
  'Remove every active-only binding from observe mode',
  'Finalize attested observe version after active-secret removal',
  'automatic-safe-rollback',
  'Conclude exact operation and safe rollback outcome',
  'release-health-controller.scalesmall.ai',
  '"* * * * *"',
  'durable_object_namespace',
  'rm -f --',
]) assert.ok(workflow.includes(required), 'Missing deploy contract: ' + required);

assert.doesNotMatch(workflow, /gh\s+workflow\s+run|actions\/workflows\/\d+\/dispatches|curl[^\n]+\/dispatches/i);
assert.doesNotMatch(workflow, /wrangler\s+(?:delete|triggers\s+delete)/i);
assert.match(workflow, /options: \[deploy-observe, deploy-active, rollback-observe\]/);
assert.ok(workflow.includes('.schema == "ssai-release-health-controller-health-v1"'));
assert.ok(workflow.includes('.checks.no_terminal_failure == true'));
assert.match(workflow, /if test "\$BOOTSTRAP" = true; then\n\s+test "\$OPERATION" = deploy-observe/);
assert.match(workflow, /test -z "\$ROLLBACK_VERSION_ID\$ROLLBACK_SOURCE\$ROLLBACK_PROFILE\$ROLLBACK_CONFIG\$ROLLBACK_ATTESTATION_SHA"/);
assert.match(workflow, /\[\[ "\$ROLLBACK_CONFIG" =~ \^\[a-f0-9\]\{64\}\$ \]\]/);

const bootstrapAbsenceStep = workflow.split(
  '      - name: Prove bootstrap has no Worker history or traffic',
)[1].split('      - name: Prepare and validate runtime credentials without disclosure')[0];
assert.match(bootstrapAbsenceStep, /if: \$\{\{ inputs\.bootstrap \}\}/);
for (const resource of ['deployments', 'versions', 'settings', 'schedules']) {
  assert.ok(bootstrapAbsenceStep.includes(resource));
}
assert.match(bootstrapAbsenceStep, /test "\$code" = 404/);
assert.match(bootstrapAbsenceStep, /release-health-controller\.scalesmall\.ai/);

const bootstrapCandidateStep = workflow.split(
  '      - name: Upload and preverify immutable bootstrap observe candidate',
)[1].split('      - name: Verify exact attested observe rollback target')[0];
assert.match(bootstrapCandidateStep, /inputs\.bootstrap && steps\.bootstrap_absence\.outcome == 'success'/);
assert.match(bootstrapCandidateStep, /wrangler versions upload/);
assert.match(bootstrapCandidateStep, /--preview-alias/);
assert.match(bootstrapCandidateStep, /protected-observe:/);
assert.match(bootstrapCandidateStep, /CONTROLLER_CONFIG_SHA256/);
assert.match(bootstrapCandidateStep, /bootstrap-preview-health\.json/);
assert.match(bootstrapCandidateStep, /test "\$code" = 503/);
for (const name of ['ADMISSION_HMAC_KEY', 'ALERT_SIGNING_KEY', 'ACTIVATION_PROOF']) {
  assert.match(bootstrapCandidateStep, new RegExp(`\\.name != "${name}"`));
}

const jobEnvironment = workflow.split('    env:\n')[1].split('    steps:\n')[0];
assert.doesNotMatch(jobEnvironment, /CLOUDFLARE_(?:ACCOUNT_ID|API_TOKEN)/);
for (const name of ['Install exact locked toolchain', 'Verify exact source and deployment contracts']) {
  const step = workflow.split(`      - name: ${name}\n`)[1].split('\n      - name: ')[0];
  assert.doesNotMatch(step, /CLOUDFLARE_(?:ACCOUNT_ID|API_TOKEN)/);
}
const baseSecretStep = workflow.split(
  '      - name: Prepare and validate runtime credentials without disclosure',
)[1].split('      - name: Validate and bind active-only dispatch credentials')[0];
assert.doesNotMatch(baseSecretStep, /ADMISSION_HMAC_KEY|ALERT_SIGNING_KEY|ACTIVATION_PROOF/);
const activeSecretStep = workflow.split(
  '      - name: Validate and bind active-only dispatch credentials',
)[1].split('      - name: Require healthy signed alert sink before active mode')[0];
assert.match(activeSecretStep, /if: \$\{\{ inputs\.operation == 'deploy-active' \}\}/);
for (const name of ['ADMISSION_HMAC_KEY', 'ALERT_SIGNING_KEY', 'ACTIVATION_PROOF']) {
  assert.ok(activeSecretStep.includes(name));
}

const attestStep = workflow.split(
  '      - name: Verify exact attested observe rollback target',
)[1].split('      - name: Apply exact observe or active deployment')[0];
assert.match(attestStep, /workers\/scripts\/\$CONTROLLER_NAME\/versions\/\$ROLLBACK_VERSION_ID/);
assert.match(attestStep, /if: \$\{\{ !inputs\.bootstrap \}\}/);
assert.match(attestStep, /workers\/message/);
assert.match(attestStep, /protected-observe:/);
assert.match(attestStep, /workers\/tag/);
assert.match(attestStep, /CONTROLLER_CONFIG_SHA256/);
for (const name of ['ADMISSION_HMAC_KEY', 'ALERT_SIGNING_KEY', 'ACTIVATION_PROOF']) {
  assert.match(attestStep, new RegExp(`\\.name != "${name}"`));
}

const stripStep = workflow.split(
  '      - name: Remove every active-only binding from observe mode',
)[1].split('      - name: Finalize attested observe version after active-secret removal')[0];
assert.match(stripStep, /inputs\.operation == 'deploy-observe'/);
assert.equal((stripStep.match(/wrangler secret delete/g) || []).length, 1);
for (const name of ['ADMISSION_HMAC_KEY', 'ALERT_SIGNING_KEY', 'ACTIVATION_PROOF']) {
  assert.ok(stripStep.includes(name));
}
assert.equal((workflow.match(/wrangler secret delete/g) || []).length, 1);

const finalizeObserveStep = workflow.split(
  '      - name: Finalize attested observe version after active-secret removal',
)[1].split('      - name: Apply exact known-good observe rollback')[0];
assert.match(finalizeObserveStep, /inputs\.operation == 'deploy-observe'/);
assert.match(finalizeObserveStep, /protected-observe:\$\{GITHUB_SHA\}:\$\{EXPECTED_SOURCE\}:\$\{EXPECTED_PROFILE\}/);

const verifyStep = workflow.split(
  '      - name: Verify exact deployment, domain, cron, mode, and liveness',
)[1].split('      - name: Automatically restore attested observe version after failed deployment verification')[0];
assert.match(verifyStep, /id: verify_deploy/);
assert.match(verifyStep, /continue-on-error: true/);
assert.match(verifyStep, /no_terminal_failure == true/);
assert.match(verifyStep, /config_digest == \$config/);
assert.match(verifyStep, /select\(\(\.percentage \| tonumber\) == 100\)/);
assert.match(verifyStep, /select\(\(\$live\.versions \/\/ \[\]\) \| length == 1\)/);
assert.match(verifyStep, /workers\/scripts\/\$CONTROLLER_NAME\/versions\/\$live_version_id/);
assert.match(verifyStep, /\.result\.metadata\.annotations\["workers\/tag"\] == \$tag/);
assert.match(verifyStep, /\.result\.metadata\.annotations\["workers\/message"\] == \$message/);
assert.match(verifyStep, /select\(\$expected == "" or \. == \$expected\)/);
assert.match(verifyStep, /expected_config="\$ROLLBACK_CONFIG"/);
for (const name of ['ADMISSION_HMAC_KEY', 'ALERT_SIGNING_KEY', 'ACTIVATION_PROOF']) {
  assert.match(verifyStep, new RegExp(`\\.name != "${name}"`));
}

const autoRollbackStep = workflow.split(
  '      - name: Automatically restore attested observe version after failed deployment verification',
)[1].split('      - name: Conclude exact operation and safe rollback outcome')[0];
assert.match(autoRollbackStep, /steps\.attest_rollback\.outcome == 'success'/);
assert.match(autoRollbackStep, /steps\.apply_deploy\.outputs\.started_at != ''/);
assert.match(autoRollbackStep, /steps\.verify_deploy\.outcome != 'success'/);
assert.match(autoRollbackStep, /wrangler rollback "\$ROLLBACK_VERSION_ID"/);
assert.match(autoRollbackStep, /no_terminal_failure == true/);

const bootstrapContainmentStep = workflow.split(
  '      - name: Contain failed first deployment without deleting Worker history',
)[1].split('      - name: Conclude exact operation and safe rollback outcome')[0];
assert.match(bootstrapContainmentStep, /inputs\.bootstrap/);
assert.match(bootstrapContainmentStep, /steps\.bootstrap_absence\.outcome == 'success'/);
assert.match(bootstrapContainmentStep, /steps\.verify_deploy\.outcome != 'success'/);
assert.match(bootstrapContainmentStep, /--request DELETE/);
assert.match(bootstrapContainmentStep, /workers\/domains\/\$domain_id/);
assert.match(bootstrapContainmentStep, /schedules\/%2A%20%2A%20%2A%20%2A%20%2A/);
assert.doesNotMatch(bootstrapContainmentStep, /workers\/scripts\/\$CONTROLLER_NAME(?:['"\s]|$).*--request DELETE/);

for (const name of [
  'Verify Cloudflare account capability',
  'Prove bootstrap has no Worker history or traffic',
  'Upload and preverify immutable bootstrap observe candidate',
  'Verify exact attested observe rollback target',
  'Apply exact observe or active deployment',
  'Remove every active-only binding from observe mode',
  'Finalize attested observe version after active-secret removal',
  'Apply exact known-good observe rollback',
  'Verify exact deployment, domain, cron, mode, and liveness',
  'Automatically restore attested observe version after failed deployment verification',
  'Contain failed first deployment without deleting Worker history',
]) {
  const step = workflow.split(`      - name: ${name}\n`)[1].split('\n      - name: ')[0];
  assert.match(step, /CLOUDFLARE_ACCOUNT_ID/);
  assert.match(step, /CLOUDFLARE_API_TOKEN/);
}

const expectedConfig = process.env.SSAI_EXPECTED_CONTROLLER_CONFIG_SHA256;
const expectedSource = process.env.SSAI_EXPECTED_CONTROLLER_TARGET_SOURCE_SHA256;
const expectedProfile = process.env.SSAI_EXPECTED_CONTROLLER_TARGET_PROFILE_SHA256;
const operation = process.env.SSAI_RELEASE_CONTROLLER_OPERATION;
if (expectedConfig !== undefined) assert.equal(expectedConfig, configDigest);
if (operation !== undefined) {
  assert.ok(['deploy-observe', 'deploy-active', 'rollback-observe'].includes(operation));
  assert.match(expectedSource || '', /^[a-f0-9]{64}$/);
  assert.match(expectedProfile || '', /^[a-f0-9]{64}$/);
  if (operation !== 'rollback-observe') {
    assert.equal(expectedSource, sourceDigest);
    assert.equal(expectedProfile, profileDigest);
  }
}

console.log(JSON.stringify({
  controller_config_sha256: configDigest,
  controller_profile_sha256: profileDigest,
  controller_source_sha256: sourceDigest,
}));
