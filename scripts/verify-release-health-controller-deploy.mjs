import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { activationProfileDigest } from '../workers/release-health-controller/src/activation-profile.mjs';
import { materializeReleaseHealthControllerBootstrap } from './materialize-release-health-controller-bootstrap.mjs';

const root = new URL('../', import.meta.url);
const sourceDirectory = new URL('workers/release-health-controller/src/', root);
const configUrl = new URL('workers/release-health-controller/wrangler.jsonc', root);
const workflowUrl = new URL('.github/workflows/deploy-release-health-controller.yml', root);
const pinnedCloudflareAccountId = '7b68f149b6054718ad2c6ff0634ae145';

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
assert.equal(config.preview_urls, false);
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

const bootstrapDirectory = await mkdtemp(join(tmpdir(), 'ssai-controller-bootstrap-'));
try {
  const bootstrapPath = join(bootstrapDirectory, 'contained.jsonc');
  await materializeReleaseHealthControllerBootstrap(fileURLToPath(configUrl), bootstrapPath);
  const bootstrapConfig = JSON.parse(await readFile(bootstrapPath, 'utf8'));
  const expectedBootstrapConfig = structuredClone(config);
  delete expectedBootstrapConfig.routes;
  delete expectedBootstrapConfig.triggers;
  assert.deepEqual(bootstrapConfig, expectedBootstrapConfig);
  assert.equal(bootstrapConfig.workers_dev, false);
  assert.equal(bootstrapConfig.preview_urls, false);
  assert.equal(bootstrapConfig.vars.MODE, 'observe');
  if (process.platform !== 'win32') assert.equal((await stat(bootstrapPath)).mode & 0o777, 0o600);
  await assert.rejects(
    materializeReleaseHealthControllerBootstrap(fileURLToPath(configUrl), bootstrapPath),
    /EEXIST/,
  );
} finally {
  await rm(bootstrapDirectory, { recursive: true, force: true });
}

for (const required of [
  'environment:\n      name: release-health-controller-production',
  'group: release-health-controller-production-deployment',
  'cancel-in-progress: false',
  'timeout-minutes: 75',
  `CLOUDFLARE_ACCOUNT_ID: ${pinnedCloudflareAccountId}`,
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
  'Capture fallback inventory before bootstrap',
  'Classify exact resumable bootstrap state',
  'Create contained bootstrap observe candidate',
  'Attest private bootstrap observe candidate',
  'Attach and preverify bootstrap health domain',
  'Activate or re-attest exact bootstrap schedule',
  'materialize-release-health-controller-bootstrap.mjs',
  '.wrangler-bootstrap-deployment.jsonc',
  'git merge-base --is-ancestor',
  'cron_verified_at=',
  'Record exact verified deployment attestation',
  'ssai-release-health-controller-deployment-attestation-v1',
  'Contain failed first deployment without deleting Worker history',
  'Verify exact attested observe rollback target',
  'protected-observe:',
  "permissionMode = process.env.OPERATION === 'deploy-active' ? 'write' : 'read'",
  "'/repos/ScaleSmall/SSAI_Shared/commits/main'",
  "'/repos/ScaleSmall/SSAI_Shared/actions/workflows/344170407/runs?event=workflow_dispatch&branch=main&per_page=100'",
  'https://alerts.scalesmall.ai/healthz',
  'ssai-release-health-alert-gateway-health-v2',
  '.version_id|test("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")',
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
assert.doesNotMatch(workflow, /wrangler\s+triggers\s+deploy/i);
assert.doesNotMatch(workflow, /preview_prefix|bootstrap-preview-health/i);
assert.match(workflow, /options: \[deploy-observe, deploy-active, rollback-observe\]/);
assert.ok(workflow.includes('.schema == "ssai-release-health-controller-health-v1"'));
assert.ok(workflow.includes('.checks.no_terminal_failure == true'));
assert.match(workflow, /if test "\$BOOTSTRAP" = true; then\n\s+test "\$OPERATION" = deploy-observe/);
assert.match(workflow, /test -z "\$ROLLBACK_VERSION_ID\$ROLLBACK_SOURCE\$ROLLBACK_PROFILE\$ROLLBACK_CONFIG\$ROLLBACK_ATTESTATION_SHA"/);
assert.match(workflow, /\[\[ "\$ROLLBACK_CONFIG" =~ \^\[a-f0-9\]\{64\}\$ \]\]/);
assert.doesNotMatch(workflow, /SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID/);

const identityStep = workflow.split(
  '      - name: Verify exact protected execution identity',
)[1].split('      - name: Install exact locked toolchain')[0];
const identityRun = identityStep.split('        run: |\n')[1];
assert.doesNotMatch(identityRun, /\$\{\{\s*inputs\./);
for (const field of ['EXPECTED_SOURCE', 'EXPECTED_PROFILE', 'EXPECTED_CONFIG']) {
  assert.match(identityStep, new RegExp(`${field}: \\$\\{\\{ inputs\\.`));
  assert.match(identityRun, new RegExp(`\\[\\[ "\\$${field}" =~ \\^\\[a-f0-9\\]\\{64\\}\\$ \\]\\]`));
}

const bootstrapAbsenceStep = workflow.split(
  '      - name: Classify exact resumable bootstrap state',
)[1].split('      - name: Prepare and validate runtime credentials without disclosure')[0];
assert.match(bootstrapAbsenceStep, /if: \$\{\{ inputs\.bootstrap \}\}/);
for (const resource of ['deployments', 'versions', 'settings', 'schedules']) {
  assert.ok(bootstrapAbsenceStep.includes(resource));
}
assert.match(bootstrapAbsenceStep, /404404404404/);
for (const state of ['absent', 'contained', 'stale-contained', 'domain', 'scheduled']) {
  assert.match(bootstrapAbsenceStep, new RegExp(`(?:state=|state == |state != )${state}`));
}
assert.match(bootstrapAbsenceStep, /git merge-base --is-ancestor "\$candidate_sha" "\$GITHUB_SHA"/);
assert.match(bootstrapAbsenceStep, /\?deployable=true/);
assert.match(bootstrapAbsenceStep, /\.result\.items/);
assert.match(bootstrapAbsenceStep, /\.result\.schedules \/\/ \.result \/\/ \[\]/);
assert.match(bootstrapAbsenceStep, /\.result\.enabled == false and \.result\.previews_enabled == false/);
assert.match(bootstrapAbsenceStep, /release-health-controller\.scalesmall\.ai/);
assert.match(bootstrapAbsenceStep, /\["GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);

const bootstrapCreateStep = workflow.split(
  '      - name: Create contained bootstrap observe candidate',
)[1].split('      - name: Attest private bootstrap observe candidate')[0];
assert.match(bootstrapCreateStep, /steps\.bootstrap_absence\.outputs\.state == 'absent'/);
assert.match(bootstrapCreateStep, /steps\.bootstrap_absence\.outputs\.state == 'stale-contained'/);
assert.match(bootstrapCreateStep, /materialize-release-health-controller-bootstrap\.mjs/);
assert.match(bootstrapCreateStep, /wrangler deploy/);
assert.match(bootstrapCreateStep, /--config "\$bootstrap_config"/);
assert.match(bootstrapCreateStep, /PREFLIGHT_STATE/);
assert.match(bootstrapCreateStep, /if test "\$PREFLIGHT_STATE" = absent/);
assert.match(bootstrapCreateStep, /deploy_args\+=\(--strict\)/);
assert.doesNotMatch(bootstrapCreateStep, /--strict\s+--message/);
assert.doesNotMatch(bootstrapCreateStep, /wrangler versions upload|wrangler triggers deploy/);

const bootstrapCandidateStep = workflow.split(
  '      - name: Attest private bootstrap observe candidate',
)[1].split('      - name: Attach and preverify bootstrap health domain')[0];
assert.match(bootstrapCandidateStep, /steps\.bootstrap_absence\.outcome == 'success'/);
assert.match(bootstrapCandidateStep, /git merge-base --is-ancestor "\$attestation_sha" "\$GITHUB_SHA"/);
assert.match(bootstrapCandidateStep, /protected-observe:/);
assert.match(bootstrapCandidateStep, /CONTROLLER_CONFIG_SHA256/);
assert.match(bootstrapCandidateStep, /workers\/scripts\/\$CONTROLLER_NAME\/deployments/);
assert.match(bootstrapCandidateStep, /workers\/scripts\/\$CONTROLLER_NAME\/schedules/);
assert.match(bootstrapCandidateStep, /workers\/scripts\/\$CONTROLLER_NAME\/subdomain/);
assert.match(bootstrapCandidateStep, /\.result\.enabled == false and \.result\.previews_enabled == false/);
assert.match(bootstrapCandidateStep, /\["GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);

const bootstrapDomainStep = workflow.split(
  '      - name: Attach and preverify bootstrap health domain',
)[1].split('      - name: Verify exact attested observe rollback target')[0];
assert.match(bootstrapDomainStep, /--request PUT/);
assert.match(bootstrapDomainStep, /\$api\/workers\/domains/);
assert.match(bootstrapDomainStep, /hostname:"release-health-controller\.scalesmall\.ai"/);
assert.match(bootstrapDomainStep, /service:"ssai-release-health-controller"/);
assert.match(bootstrapDomainStep, /zone_name:"scalesmall\.ai"/);
assert.match(bootstrapDomainStep, /test "\$code" = 503/);
assert.match(bootstrapDomainStep, /last_completed_tick == null and \.last_scheduled_time == null and \.last_decision == null/);
assert.match(bootstrapDomainStep, /const historical = scheduled !== null/);
assert.match(bootstrapDomainStep, /no_terminal_failure === true/);
assert.match(bootstrapDomainStep, /no_internal_failure === true/);
assert.doesNotMatch(bootstrapDomainStep, /wrangler/);
assert.match(bootstrapDomainStep, /timeout-minutes: 10/);
assert.match(bootstrapDomainStep, /domain_deadline=\$\(\(SECONDS \+ 480\)\)/);
assert.match(bootstrapDomainStep, /printf 'domain_created_by_run=false/);
assert.match(bootstrapDomainStep, /test "\$attach_code" = 200/);
assert.match(bootstrapDomainStep, /select\(\.success == true\)/);
assert.ok(
  bootstrapDomainStep.indexOf('test "$attach_code" = 200')
    < bootstrapDomainStep.indexOf("printf 'domain_created_by_run=true"),
  'Domain ownership may be asserted only after an exact successful provider receipt.',
);

const applyBootstrapStep = workflow.split(
  '      - name: Activate or re-attest exact bootstrap schedule',
)[1].split('      - name: Remove every active-only binding from observe mode')[0];
assert.match(applyBootstrapStep, /steps\.bootstrap_candidate\.outcome == 'success'/);
assert.match(applyBootstrapStep, /steps\.bootstrap_domain\.outcome == 'success'/);
assert.match(applyBootstrapStep, /workers\/scripts\/\$CONTROLLER_NAME\/deployments/);
assert.match(applyBootstrapStep, /workers\/scripts\/\$CONTROLLER_NAME\/schedules/);
assert.match(applyBootstrapStep, /workers\/domains/);
assert.match(applyBootstrapStep, /--request PUT/);
assert.match(applyBootstrapStep, /\[\{cron:"\* \* \* \* \*"\}\]/);
assert.match(applyBootstrapStep, /\.result\.schedules \/\/ \.result \/\/ \[\]/);
assert.equal((applyBootstrapStep.match(/cron_verified_at=%s/g) || []).length, 1);
assert.doesNotMatch(applyBootstrapStep, /cron_verified_at=\\n|wrangler/);
assert.match(applyBootstrapStep, /timeout-minutes: 8/);
assert.match(applyBootstrapStep, /schedule_deadline=\$\(\(SECONDS \+ 360\)\)/);
assert.match(applyBootstrapStep, /printf 'schedule_created_by_run=false/);
assert.match(applyBootstrapStep, /test "\$schedule_code" = 200/);
assert.ok(
  applyBootstrapStep.indexOf('test "$schedule_code" = 200')
    < applyBootstrapStep.indexOf("printf 'schedule_created_by_run=true"),
  'Schedule ownership may be asserted only after an exact successful provider receipt.',
);

const jobEnvironment = workflow.split('    env:\n')[1].split('    steps:\n')[0];
assert.match(jobEnvironment, new RegExp(`CLOUDFLARE_ACCOUNT_ID: ${pinnedCloudflareAccountId}`));
assert.equal((workflow.match(new RegExp(pinnedCloudflareAccountId, 'g')) || []).length, 1);
assert.doesNotMatch(jobEnvironment, /CLOUDFLARE_API_TOKEN/);
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
assert.match(attestStep, /\["GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);

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
assert.match(verifyStep, /no_terminal_failure:true/);
assert.match(verifyStep, /config_digest == \$config/);
assert.match(verifyStep, /select\(\(\$live\.versions \/\/ \[\]\) \| length == 1\)/);
assert.match(verifyStep, /select\(\(\$live\.versions\[0\]\.percentage \| tonumber\) == 100\)/);
assert.match(verifyStep, /workers\/scripts\/\$CONTROLLER_NAME\/versions\/\$live_version_id/);
assert.match(verifyStep, /\["workers\/tag"\] == \$tag/);
assert.match(verifyStep, /\["workers\/message"\] == \$message/);
assert.match(verifyStep, /select\(\$expected == "" or \. == \$expected\)/);
assert.match(verifyStep, /expected_config="\$ROLLBACK_CONFIG"/);
for (const output of ['candidate_version_id', 'candidate_deployment_id', 'attestation_sha']) {
  assert.match(verifyStep, new RegExp(`steps\\.bootstrap_candidate\\.outputs\\.${output}`));
}
assert.match(verifyStep, /steps\.bootstrap_domain\.outputs\.domain_id/);
assert.match(verifyStep, /steps\.apply_bootstrap\.outputs\.cron_verified_at/);
assert.match(verifyStep, /steps\.fallback_before\.outputs\.latest_run_id/);
assert.match(verifyStep, /controller-subdomain-after\.json/);
assert.match(verifyStep, /\.result\.enabled == false and \.result\.previews_enabled == false/);
assert.match(verifyStep, /\.result\.schedules \/\/ \.result \/\/ \[\]/);
assert.match(verifyStep, /\(keys \| sort\) == \["alerts","checks","component","config_digest","last_completed_tick","last_decision","last_scheduled_time","mode","profile_digest","schema","source_digest","status"\]/);
assert.match(verifyStep, /scheduled < threshold/);
assert.match(verifyStep, /fallback_after_id.*FALLBACK_BEFORE_ID/s);
assert.match(verifyStep, /createdMs < startMs/);
assert.match(verifyStep, /timeout-minutes: 15/);
assert.match(verifyStep, /verification_deadline=\$\(\(SECONDS \+ 720\)\)/);
for (const decision of ['outside-window', 'claimed', 'standby', 'native-blocked', 'native-blocked-final', 'outstanding', 'would_dispatch']) {
  assert.ok(verifyStep.includes(`.last_decision == "${decision}"`));
}
assert.match(verifyStep, /\["GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);
assert.match(verifyStep, /\["ACTIVATION_PROOF","ADMISSION_HMAC_KEY","ALERT_SIGNING_KEY","GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);
const attestationRecordStep = workflow.split(
  '      - name: Record exact verified deployment attestation',
)[1].split('      - name: Automatically restore attested observe version after failed deployment verification')[0];
assert.match(attestationRecordStep, /steps\.verify_deploy\.outcome == 'success'/);
assert.match(attestationRecordStep, /ssai-release-health-controller-deployment-attestation-v1/);
assert.match(attestationRecordStep, /\$GITHUB_STEP_SUMMARY/);
for (const field of ['VERSION_ID', 'DEPLOYMENT_ID', 'DOMAIN_ID', 'EXPECTED_SOURCE', 'EXPECTED_PROFILE', 'EXPECTED_CONFIG', 'ROLLBACK_CONFIG']) {
  assert.ok(attestationRecordStep.includes(field));
}
assert.match(attestationRecordStep, /effective_config="\$EXPECTED_CONFIG"/);
assert.match(attestationRecordStep, /if test "\$OPERATION" = rollback-observe; then effective_config="\$ROLLBACK_CONFIG"; fi/);
assert.match(attestationRecordStep, /--arg config_sha256 "\$effective_config"/);
assert.doesNotMatch(attestationRecordStep, /ACTIVATION_PROOF|PRIVATE_KEY|API_TOKEN|HMAC_KEY|SIGNING_KEY/);

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
assert.match(bootstrapContainmentStep, /steps\.bootstrap_domain\.outputs\.mutation_attempted == 'true'/);
assert.match(bootstrapContainmentStep, /steps\.apply_bootstrap\.outputs\.mutation_attempted == 'true'/);
assert.match(bootstrapContainmentStep, /--request DELETE/);
assert.match(bootstrapContainmentStep, /workers\/domains\/\$domain_id/);
assert.match(bootstrapContainmentStep, /\^\[a-f0-9\]\{40\}\$/);
assert.match(bootstrapContainmentStep, /\^\[a-f0-9\]\{8\}-\[a-f0-9\]\{4\}-\[a-f0-9\]\{4\}-\[a-f0-9\]\{4\}-\[a-f0-9\]\{12\}\$/);
assert.match(bootstrapContainmentStep, /bootstrap-schedule-empty-body\.json/);
assert.match(bootstrapContainmentStep, /--request PUT/);
assert.match(bootstrapContainmentStep, /DOMAIN_CREATED_BY_RUN/);
assert.match(bootstrapContainmentStep, /SCHEDULE_CREATED_BY_RUN/);
assert.match(bootstrapContainmentStep, /if test "\$SCHEDULE_MUTATION_ATTEMPTED" = true && test "\$SCHEDULE_CREATED_BY_RUN" != true; then\n\s+containment_rc=1/);
assert.match(bootstrapContainmentStep, /if test "\$DOMAIN_MUTATION_ATTEMPTED" = true && test "\$DOMAIN_CREATED_BY_RUN" != true; then\n\s+containment_rc=1/);
assert.match(bootstrapContainmentStep, /timeout-minutes: 10/);
assert.match(bootstrapContainmentStep, /containment_deadline=\$\(\(SECONDS \+ 480\)\)/);
assert.ok(
  bootstrapContainmentStep.indexOf('bootstrap-schedule-empty-body.json')
    < bootstrapContainmentStep.indexOf('--request DELETE'),
  'Bootstrap containment must withdraw cron before deleting a run-created domain.',
);
const scheduleContainment = bootstrapContainmentStep.split(
  'if test "$SCHEDULE_CREATED_BY_RUN" = true; then',
)[1].split('if test "$DOMAIN_CREATED_BY_RUN" = true; then')[0];
assert.match(scheduleContainment, /--request PUT/);
const domainContainment = bootstrapContainmentStep.split(
  'if test "$DOMAIN_CREATED_BY_RUN" = true; then',
)[1];
assert.match(domainContainment, /--request DELETE/);
assert.doesNotMatch(bootstrapContainmentStep, /workers\/scripts\/\$CONTROLLER_NAME(?:['"\s]|$).*--request DELETE/);
assert.match(bootstrapContainmentStep, /\["GITHUB_APP_CLIENT_ID","GITHUB_APP_PRIVATE_KEY","GITHUB_INSTALLATION_ID"\]/);

for (const name of [
  'Verify Cloudflare account capability',
  'Classify exact resumable bootstrap state',
  'Create contained bootstrap observe candidate',
  'Attest private bootstrap observe candidate',
  'Attach and preverify bootstrap health domain',
  'Activate or re-attest exact bootstrap schedule',
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
