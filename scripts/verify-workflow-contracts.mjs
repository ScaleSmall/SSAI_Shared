import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  releaseHealthFallbackNoHistoryExpiresAt,
  releaseHealthIncidentProducerPolicies,
  releaseHealthMonitorJobNames,
  releaseHealthMonitorWorkflowIdentities,
} from './release-health-monitor-utils.mjs';
import { activationProfileDigest } from '../workers/release-health-controller/src/activation-profile.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const workflowDirectory = path.join(repoRoot, '.github', 'workflows');

const readWorkflow = async (name) =>
  (await readFile(path.join(workflowDirectory, name), 'utf8')).replace(/\r\n?|\n/g, '\n');

const readSource = async (...segments) =>
  (await readFile(path.join(repoRoot, ...segments), 'utf8')).replace(/\r\n?|\n/g, '\n');

const requireText = (source, expected, description) => {
  if (!source.includes(expected)) {
    throw new Error(`Missing ${description}: ${expected}`);
  }
};

const assertRecoveryPolicyFields = (block, key, expectedFields) => {
  for (const [expected, description] of expectedFields) {
    requireText(block, expected, `${key} ${description}`);
  }
};

const requireRecoveryPolicyBlock = (source, key, expectedFields, marker = `['${key}', {`) => {
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`Missing recovery policy: ${key}`);
  const end = source.indexOf('\n  }],', start);
  if (end < 0) throw new Error(`Unterminated recovery policy: ${key}`);
  const block = source.slice(start, end + '\n  }],'.length);
  assertRecoveryPolicyFields(block, key, expectedFields);
  return block;
};

const rejectPattern = (source, pattern, description) => {
  if (pattern.test(source)) {
    throw new Error(`Workflow contract violation: ${description}`);
  }
};

const collectWorkflowSources = async () => {
  const entries = await readdir(workflowDirectory, { withFileTypes: true });
  const workflowEntries = entries
    .filter((entry) => /\.ya?ml$/i.test(entry.name))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (workflowEntries.length === 0) throw new Error('No GitHub workflow sources were found.');

  const sources = new Map();
  for (const entry of workflowEntries) {
    if (!entry.isFile()) {
      throw new Error(`GitHub workflow source is not a regular file: ${entry.name}`);
    }
    const canonicalName = entry.name.toLowerCase();
    if ([...sources.keys()].some((name) => name.toLowerCase() === canonicalName)) {
      throw new Error(`Duplicate case-insensitive GitHub workflow source: ${entry.name}`);
    }
    sources.set(entry.name, await readWorkflow(entry.name));
  }
  return sources;
};

const requireWorkflowSource = (sources, name) => {
  const source = sources.get(name);
  if (typeof source !== 'string') throw new Error(`Missing required GitHub workflow source: ${name}`);
  return source;
};

const assertNoLegacyCrossRepositoryPat = (sources) => {
  if (!(sources instanceof Map) || sources.size === 0) {
    throw new TypeError('workflow sources must be a non-empty Map');
  }
  for (const [name, source] of sources) {
    if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.ya?ml$/i.test(name) || typeof source !== 'string') {
      throw new TypeError('workflow source inventory contains an invalid entry');
    }
    if (/\bSCALESMALL_PAT\b/.test(source)) {
      throw new Error(`Workflow contract violation: ${name} references the retired SCALESMALL_PAT identifier`);
    }
  }
};

const requireBalancedExpressions = (source, description) => {
  const openings = source.match(/\$\{\{/g)?.length ?? 0;
  let cursor = 0;
  let paired = 0;
  while (true) {
    const opening = source.indexOf('${{', cursor);
    if (opening < 0) break;
    const closing = source.indexOf('}}', opening + 3);
    if (closing < 0) break;
    paired += 1;
    cursor = closing + 2;
  }
  if (openings !== paired) throw new Error(`Unbalanced GitHub expressions in ${description}: ${openings}/${paired}`);
};

const requireSpaceIndentation = (source, description) => {
  const tabbedLine = source.split('\n').findIndex((line) => /^\s*\t|\t/.test(line));
  if (tabbedLine >= 0) throw new Error(`${description} contains a tab on line ${tabbedLine + 1}`);
};

const expandCronMinuteField = (field, description) => {
  const minutes = new Set();
  for (const segment of field.split(',')) {
    const [range, rawStep] = segment.split('/');
    const step = rawStep === undefined ? 1 : Number.parseInt(rawStep, 10);
    const [rawStart, rawEnd] = range === '*'
      ? ['0', '59']
      : range.includes('-')
        ? range.split('-')
        : [range, range];
    const start = Number.parseInt(rawStart, 10);
    const end = Number.parseInt(rawEnd, 10);
    if (
      !Number.isInteger(start)
      || !Number.isInteger(end)
      || !Number.isInteger(step)
      || start < 0
      || end > 59
      || start > end
      || step < 1
    ) {
      throw new Error(`Invalid cron minute field for ${description}: ${field}`);
    }
    for (let minute = start; minute <= end; minute += step) minutes.add(minute);
  }
  return minutes;
};

const requireWorkflowJobBlock = (source, jobName, description) => {
  const jobsStart = source.indexOf('\njobs:\n');
  if (jobsStart < 0) throw new Error(`Missing jobs mapping in ${description}`);
  const marker = `\n  ${jobName}:\n`;
  const start = source.indexOf(marker, jobsStart);
  if (start < 0) throw new Error(`Missing ${jobName} job in ${description}`);
  const remainderStart = start + marker.length;
  const nextJobOffset = source.slice(remainderStart).search(/^  [A-Za-z0-9_-]+:\n/m);
  const end = nextJobOffset < 0 ? source.length : remainderStart + nextJobOffset;
  return source.slice(start + 1, end);
};

const collectWorkflowJobNames = (source, description) => {
  const jobsStart = source.indexOf('\njobs:\n');
  if (jobsStart < 0) throw new Error(`Missing jobs mapping in ${description}`);
  return [...source.slice(jobsStart + '\njobs:\n'.length).matchAll(/^  ([A-Za-z0-9_-]+):\n/gm)]
    .map((match) => match[1]);
};

const requireFlatJobMapping = (jobBlock, fieldName, description) => {
  const pattern = new RegExp(`^    ${fieldName}:\\n((?:^      [A-Za-z0-9_-]+:.*\\n)+)`, 'm');
  const match = jobBlock.match(pattern);
  if (!match) throw new Error(`Missing ${description}`);
  return `    ${fieldName}:\n${match[1]}`;
};

const assertSharedMonitorConcurrency = (source, description, queueRequired = false) => {
  requireText(source, 'concurrency:', `${description} concurrency mapping`);
  requireText(source, '  group: scale-small-ai-release-health-monitor-v2', `${description} shared concurrency group`);
  requireText(source, '  cancel-in-progress: false', `${description} non-cancelling concurrency`);
  if (queueRequired) requireText(source, '  queue: max', `${description} lossless pending-run queue`);
  assert.equal((source.match(/^concurrency:$/gm) || []).length, 1, `${description} must declare one top-level concurrency contract`);
  assert.equal((source.match(/^  group: scale-small-ai-release-health-monitor-v2$/gm) || []).length, 1, `${description} must declare the shared concurrency group once`);
  assert.equal((source.match(/^  cancel-in-progress: false$/gm) || []).length, 1, `${description} must declare non-cancelling concurrency once`);
  if (queueRequired) assert.equal((source.match(/^  queue: max$/gm) || []).length, 1, `${description} must declare queue:max once`);
};

const assertProtectedWorkflowAdmission = (jobBlock, jobName, eventAssertion) => {
  for (const [expected, description] of [
    ['ref: ${{ github.sha }}', 'exact checkout SHA'],
    ['ACTUAL_EVENT: ${{ github.event_name }}', 'event binding'],
    ['ACTUAL_REF: ${{ github.ref }}', 'branch ref binding'],
    ['ACTUAL_REPOSITORY: ${{ github.repository }}', 'repository binding'],
    ['ACTUAL_SHA: ${{ github.sha }}', 'event SHA binding'],
    ['ACTUAL_WORKFLOW_REF: ${{ github.workflow_ref }}', 'workflow ref binding'],
    ['EXPECTED_REF: refs/heads/${{ github.event.repository.default_branch }}', 'default-branch ref'],
    ['EXPECTED_REPOSITORY: ScaleSmall/SSAI_Shared', 'exact repository'],
    ['EXPECTED_WORKFLOW_REF: ScaleSmall/SSAI_Shared/.github/workflows/release-health-monitor.yml@refs/heads/${{ github.event.repository.default_branch }}', 'authoritative workflow path'],
    ['checked_out_sha="$(git rev-parse HEAD)"', 'checked-out SHA attestation'],
    [eventAssertion, 'event allowlist'],
    ['[ "$ACTUAL_REPOSITORY" != "$EXPECTED_REPOSITORY" ]', 'repository assertion'],
    ['[ "$ACTUAL_REF" != "$EXPECTED_REF" ]', 'ref assertion'],
    ['[ "$ACTUAL_WORKFLOW_REF" != "$EXPECTED_WORKFLOW_REF" ]', 'workflow ref assertion'],
    ['! [[ "$ACTUAL_SHA" =~ ^[0-9a-f]{40}$ ]]', 'full SHA format assertion'],
    ['[ "$checked_out_sha" != "$ACTUAL_SHA" ]', 'checked-out SHA equality assertion'],
  ]) requireText(jobBlock, expected, `${jobName} ${description}`);
};

const workflowSources = await collectWorkflowSources();
const validate = requireWorkflowSource(workflowSources, 'validate.yml');
const propagate = requireWorkflowSource(workflowSources, 'propagate.yml');
const releaseHealth = requireWorkflowSource(workflowSources, 'release-health-monitor.yml');
const releaseHealthIdentityCanary = requireWorkflowSource(workflowSources, 'release-health-monitor-v3.yml');
const releaseHealthFallbackRegistration = requireWorkflowSource(workflowSources, 'release-health-monitor-fallback.yml');
const releaseHealthVerifier = await readSource('scripts', 'verify-org-release-health.mjs');
const releaseHealthUtils = await readSource('scripts', 'release-health-monitor-utils.mjs');
const releaseHealthDelivery = await readSource('scripts', 'sync-release-health-incident-issue.mjs');
const releaseHealthRunbook = await readSource('docs', 'RELEASE_HEALTH_GITHUB_APP_RUNBOOK.md');
const fallbackAdmission = await readSource('scripts', 'verify-release-health-fallback-admission.mjs');
const controllerConfig = JSON.parse(await readSource('workers', 'release-health-controller', 'wrangler.jsonc'));
const controllerSourceNames = (await readdir(path.join(repoRoot, 'workers', 'release-health-controller', 'src'))).sort();
const controllerSources = await Promise.all(controllerSourceNames.map((name) => readSource('workers', 'release-health-controller', 'src', name)));
const controllerSourceByName = new Map(controllerSourceNames.map((name, index) => [name, controllerSources[index]]));
const propagationRetirementRunbook = await readSource('docs', 'SHARED_PROPAGATION_RETIREMENT.md');
const combined = [...workflowSources.values()].join('\n');
const controllerDeployment = requireWorkflowSource(
  workflowSources,
  'deploy-release-health-controller.yml',
);
const alertGatewayDeployment = requireWorkflowSource(
  workflowSources,
  'deploy-release-health-alert-gateway.yml',
);
const workflowsWithoutControllerDeployment = [...workflowSources.entries()]
  .filter(([name]) => ![
    'deploy-release-health-controller.yml',
    'deploy-release-health-alert-gateway.yml',
  ].includes(name))
  .map(([, source]) => source)
  .join('\n');

assert.equal(controllerConfig.vars.MODE, 'observe', 'F2b controller must remain observe-only');
assert.equal(controllerConfig.workers_dev, false, 'F2b controller must have no public workers.dev route');
assert.deepEqual(controllerConfig.triggers.crons, ['* * * * *'], 'controller recovery cadence must remain exact');
assert.deepEqual(controllerConfig.migrations, [{ tag: 'v1', new_sqlite_classes: ['ReleaseHealthControllerObject'] }], 'controller SQLite Durable Object migration must remain exact');
assert.deepEqual(
  {
    repository: controllerConfig.vars.REPOSITORY,
    repositoryId: controllerConfig.vars.REPOSITORY_ID,
    nativeWorkflow: controllerConfig.vars.NATIVE_WORKFLOW_ID,
    canaryWorkflow: controllerConfig.vars.CANARY_WORKFLOW_ID,
    fallbackWorkflow: controllerConfig.vars.FALLBACK_WORKFLOW_ID,
    logicalSlots: controllerConfig.vars.LOGICAL_SLOT_MINUTES,
    nativeMinutes: controllerConfig.vars.NATIVE_MINUTES,
    grace: controllerConfig.vars.GRACE_MINUTES,
    circuitFailures: controllerConfig.vars.CIRCUIT_FAILURE_LIMIT,
    circuitWindow: controllerConfig.vars.CIRCUIT_WINDOW_MINUTES,
    circuitCooldown: controllerConfig.vars.CIRCUIT_COOLDOWN_MINUTES,
    appEpoch: controllerConfig.vars.GITHUB_APP_CREDENTIAL_EPOCH,
    admissionEpoch: controllerConfig.vars.FALLBACK_ADMISSION_HMAC_EPOCH,
    alertEpoch: controllerConfig.vars.ALERT_SIGNING_EPOCH,
    alertSink: controllerConfig.vars.ALERT_SINK_URL,
  },
  {
    repository: 'ScaleSmall/SSAI_Shared',
    repositoryId: '1183552904',
    nativeWorkflow: '315630665',
    canaryWorkflow: '344135917',
    fallbackWorkflow: '344170407',
    logicalSlots: '1,16,31,46',
    nativeMinutes: '9,24,39,54',
    grace: '10',
    circuitFailures: '4',
    circuitWindow: '60',
    circuitCooldown: '60',
    appEpoch: 'github-app-credential-v1',
    admissionEpoch: 'fallback-admission-hmac-v1',
    alertEpoch: 'release-health-alert-hmac-v1',
    alertSink: 'https://alerts.scalesmall.ai/release-health-alert',
  },
  'controller effective activation environment must remain exact',
);
assert.equal(Object.hasOwn(controllerConfig.vars, 'NO_HISTORY_EXPIRES_AT'), false, 'inventory allowance expiry must not be an ignored controller variable');
const controllerDigest = createHash('sha256');
for (let index = 0; index < controllerSourceNames.length; index += 1) {
  controllerDigest.update(controllerSourceNames[index] + '\0').update(controllerSources[index]).update('\0');
}
assert.equal(controllerConfig.vars.CONTROLLER_SOURCE_SHA256, controllerDigest.digest('hex'), 'controller source digest must bind every runtime module');
assert.equal(
  controllerConfig.vars.CONTROLLER_ACTIVATION_PROFILE_SHA256,
  await activationProfileDigest(controllerConfig.vars),
  'controller activation profile must bind the effective nonsecret environment',
);
for (const source of controllerSources) rejectPattern(source, /from ['"](?!\.\/|node:)/, 'controller runtime dependency');
const controllerRuntime = controllerSourceByName.get('controller.mjs');
const controllerStore = controllerSourceByName.get('store.mjs');
const controllerApi = controllerSourceByName.get('github-api.mjs');
const controllerIndex = controllerSourceByName.get('index.mjs');
requireText(controllerStore, "CHECK(phase IN ('leased','prepared','post-attempted','unknown','confirmed','terminal'))", 'typed durable controller phases');
requireText(controllerStore, "phase='post-attempted',post_attempt_count=1", 'pre-network one-shot dispatch permit');
requireText(controllerStore, 'envelope_json TEXT', 'unsigned prepared envelope persistence');
rejectPattern(controllerStore, /inputs_json|signature\s+TEXT/i, 'persisted reusable dispatch or alert signature');
requireText(controllerStore, "phase IN ('post-attempted','unknown')", 'restart GET-only reconciliation inventory');
requireText(controllerStore, 'async abandonUnattempted(', 'stale lease/prepared abandonment');
requireText(controllerRuntime, "phase === 'prepared' ? 'prepared-abandoned' : 'lease-abandoned'", 'stale unattempted alert path');
requireText(controllerStore, "circuit_state='half-open'", 'durable circuit half-open transition');
requireText(controllerStore, "state IN ('pending','sending','delivered','dead')", 'durable alert outbox phases');
requireText(controllerRuntime, "344170407,\n      'workflow_dispatch'", 'single unfiltered fallback inventory');
rejectPattern(controllerRuntime, /actions\/workflows\/344170407\/runs\?status=/, 'sequential fallback status inventory');
requireText(controllerApi, 'export async function dispatchWorkflowOnce', 'operation-specific one-attempt dispatch client');
requireText(controllerApi, 'attempts: 3', 'bounded GitHub read and token retry client');
requireText(controllerIndex, "if (request.method !== 'POST')", 'internal evaluate method boundary');
requireText(controllerIndex, "url.pathname !== '/evaluate' || url.search || url.hash", 'internal evaluate path boundary');
requireText(releaseHealthRunbook, controllerConfig.vars.CONTROLLER_SOURCE_SHA256, 'controller source digest runbook binding');
requireText(releaseHealthRunbook, controllerConfig.vars.CONTROLLER_ACTIVATION_PROFILE_SHA256, 'controller activation profile runbook binding');
requireText(fallbackAdmission, 'ssai-release-health-fallback-envelope-v1\\0', 'versioned fallback HMAC domain');
requireText(fallbackAdmission, 'writeUInt32BE', 'uint32be fallback envelope canonicalization');
requireText(fallbackAdmission, 'fallbackRepositoryId = 1183552904', 'exact fallback repository ID');
requireText(releaseHealthVerifier, "['SSAI_Shared:Scale Small AI Release Health Independent Fallback'", 'observe-only fallback no-history inventory allowance');
requireText(releaseHealthVerifier, 'workflowId: releaseHealthMonitorWorkflowIdentities.fallback.workflowId', 'fallback no-history workflow ID binding');
requireText(releaseHealthVerifier, 'observeStageExpiresAt: releaseHealthFallbackNoHistoryExpiresAt', 'fallback no-history absolute observe-stage expiry binding');
requireText(releaseHealthVerifier, "name: 'Validate shared package'", 'fallback no-history validation witness');
requireText(releaseHealthVerifier, "allowedEvents: ['push']", 'fallback no-history push-only witness');
requireText(releaseHealthVerifier, "maxAgeHours: 30", 'fallback no-history witness freshness');
requireText(releaseHealthUtils, 'Number(workflow.id) !== releaseHealthMonitorWorkflowIdentities.fallback.workflowId', 'exact observed fallback workflow ID enforcement');
requireText(releaseHealthUtils, 'nowMs >= observeStageExpiresAtMs', 'fail-closed fallback no-history expiry enforcement');
requireText(releaseHealthUtils, 'recovery_evidence: false', 'fallback no-history non-recovery evidence classification');
requireText(releaseHealthVerifier, 'const exactFallbackProducer =', 'fallback self-deployment exact producer branch');
requireText(releaseHealthVerifier, 'Number(status?.source_run_attempt) === 1', 'fallback self-deployment first-attempt restriction');
requireText(releaseHealthFallbackRegistration, 'X-GitHub-Api-Version: 2026-03-10', 'exact fallback GitHub API version');
rejectPattern(
  workflowsWithoutControllerDeployment,
  /wrangler\s+(?:deploy|publish)|cloudflare\/wrangler-action/i,
  'controller deployment outside the exact protected workflow',
);
requireText(controllerDeployment, 'environment:\n      name: release-health-controller-production', 'protected controller deployment environment');
requireText(controllerDeployment, 'github.workflow_sha == inputs.expected_sha', 'exact controller deployment workflow SHA');
requireText(controllerDeployment, 'cancel-in-progress: false', 'non-cancelling controller deployment concurrency');
requireText(controllerDeployment, 'wrangler deploy', 'controller deployment command');
requireText(controllerDeployment, 'wrangler rollback', 'controller observe rollback command');
requireText(controllerDeployment, 'ssai-release-health-alert-gateway-health-v2', 'version-bound alert-gateway health contract');
requireText(controllerDeployment, '.version_id|test("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")', 'valid alert-gateway version identity');
rejectPattern(controllerDeployment, /actions\/workflows\/\d+\/dispatches|gh\s+workflow\s+run/i, 'workflow dispatch from controller deployment');
requireText(alertGatewayDeployment, 'environment:\n      name: release-health-controller-production', 'protected alert-gateway deployment environment');
requireText(alertGatewayDeployment, 'github.workflow_sha == inputs.expected_sha', 'exact alert-gateway deployment workflow SHA');
requireText(alertGatewayDeployment, 'cancel-in-progress: false', 'non-cancelling alert-gateway deployment concurrency');
requireText(alertGatewayDeployment, 'wrangler deploy', 'alert-gateway deployment command');
requireText(alertGatewayDeployment, 'candidate_secrets="$RUNNER_TEMP/gateway-candidate-secrets.json"', 'private immutable-candidate secret bundle');
requireText(alertGatewayDeployment, '--secrets-file "$candidate_secrets"', 'atomic immutable-candidate signing-key binding');
requireText(alertGatewayDeployment, 'bootstrap_dir="$RUNNER_TEMP/gateway-bootstrap"', 'contained alert-gateway bootstrap staging');
requireText(alertGatewayDeployment, 'cp -R -- "$(dirname "$GATEWAY_CONFIG")/." "$bootstrap_dir/"', 'complete alert-gateway bootstrap bundle');
requireText(alertGatewayDeployment, 'bootstrap_secrets="$bootstrap_dir/bootstrap-secrets.json"', 'private alert-gateway bootstrap secret bundle');
requireText(alertGatewayDeployment, '--secrets-file "$bootstrap_secrets"', 'atomic alert-gateway bootstrap secret binding');
requireText(alertGatewayDeployment, '--dry-run --outdir "$RUNNER_TEMP/gateway-bootstrap-dry-run"', 'exact alert-gateway bootstrap dry-run');
requireText(alertGatewayDeployment, 'bootstrap_mutation_attempted=true', 'pre-armed alert-gateway bootstrap containment');
requireText(alertGatewayDeployment, 'timeout --signal=TERM --kill-after=15s 10m', 'bounded live alert-gateway bootstrap mutation');
requireText(alertGatewayDeployment, 'contain_bootstrap()', 'bounded alert-gateway bootstrap containment');
requireText(alertGatewayDeployment, 'contain_bootstrap bootstrap-containment', 'bootstrap failure containment invocation');
requireText(alertGatewayDeployment, '{enabled:false,previews_enabled:true}', 'explicit safe alert-gateway bootstrap subdomain state');
requireText(alertGatewayDeployment, 'wait_domain_absent bootstrap-post-deploy', 'post-bootstrap custom-domain absence proof');
requireText(alertGatewayDeployment, 'latest_deployment_id()', 'provider-ordered active alert-gateway deployment lookup');
requireText(alertGatewayDeployment, '.result.deployments|select(type=="array" and length>0)|.[0]', 'Cloudflare active-deployment element-zero contract');
requireText(alertGatewayDeployment, 'deployments/$previous_deployment_id', 'exact prior alert-gateway deployment attestation');
requireText(alertGatewayDeployment, 'deployments/$candidate_deployment_id', 'exact promoted alert-gateway deployment attestation');
requireText(alertGatewayDeployment, 'legacy_contained_version_ok()', 'bounded legacy-contained alert-gateway upgrade');
requireText(alertGatewayDeployment, 'known_settings_binding_ok()', 'latest-versus-active alert-gateway settings compatibility');
requireText(alertGatewayDeployment, 'legacy_contained_previous=true', 'attested legacy-contained rollback state');
requireText(alertGatewayDeployment, 'CF_VERSION_METADATA', 'version metadata alert-gateway binding');
requireText(alertGatewayDeployment, 'observability_ok "$RUNNER_TEMP/gateway-preflight-settings.json"', 'pre-mutation alert-gateway observability attestation');
requireText(alertGatewayDeployment, '.result.logpush==false', 'disabled legacy alert-gateway logpush');
requireText(alertGatewayDeployment, '.result.tail_consumers//[]', 'empty alert-gateway tail-consumer state');
requireText(alertGatewayDeployment, '[.[]|select(.type=="version-upload")] as $events|($events|length)==1', 'single pinned Wrangler upload event');
requireText(alertGatewayDeployment, '$metadata.hasPreview?', 'documented Cloudflare preview metadata');
requireText(alertGatewayDeployment, '$metadata.has_preview?', 'observed Cloudflare preview metadata compatibility');
requireText(alertGatewayDeployment, '.result.annotations//.result.metadata.annotations//{}', 'provider-side alert-gateway candidate annotations');
requireText(alertGatewayDeployment, '$annotations["workers/tag"]==$sha', 'provider-side alert-gateway commit provenance');
requireText(alertGatewayDeployment, '$annotations["workers/message"]==$msg', 'provider-side alert-gateway digest provenance');
requireText(alertGatewayDeployment, '$annotations["workers/alias"]==$alias', 'provider-side alert-gateway alias provenance');
requireText(alertGatewayDeployment, 'rm -f -- "$RUNNER_TEMP/gateway-candidate.jsonl"', 'empty alert-gateway candidate output path');
requireText(alertGatewayDeployment, 'api_post_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/deployments"', 'documented alert-gateway deployment API');
requireText(alertGatewayDeployment, 'traffic_mutated=true', 'pre-armed alert-gateway traffic rollback');
requireText(alertGatewayDeployment, 'reconcile_traffic_rollback()', 'bounded alert-gateway traffic rollback reconciliation');
requireText(alertGatewayDeployment, 'deployments?force=true', 'provider-supported alert-gateway secret-change rollback');
requireText(alertGatewayDeployment, 'attest_rollback_active()', 'exact alert-gateway rollback deployment proof');
requireText(alertGatewayDeployment, 'return 2', 'fail-closed alert-gateway concurrent-state classification');
requireText(alertGatewayDeployment, 'workers/domains?service=$GATEWAY_NAME', 'service-filtered alert-gateway domain inventory');
requireText(alertGatewayDeployment, 'workers/domains?hostname=$GATEWAY_DOMAIN', 'hostname-filtered alert-gateway domain inventory');
requireText(alertGatewayDeployment, 'domain_list_complete()', 'complete single-page alert-gateway domain inventory');
requireText(alertGatewayDeployment, '(.result.zone_id|type)=="string"', 'validated provider-issued alert-gateway zone identity');
requireText(alertGatewayDeployment, '.result.zone_id|test("^[a-f0-9]{32}$")', 'well-formed provider-issued alert-gateway zone identity');
requireText(alertGatewayDeployment, '(.result.cert_id|type)=="string"', 'validated provider-managed alert-gateway TLS certificate identity');
requireText(alertGatewayDeployment, '.result.cert_id|test("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")', 'well-formed provider-managed alert-gateway TLS certificate identity');
requireText(alertGatewayDeployment, 'script_routes_absent()', 'account-level alert-gateway ordinary-route attestation');
requireText(alertGatewayDeployment, 'api_get "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts"', 'documented account Worker inventory');
requireText(alertGatewayDeployment, 'domain_attach_attempted=true', 'pre-armed alert-gateway domain rollback');
requireText(alertGatewayDeployment, 'api_put_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains"', 'documented alert-gateway domain attach API');
requireText(alertGatewayDeployment, 'reconcile_domain_attach_response()', 'bounded idempotent alert-gateway domain response reconciliation');
requireText(alertGatewayDeployment, 'reconcile_owned_domain_rollback()', 'bounded alert-gateway domain rollback reconciliation');
requireText(alertGatewayDeployment, 'test "$domain_created_by_run" != true || ! valid_domain_id "$candidate_domain_id"', 'owned immutable alert-gateway domain rollback gate');
requireText(alertGatewayDeployment, 'api_delete "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains/$observed_domain"', 'exact immutable alert-gateway domain rollback');
requireText(alertGatewayDeployment, 'attest_previous_provider_state()', 'final alert-gateway rollback provider proof');
requireText(alertGatewayDeployment, 'attest_candidate_ingress()', 'post-health alert-gateway ingress proof');
requireText(alertGatewayDeployment, 'attest_candidate_provider_state()', 'final alert-gateway candidate provider proof');
requireText(alertGatewayDeployment, 'ssai-release-health-alert-gateway-health-v2', 'version-bound alert-gateway health schema');
requireText(alertGatewayDeployment, 'committed=false', 'armed alert-gateway transaction state');
requireText(alertGatewayDeployment, 'committed=true', 'atomic alert-gateway success commit');
requireText(alertGatewayDeployment, 'gateway_rollback_reserve_seconds=1200', 'hard alert-gateway rollback reserve');
requireText(alertGatewayDeployment, 'test "$now_epoch" -le "$gateway_promotion_deadline_epoch"', 'pre-promotion alert-gateway deadline gate');
requireText(alertGatewayDeployment, 'Record hard job budget', 'pre-checkout alert-gateway job budget start');
requireText(alertGatewayDeployment, 'request_timeout_seconds()', 'deadline-bounded alert-gateway API calls');
requireText(alertGatewayDeployment, 'bounded_sleep()', 'deadline-bounded alert-gateway convergence waits');
requireText(alertGatewayDeployment, 'require_forward_budget 900', 'minimum alert-gateway bootstrap budget');
requireText(alertGatewayDeployment, 'require_forward_budget 360', 'minimum immutable-candidate upload budget');
requireText(alertGatewayDeployment, 'require_forward_budget 300', 'minimum alert-gateway promotion convergence budget');
requireText(alertGatewayDeployment, 'rollback_mode=true', 'reserved alert-gateway rollback mode');
requireText(alertGatewayDeployment, 'trap - EXIT', 'non-recursive alert-gateway cleanup trap');
requireText(alertGatewayDeployment, 'set +e', 'best-effort alert-gateway rollback sequence');
requireText(alertGatewayDeployment, 'gateway_failure_stage=account-id-shape', 'initialized alert-gateway failure stage');
requireText(alertGatewayDeployment, 'report_gateway_failure_stage()', 'closed alert-gateway failure-stage reporter');
requireText(alertGatewayDeployment, '*) stage=unclassified ;;', 'fail-closed alert-gateway diagnostic fallback');
requireText(alertGatewayDeployment, 'Gateway deployment failed at an allowlisted stage (stage=%s).', 'redacted alert-gateway failure-stage annotation');
requireText(alertGatewayDeployment, 'report_gateway_failure_stage "$gateway_failure_stage"', 'normalized alert-gateway failure-stage emission');
rejectPattern(alertGatewayDeployment, /gateway_failure_stage=(?:"|'|\$|\{)/, 'dynamic alert-gateway diagnostic stage assignment');
const alertGatewayFailureReporter = alertGatewayDeployment.split('          report_gateway_failure_stage() {')[1].split('          request_timeout_seconds() {')[0];
rejectPattern(alertGatewayFailureReporter, /BASH_COMMAND|CLOUDFLARE_|RUNNER_TEMP|GATEWAY_DOMAIN|https?:|response|headers|GITHUB_(?:ENV|OUTPUT|STEP_SUMMARY)/i, 'sensitive alert-gateway failure diagnostics');
rejectPattern(alertGatewayDeployment, /\$RUNNER_TEMP\/gateway-bootstrap\.jsonc/, 'detached alert-gateway bootstrap config');
rejectPattern(alertGatewayDeployment, /wrangler\s+secret\s+put/i, 'non-atomic alert-gateway bootstrap secret mutation');
rejectPattern(alertGatewayDeployment, /wrangler\s+versions\s+deploy|wrangler\s+triggers\s+deploy/i, 'Wrangler alert-gateway production mutation');
rejectPattern(alertGatewayDeployment, /sort_by\(\.created_on\)|\|last\|/, 'undocumented alert-gateway deployment-history ordering');
rejectPattern(alertGatewayDeployment, /["']force["']\s*:\s*true/i, 'forced alert-gateway version rollback');
assert.equal((alertGatewayDeployment.match(/\?force=true/g) ?? []).length, 1, 'only the exact alert-gateway rollback helper may force a deployment');
const alertGatewayRollbackFunction = alertGatewayDeployment.split('          reconcile_traffic_rollback() {')[1].split('          attest_rollback_active() {')[0];
assert.ok(alertGatewayRollbackFunction.includes('deployments?force=true'), 'forced alert-gateway rollback must remain scoped to the provenance-gated helper');
rejectPattern(alertGatewayDeployment, /\b(?:domain_snapshot|previous_domain_snapshot)\b/, 'redundant serialized alert-gateway domain snapshot');
const alertGatewayDomainOkLine = alertGatewayDeployment.split('\n').find((line) => line.includes('domain_ok()'));
assert.ok(alertGatewayDomainOkLine, 'alert-gateway direct domain identity validator must exist');
for (const fieldCheck of ['.result.id==$id', '.result.hostname==$h', '.result.service==$s', '.result.zone_name==$z', '(.result.environment//"production")=="production"']) {
  requireText(alertGatewayDomainOkLine, fieldCheck, `alert-gateway direct routing identity check ${fieldCheck}`);
}
rejectPattern(alertGatewayDeployment, /^\s+(?:traffic_mutated|domain_attach_attempted|domain_created_by_run|bootstrap_mutation_attempted)=false\s*$/m, 'sequential alert-gateway rollback disarm');
rejectPattern(alertGatewayDeployment, /actions\/workflows\/\d+\/dispatches|gh\s+workflow\s+run/i, 'workflow dispatch from alert-gateway deployment');

assert.deepEqual(
  releaseHealthMonitorWorkflowIdentities,
  {
    active: { workflowId: 315630665, path: '.github/workflows/release-health-monitor.yml' },
    predecessor: { workflowId: 344135917, path: '.github/workflows/release-health-monitor-v3.yml' },
    canary: { workflowId: 344135917, path: '.github/workflows/release-health-monitor-v3.yml' },
    fallback: { workflowId: 344170407, path: '.github/workflows/release-health-monitor-fallback.yml' },
  },
  'the shared release-health identity registry must remain exact',
);
assert.deepEqual(
  releaseHealthIncidentProducerPolicies,
  {
    nativeSchedule: {
      kind: 'github-actions-workflow-run',
      policy: 'native-schedule-v1',
      workflowId: 315630665,
      path: '.github/workflows/release-health-monitor.yml',
      events: ['schedule'],
    },
    fallbackDispatch: {
      kind: 'github-actions-workflow-run',
      policy: 'independent-fallback-v1',
      workflowId: 344170407,
      path: '.github/workflows/release-health-monitor-fallback.yml',
      events: ['workflow_dispatch'],
    },
  },
  'F2b must authorize the exact native schedule and independent fallback producers',
);
assert.deepEqual(
  releaseHealthMonitorJobNames,
  {
    scan: 'Verify current organization release health',
    delivery: 'Deliver managed incident and conclude',
  },
  'the shared release-health job-name registry must remain exact',
);
assert.deepEqual(
  [...releaseHealth.matchAll(/^    name: (.+)$/gm)].map((match) => match[1]),
  [releaseHealthMonitorJobNames.scan, releaseHealthMonitorJobNames.delivery],
  'the authoritative workflow job names must exactly match the shared runtime registry',
);

for (const [name, source] of [
  ['renamed-cross-repository-delivery.yaml', 'env:\n  GH_TOKEN: ${{ secrets.SCALESMALL_PAT }}\n'],
  ['future-shared-sync.yml', "env:\n  GH_TOKEN: ${{ secrets['SCALESMALL_PAT'] }}\n"],
]) {
  assert.throws(
    () => assertNoLegacyCrossRepositoryPat(new Map([[name, source]])),
    new RegExp(`${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} references the retired SCALESMALL_PAT identifier`),
    `${name} must not bypass the fleet-wide retired credential guard`,
  );
}
assertNoLegacyCrossRepositoryPat(workflowSources);

requireText(validate, 'permissions:\n  contents: read', 'read-only workflow permissions');
requireText(validate, 'runs-on: ubuntu-24.04', 'pinned validation runner');
requireText(validate, 'persist-credentials: false', 'checkout credential isolation');
requireText(validate, "node-version: '24'", 'current Node runtime');
requireText(validate, 'run: npm run check', 'full shared package check');

const expectedRetiredPropagationSource = [
  'name: Propagate to consumer apps',
  '',
  'on:',
  '  workflow_dispatch:',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  retired:',
  '    if: ${{ false }}',
  '    runs-on: ubuntu-24.04',
  '    steps:',
  '      - name: Legacy propagation is permanently retired',
  '        run: |',
  '          echo "::error::Legacy shared propagation is permanently retired."',
  '          exit 1',
  '',
].join('\n');
assert.equal(
  propagate,
  expectedRetiredPropagationSource,
  'the legacy propagation workflow must remain the exact inert identity-preserving tombstone',
);
const retiredPropagationSourceSha256 = createHash('sha256').update(propagate).digest('hex');
assert.equal(
  retiredPropagationSourceSha256,
  '28650c6de12cfc94c165b2cb9c3dab1cb6bf1caf8de3815d67cf8bbe6c6b9ba2',
  'the retired propagation tombstone source digest must remain exact',
);
requireText(propagate, 'workflow_dispatch:', 'identity-preserving manual trigger tombstone');
requireText(propagate, 'permissions: {}', 'empty retired workflow permissions');
requireText(propagate, 'if: ${{ false }}', 'unconditionally false retired job gate');
requireText(propagate, 'runs-on: ubuntu-24.04', 'pinned retired workflow runner declaration');
rejectPattern(propagate, /^  (?:push|pull_request|schedule|repository_dispatch):/m, 'retired propagation event trigger');
rejectPattern(propagate, /(?:SCALESMALL_PAT|GH_TOKEN|repos\/ScaleSmall\/(?:SSAI_Connect|SSAI_Dashboard)|\/dispatches\b|gh\s+api\b)/, 'retired propagation credential, consumer, or dispatch path');
requireText(propagationRetirementRunbook, 'workflow identity\n`247016064`', 'retired propagation workflow identity runbook');
requireText(propagationRetirementRunbook, '`disabled_manually` state', 'permanent disabled-state runbook');
requireText(propagationRetirementRunbook, retiredPropagationSourceSha256, 'exact retired tombstone digest runbook');
requireText(propagationRetirementRunbook, 'There is no rollback procedure', 'no-reactivation retirement control');
requireText(propagationRetirementRunbook, 'Delete the `SCALESMALL_PAT` Actions secret', 'repository credential removal gate');
requireText(propagationRetirementRunbook, 'Do not create a replacement cross-repository PAT', 'replacement credential prohibition');
requireText(
  releaseHealthRunbook,
  '[Shared propagation retirement](./SHARED_PROPAGATION_RETIREMENT.md)',
  'release-health runbook pointer to the permanent retired hold',
);
rejectPattern(propagationRetirementRunbook, /gh\s+workflow\s+(?:enable|run)|\/actions\/workflows\/247016064\/(?:enable|dispatches)/i, 'retired propagation reactivation command');

const expectedReleaseHealthIdentityCanarySource = [
  'name: Scale Small AI Release Health Scheduler Identity Canary',
  'run-name: Release health scheduler identity canary [natural]',
  '',
  'on:',
  '  schedule:',
  "    - cron: '1,16,31,46 * * * *'",
  '',
  'concurrency:',
  '  group: scale-small-ai-release-health-monitor-v3-canary',
  '  cancel-in-progress: false',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  prove-natural-delivery:',
  '    name: Prove natural scheduler delivery',
  "    if: ${{ github.event_name == 'schedule' && github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}",
  '    runs-on: ubuntu-24.04',
  '    timeout-minutes: 2',
  '    steps:',
  '      - name: Verify immutable natural-schedule context',
  '        shell: bash',
  '        env:',
  '          ACTUAL_EVENT: ${{ github.event_name }}',
  '          ACTUAL_REF: ${{ github.ref }}',
  '          ACTUAL_REPOSITORY: ${{ github.repository }}',
  '          ACTUAL_SHA: ${{ github.sha }}',
  '          EXPECTED_REF: refs/heads/${{ github.event.repository.default_branch }}',
  '          EXPECTED_REPOSITORY: ScaleSmall/SSAI_Shared',
  '        run: |',
  '          set -euo pipefail',
  '          if [ "$ACTUAL_EVENT" != \'schedule\' ] || [ "$ACTUAL_REPOSITORY" != "$EXPECTED_REPOSITORY" ] || [ "$ACTUAL_REF" != "$EXPECTED_REF" ] || ! [[ "$ACTUAL_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
  '            echo "::error::Scheduler identity canary received an invalid execution context."',
  '            exit 1',
  '          fi',
  "          printf 'natural_schedule_delivery=verified\\n'",
  "          printf 'repository=%s\\n' \"$ACTUAL_REPOSITORY\"",
  "          printf 'ref=%s\\n' \"$ACTUAL_REF\"",
  "          printf 'sha=%s\\n' \"$ACTUAL_SHA\"",
  '',
].join('\n');

const assertReleaseHealthIdentityCanary = (source) => {
  assert.equal(
    source,
    expectedReleaseHealthIdentityCanarySource,
    'the scheduler identity canary must remain the exact schedule-only inert source',
  );
  rejectPattern(source, /^\s{2}(?:workflow_dispatch|push|pull_request|pull_request_target|repository_dispatch|workflow_call):/m, 'scheduler identity canary non-schedule trigger');
  rejectPattern(source, /\b(?:uses:|secrets\.|github\.token|GITHUB_TOKEN|https?:\/\/|curl\b|wget\b)/i, 'scheduler identity canary credential, action, or network access');
};

assertReleaseHealthIdentityCanary(releaseHealthIdentityCanary);
for (const [description, mutatedSource] of [
  ['manual trigger', releaseHealthIdentityCanary.replace('  schedule:\n', '  workflow_dispatch:\n  schedule:\n')],
  ['repository write permission', releaseHealthIdentityCanary.replace('permissions: {}', 'permissions:\n  contents: write')],
  ['secret access', `${releaseHealthIdentityCanary}# \${{ secrets.UNTRUSTED_SECRET }}\n`],
  ['third-party action', releaseHealthIdentityCanary.replace('    steps:\n', '    steps:\n      - uses: actions/checkout@untrusted\n')],
]) {
  assert.throws(
    () => assertReleaseHealthIdentityCanary(mutatedSource),
    /scheduler identity canary/,
    `the canary contract must reject ${description}`,
  );
}
const releaseHealthIdentityCanarySourceSha256 = createHash('sha256')
  .update(releaseHealthIdentityCanary)
  .digest('hex');
assert.equal(
  releaseHealthIdentityCanarySourceSha256,
  '3fe965ac8e77c17640fbc89633c230639c83d2e4e3ba0d43c9c50195338ce825',
  'the scheduler identity canary source digest must remain exact',
);

const expectedReleaseHealthFallbackRegistrationSource = [
  'name: Scale Small AI Release Health Independent Fallback (Registration)',
  'run-name: Release health independent fallback registration [inert]',
  '',
  'on:',
  '  workflow_dispatch:',
  '',
  'concurrency:',
  '  group: scale-small-ai-release-health-monitor-v2',
  '  cancel-in-progress: false',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  registration:',
  '    name: Register independent fallback workflow identity',
  '    if: ${{ false }}',
  '    permissions: {}',
  '    runs-on: ubuntu-24.04',
  '    timeout-minutes: 1',
  '    steps:',
  '      - name: Independent fallback remains inert until protected Stage F2',
  '        run: |',
  '          echo "::error::Independent release-health fallback is not activated."',
  '          exit 1',
  '',
].join('\n');

const assertReleaseHealthFallbackRegistration = (source) => {
  requireText(source, 'name: Scale Small AI Release Health Independent Fallback', 'activated independent fallback name');
  requireText(source, '  workflow_dispatch:', 'fallback workflow_dispatch-only trigger');
  requireText(source, '  queue: max', 'fallback lossless shared queue');
  requireText(source, '    name: Admit exact independent fallback request', 'pre-secret fallback admission');
  requireText(source, 'SSAI_RELEASE_MONITOR_FALLBACK_ADMISSION_HMAC_KEY', 'dedicated admission HMAC');
  requireText(source, 'ssai-release-health-state-v6-v1-', 'shared producer-neutral v6 cache namespace');
  assert.equal((source.match(/required: true/g) || []).length, 4, 'fallback must expose exactly four packed routing inputs');
  for (const input of ['envelope_base64url', 'slot_epoch_minute', 'request_id', 'signature_sha256']) {
    requireText(source, '      ' + input + ': { required: true, type: string }', 'exact packed fallback input ' + input);
  }
  requireText(source, "if: ${{ github.run_attempt == 1 }}", 'admission and scan rerun fence');
  requireText(source, "always() && github.run_attempt == 1", 'delivery rerun fence');
  requireText(source, 'Verify exact immutable slot claim visibility', 'exact claim post-save visibility');
  requireText(source, 'Verify exact authenticated state visibility', 'exact state post-save visibility');
  requireText(source, 'cmp --silent', 'fetched admission source byte comparison');
  rejectPattern(source, /^\s{2}(?:schedule|push|pull_request|pull_request_target|repository_dispatch|workflow_call):/m, 'fallback registration executable event trigger');
  rejectPattern(source, /^\s{2}(?:schedule|repository_dispatch):/m, 'fallback forbidden autonomous trigger');
};

assertReleaseHealthFallbackRegistration(releaseHealthFallbackRegistration);
const releaseHealthFallbackRegistrationSourceSha256 = createHash('sha256')
  .update(releaseHealthFallbackRegistration)
  .digest('hex');
assert.equal(
  releaseHealthFallbackRegistrationSourceSha256,
  '6fdb093c47e8631ea151b6f0a0aa5356db03c025a6813321f7f35e8bc6ed86b9',
  'the activated independent fallback source digest must remain exact',
);
assert.equal(
  releaseHealthFallbackNoHistoryExpiresAt,
  '2026-09-30T23:59:59Z',
  'fallback no-history expiry must remain the exact absolute observe-stage deadline',
);
requireText(releaseHealthRunbook, '## Scheduler identity recovery', 'bounded scheduler identity recovery procedure');
requireText(releaseHealthRunbook, '`.github/workflows/release-health-monitor-v3.yml`', 'replacement workflow path');
requireText(releaseHealthRunbook, releaseHealthIdentityCanarySourceSha256, 'exact canary source digest');
requireText(releaseHealthRunbook, 'Require two successful natural `schedule` runs', 'repeated natural-delivery acceptance gate');
requireText(releaseHealthRunbook, 'Do not leave two full\n   incident writers scheduled', 'single incident-writer cutover gate');
requireText(releaseHealthRunbook, 'require zero queued or in-progress runs', 'drained scheduler cutover gate');
requireText(releaseHealthRunbook, 'Rollback is also protected', 'protected scheduler rollback procedure');
requireText(releaseHealthRunbook, 'Any future hard timing\nrequirement needs a separately reviewed independent scheduler', 'explicit GitHub scheduler service-level boundary');
requireText(releaseHealthRunbook, '## Independent scheduler failover registration', 'bounded independent scheduler failover procedure');
requireText(releaseHealthRunbook, '`.github/workflows/release-health-monitor-fallback.yml`', 'independent fallback workflow path');
requireText(releaseHealthRunbook, releaseHealthFallbackRegistrationSourceSha256, 'exact independent fallback registration digest');
requireText(releaseHealthRunbook, 'Never dispatch Stage F1.', 'inert registration dispatch prohibition');
requireText(releaseHealthRunbook, 'Merge Stage F1 only through exact-head independent approval, hosted validation, and normal branch\nprotection.', 'protected Stage F1 merge gate');
requireText(releaseHealthRunbook, 'record the distinct numeric ID at\nthe exact fallback path and verify state `active`', 'post-merge distinct fallback identity proof');
requireText(releaseHealthRunbook, 'Do not change, dispatch, disable, or reinterpret\nthe existing monitor or native canary', 'native workflow non-mutation boundary');
requireText(releaseHealthRunbook, 'strongly consistent per-slot idempotency', 'independent controller idempotency requirement');
requireText(releaseHealthRunbook, 'Every fallback run must be labeled as fallback', 'fallback provenance boundary');
requireText(releaseHealthRunbook, 'two\nconsecutive exact native `schedule` runs', 'native recovery standby gate');
requireText(releaseHealthRunbook, 'Rollback is ordered: disable controller dispatch first, require zero queued or in-progress fallback\nruns', 'ordered fallback rollback gate');
requireText(releaseHealthRunbook, 'disable the fallback workflow through the official API', 'official fallback disable rollback gate');
requireText(releaseHealthRunbook, 'Preserve run and controller-ledger evidence.', 'fallback rollback evidence preservation');
requireText(releaseHealthRunbook, '## Protected F2a release-health foundation', 'protected F2a foundation contract');
requireText(releaseHealthRunbook, 'authoritative incident producer remains workflow ID `315630665`', 'native F2a producer authority');
requireText(releaseHealthRunbook, releaseHealthMonitorWorkflowIdentities.active.path, 'native F2a producer path');
requireText(releaseHealthRunbook, releaseHealthMonitorWorkflowIdentities.canary.path, 'explicit canary rejection path');
requireText(releaseHealthRunbook, releaseHealthMonitorWorkflowIdentities.fallback.path, 'explicit fallback rejection path');
requireText(releaseHealthRunbook, 'explicitly rejects both alternate IDs as state producers and managed-issue\nwriters', 'alternate producer and delivery rejection');
requireText(releaseHealthRunbook, 'queue: max', 'lossless authoritative writer queue');
requireText(releaseHealthRunbook, '### Authenticated producer-neutral v6 state', 'producer-neutral v6 state contract');
requireText(releaseHealthRunbook, 'producer kind and policy, workflow ID and path, event, run ID, run attempt,\nhead SHA, and authoritative run creation time', 'complete authenticated producer provenance');
requireText(releaseHealthRunbook, 'comes from the exact GitHub\nActions provider record selected by current run ID and attempt', 'provider-sourced producer creation time');
requireText(releaseHealthRunbook, 'Restore v6 first. Authenticated v4, v3, and v2 records', 'ordered authenticated state migrations');
requireText(releaseHealthRunbook, '### Managed issue ordering and marker upgrade', 'stale issue-write and marker upgrade contract');
requireText(releaseHealthRunbook, 'ordered first by authoritative provider creation time, then run ID, then attempt', 'authoritative issue-write ordering');
requireText(releaseHealthRunbook, 'valid legacy v1 delivery marker is read once and upgraded', 'managed issue marker upgrade');
requireText(releaseHealthRunbook, '### F2a acceptance evidence ledger', 'finite F2a acceptance ledger');
requireText(releaseHealthRunbook, '| Provider-bound v6 provenance |', 'producer provenance acceptance row');
requireText(
  releaseHealthRunbook,
  createHash('sha256').update(releaseHealth).digest('hex'),
  'exact authoritative workflow digest in the F2a runbook',
);
requireBalancedExpressions(releaseHealthIdentityCanary, 'release-health scheduler identity canary');
requireSpaceIndentation(releaseHealthIdentityCanary, 'release-health scheduler identity canary');
requireBalancedExpressions(releaseHealthFallbackRegistration, 'release-health fallback registration');
requireSpaceIndentation(releaseHealthFallbackRegistration, 'release-health fallback registration');

const expectedScanOutputs = [
  '    outputs:',
  '      scan_completed: ${{ steps.reconcile.outputs.scan_completed }}',
  '      health_degraded: ${{ steps.reconcile.outputs.health_degraded }}',
  '      incident_state_changed: ${{ steps.reconcile.outputs.incident_state_changed }}',
  '      state_persistence_required: ${{ steps.reconcile.outputs.state_persistence_required }}',
  '      incident_state: ${{ steps.reconcile.outputs.incident_state }}',
  '      notification_outcome: ${{ steps.reconcile.outputs.notification_outcome }}',
  '      notification_reconciliation_required: ${{ steps.reconcile.outputs.notification_reconciliation_required }}',
  '      incident_delivery_identity: ${{ steps.reconcile.outputs.incident_delivery_identity }}',
  '',
].join('\n');
const expectedScanPermissions = [
  '    permissions:',
  '      contents: read',
  '',
].join('\n');
const expectedDeliveryPermissions = [
  '    permissions:',
  '      actions: read',
  '      contents: read',
  '      issues: write',
  '',
].join('\n');

const assertAuthoritativeReleaseHealthIsolation = (source) => {
  requireText(source, 'permissions: {}\n\nenv:', 'empty top-level release-health permissions');
  assert.equal(
    (source.match(/^permissions:/gm) || []).length,
    1,
    'the authoritative release-health workflow must declare exactly one top-level permission contract',
  );
  assertSharedMonitorConcurrency(source, 'authoritative release-health workflow', true);
  assert.deepEqual(
    collectWorkflowJobNames(source, 'authoritative release-health workflow'),
    ['scan', 'deliver'],
    'the authoritative release-health workflow must expose only the scan and delivery jobs',
  );
  const scanJob = requireWorkflowJobBlock(source, 'scan', 'authoritative release-health workflow');
  const deliverJob = requireWorkflowJobBlock(source, 'deliver', 'authoritative release-health workflow');
  assert.equal(
    requireFlatJobMapping(scanJob, 'permissions', 'scan permissions'),
    expectedScanPermissions,
    'the scan job must remain contents-read only',
  );
  assert.equal(
    requireFlatJobMapping(deliverJob, 'permissions', 'delivery permissions'),
    expectedDeliveryPermissions,
    'the delivery job must have only actions/read, contents/read, and issues/write',
  );
  assert.equal(
    requireFlatJobMapping(scanJob, 'outputs', 'scan output allowlist'),
    expectedScanOutputs,
    'the scan job output allowlist must remain exact',
  );
  rejectPattern(scanJob, /^      issues:\s*write$/m, 'scan job issue write permission');
  rejectPattern(
    deliverJob,
    /(?:secrets\.|SSAI_RELEASE_MONITOR_APP_|SSAI_RELEASE_MONITOR_STATE_|state\.json|actions\/cache|release_health_app_token)/i,
    'delivery job App credential, state file, or cache access',
  );
  rejectPattern(source, /\bartifacts?\b|actions\/(?:upload|download)-artifact/i, 'release-health artifact transfer');
  assertProtectedWorkflowAdmission(
    scanJob,
    'scan job',
    '! [[ "$ACTUAL_EVENT" =~ ^(schedule|workflow_dispatch)$ ]]',
  );
  assertProtectedWorkflowAdmission(
    deliverJob,
    'delivery job',
    '[ "$ACTUAL_EVENT" != \'schedule\' ]',
  );
};

assertAuthoritativeReleaseHealthIsolation(releaseHealth);
for (const [description, mutatedSource] of [
  ['top-level write permission', releaseHealth.replace('permissions: {}\n\nenv:', 'permissions:\n  issues: write\n\nenv:')],
  ['scan issue mutation authority', releaseHealth.replace('    permissions:\n      contents: read\n', '    permissions:\n      contents: read\n      issues: write\n')],
  ['delivery App secret access', releaseHealth.replace('  deliver:\n', '  deliver:\n    env:\n      SSAI_RELEASE_MONITOR_APP_CLIENT_ID: ${{ secrets.SSAI_RELEASE_MONITOR_APP_CLIENT_ID }}\n')],
  ['unallowlisted scan output', releaseHealth.replace('      scan_completed:', '      internal_secret:\n      scan_completed:')],
  ['wrong protected workflow path', releaseHealth.replaceAll('release-health-monitor.yml@refs/heads/', 'release-health-monitor-v3.yml@refs/heads/')],
  ['missing lossless queue', releaseHealth.replace('  queue: max\n', '')],
  ['artifact transfer', `${releaseHealth}# artifacts\n`],
]) {
  assert.throws(
    () => assertAuthoritativeReleaseHealthIsolation(mutatedSource),
    /release-health|scan|delivery|workflow path|queue/i,
    `the authoritative release-health contract must reject ${description}`,
  );
}

const releaseHealthScheduleOwners = [...workflowSources]
  .filter(([name, source]) => name.startsWith('release-health-monitor') && /^  schedule:/m.test(source))
  .map(([name]) => name)
  .sort();
assert.deepEqual(
  releaseHealthScheduleOwners,
  ['release-health-monitor-v3.yml', 'release-health-monitor.yml'].sort(),
  'only the authoritative native monitor and inert scheduler canary may own release-health schedules in F2a',
);

requireText(releaseHealth, 'workflow_dispatch:', 'manual release-health control');
const releaseHealthCron = '9,24,39,54 * * * *';
requireText(releaseHealth, `cron: '${releaseHealthCron}'`, 'fleet-staggered 15-minute release-health schedule');
const releaseHealthMinutes = [...expandCronMinuteField(releaseHealthCron.split(/\s+/)[0], 'release-health monitor')]
  .sort((left, right) => left - right);
const cyclicReleaseHealthIntervals = releaseHealthMinutes.map((minute, index) => {
  const nextMinute = releaseHealthMinutes[(index + 1) % releaseHealthMinutes.length];
  return (nextMinute - minute + 60) % 60;
});
assert.deepEqual(cyclicReleaseHealthIntervals, [15, 15, 15, 15], 'release-health cadence must remain exactly 15 minutes');
const releaseHealthIdentityCanaryCron = '1,16,31,46 * * * *';
const releaseHealthIdentityCanaryMinutes = [...expandCronMinuteField(
  releaseHealthIdentityCanaryCron.split(/\s+/)[0],
  'release-health scheduler identity canary',
)].sort((left, right) => left - right);
const cyclicReleaseHealthIdentityCanaryIntervals = releaseHealthIdentityCanaryMinutes.map((minute, index) => {
  const nextMinute = releaseHealthIdentityCanaryMinutes[(index + 1) % releaseHealthIdentityCanaryMinutes.length];
  return (nextMinute - minute + 60) % 60;
});
assert.deepEqual(
  cyclicReleaseHealthIdentityCanaryIntervals,
  [15, 15, 15, 15],
  'scheduler identity canary cadence must remain exactly 15 minutes',
);
assert.deepEqual(
  releaseHealthIdentityCanaryMinutes.filter((minute) => releaseHealthMinutes.includes(minute)),
  [],
  'scheduler identity canary must not collide with the current monitor',
);
// Keep these minute fields aligned with every in-scope fleet cron so the monitor
// does not sample partial state while scheduled production work is starting.
const fleetScheduleMinuteReservations = new Map([
  ['SSAI_AI_Audit production-canary.yml', '17 14 * * *'],
  ['SSAI_Analytics_Reporting monthly-reporting.yml monthly', '20 7 1 * *'],
  ['SSAI_Analytics_Reporting monthly-reporting.yml daily', '35 7 * * *'],
  ['SSAI_Analytics_Reporting production-hardening.yml', '37 13 * * *'],
  ['SSAI_Analytics_Reporting production-pages-canary.yml', '17 12 * * *'],
  ['SSAI_CI_Engine production-ci-worker.yml', '7-57/10 * * * *'],
  ['SSAI_Content_Engine production-content-engine-worker.yml', '*/10 * * * *'],
  ['SSAI_Dashboard pull-shared-with-protected-evidence.yml', '11 * * * *'],
  ['SSAI_PoW n8n-production-exactness.yml', '19 */6 * * *'],
  ['SSAI_Production_QA production-service-canaries.yml', '37 * * * *'],
]);
for (const [reservation, cron] of fleetScheduleMinuteReservations) {
  const reservedMinutes = expandCronMinuteField(cron.split(/\s+/)[0], reservation);
  const collisions = releaseHealthMinutes.filter((minute) => reservedMinutes.has(minute));
  if (collisions.length > 0) {
    throw new Error(`Release-health schedule collides with ${reservation} at minute(s): ${collisions.join(', ')}`);
  }
  const canaryCollisions = releaseHealthIdentityCanaryMinutes.filter((minute) => reservedMinutes.has(minute));
  if (canaryCollisions.length > 0) {
    throw new Error(`Scheduler identity canary collides with ${reservation} at minute(s): ${canaryCollisions.join(', ')}`);
  }
}
rejectPattern(releaseHealth, /(?:actions|checks|contents|deployments|packages|pull-requests|statuses|workflows): write/, 'unapproved release-health write permission');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-cancelling release-health serialization');
requireText(releaseHealth, 'runs-on: ubuntu-24.04', 'pinned release-health runner');
requireText(releaseHealth, 'persist-credentials: false', 'release-health checkout credential isolation');
requireText(releaseHealth, "node-version: '24'", 'release-health Node runtime');
requireText(releaseHealth, 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1', 'immutable release-health GitHub App token action');
requireText(releaseHealth, 'client-id: ${{ secrets.SSAI_RELEASE_MONITOR_APP_CLIENT_ID }}', 'dedicated release-health GitHub App client ID');
requireText(releaseHealth, 'private-key: ${{ secrets.SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY }}', 'dedicated release-health GitHub App private key');
requireText(releaseHealth, 'owner: ScaleSmall', 'personal-account GitHub App installation owner');
for (const permission of ['actions', 'checks', 'contents', 'deployments', 'metadata', 'pull-requests', 'statuses']) {
  requireText(releaseHealth, `permission-${permission}: read`, `read-only GitHub App ${permission} permission`);
}
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN: ${{ steps.release_health_app_token.outputs.token }}', 'short-lived release-health installation token source');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_INSTALLATION_ID: ${{ steps.release_health_app_token.outputs.installation-id }}', 'release-health installation identity gate');
rejectPattern(releaseHealth, /SSAI_RELEASE_MONITOR_READ_TOKEN/, 'unsupported fine-grained PAT release-health source');
rejectPattern(releaseHealth, /SSAI_RELEASE_MONITOR_GITHUB_TOKEN:\s*\$\{\{\s*secrets\.SCALESMALL_PAT\s*\}\}/, 'legacy shared PAT as the release-health token');
rejectPattern(releaseHealth, /skip-token-revoke:\s*['"]?true/i, 'installation token revocation bypass');
requireText(releaseHealth, 'environment:\n      name: release-health-monitor', 'protected release-health environment binding');
requireText(
  releaseHealth,
  "if: ${{ github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}",
  'server-side default-branch scan gate',
);
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256: ${{ secrets.SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256 }}', 'protected expected-inventory attestation');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY: ${{ secrets.SSAI_RELEASE_MONITOR_STATE_HMAC_KEY }}', 'dedicated protected state HMAC key');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_HMAC_EPOCH: v1', 'explicit state HMAC epoch');
const scanJob = requireWorkflowJobBlock(releaseHealth, 'scan', 'authoritative release-health workflow');
const deliveryJob = requireWorkflowJobBlock(releaseHealth, 'deliver', 'authoritative release-health workflow');
const scanJobHeader = scanJob.slice(0, scanJob.indexOf('    steps:\n'));
rejectPattern(scanJobHeader, /secrets\./, 'fleet secrets exposed to job-level actions');
for (const secretName of ['SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256', 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY']) {
  const references = releaseHealth.match(new RegExp(`secrets\\.${secretName}`, 'g')) || [];
  assert.equal(references.length, 2, `${secretName} must be scoped only to preflight and reconcile steps`);
}
for (const secretName of ['SSAI_RELEASE_MONITOR_APP_CLIENT_ID', 'SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY']) {
  const references = releaseHealth.match(new RegExp(`secrets\\.${secretName}`, 'g')) || [];
  assert.equal(references.length, 1, `${secretName} must be scoped only to the installation-token mint step`);
}
assert.equal(
  (releaseHealth.match(/steps\.release_health_app_token\.outputs\.token/g) || []).length,
  2,
  'the short-lived installation token must be scoped only to preflight and reconcile steps',
);
requireText(releaseHealth, 'scan_mode:', 'explicit continuous/incident release-health mode');
requireText(releaseHealth, 'type: choice', 'validated release-health mode choice');
requireText(releaseHealth, '          - continuous\n          - incident', 'release-health mode options');
requireText(releaseHealth, "run-name: Release health monitor [${{ inputs.scan_mode == 'incident' && 'incident:168h' || format('continuous:{0}h', inputs.lookback_hours || '6') }}]", 'incident-exhaustive release-health run identity');
requireText(releaseHealth, 'lookback_hours:', 'manual release-health lookback control');
requireText(releaseHealth, "default: '6'", 'bounded scheduled release-health lookback default');
requireText(releaseHealth, "timeout-minutes: ${{ inputs.scan_mode == 'incident' && 45 || 12 }}", 'mode-bounded release-health timeout');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MODE: ${{ inputs.scan_mode || 'continuous' }}", 'release-health scan mode');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_LOOKBACK_HOURS: ${{ inputs.scan_mode == 'incident' && '168' || inputs.lookback_hours || '6' }}", 'forced exhaustive incident lookback');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MAX_REQUESTS: ${{ inputs.scan_mode == 'incident' && '3500' || '600' }}", 'release-health API request budget');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_RATE_RESERVE: ${{ inputs.scan_mode == 'incident' && '250' || '1000' }}", 'release-health API reserve');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_API_CONCURRENCY: '6'", 'release-health global API concurrency');
requireText(releaseHealth, 'group: scale-small-ai-release-health-monitor-v2', 'orphan-isolated serialized release-health concurrency');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-destructive release-health concurrency');
requireText(releaseHealth, 'actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state restore');
requireText(releaseHealth, 'actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state save');
requireText(releaseHealth, 'key: ssai-release-health-state-v6-v1-lookup', 'non-sensitive v6 fixed cache lookup key');
requireText(
  releaseHealth,
  'restore-keys: |\n            ssai-release-health-state-v6-v1-\n            ssai-release-health-state-v4-v1-\n            ssai-release-health-state-v3-v1-\n            ssai-release-health-state-v2-v1-',
  'ordered v6, v4, v3, and v2 authenticated state restoration',
);
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_CACHE_PREFIX: ssai-release-health-state-v6-v1-', 'v6 authenticated cache save prefix');
rejectPattern(releaseHealth, /state-v\d+[^\n]*github\.run_id/, 'source run ID in public cache action key');
requireText(releaseHealth, "if: ${{ github.event_name == 'schedule' }}", 'schedule-only state restore');
assert.equal(
  (releaseHealth.match(/always\(\) && github\.event_name == 'schedule' && steps\.reconcile\.outputs\.state_persistence_required == 'true'/g) || []).length,
  3,
  'save, lookup verification, and persistence assertion must all use state_persistence_required',
);
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}', 'default-branch state provenance');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_CACHE_MATCHED_KEY:', 'immutable restored cache identity handoff');
assert.equal(
  (releaseHealth.match(/key: \$\{\{ steps\.reconcile\.outputs\.incident_state_cache_key \}\}/g) || []).length,
  2,
  'the v6 content-digested key must bind both cache save and exact lookup verification',
);
requireText(releaseHealth, 'id: verify_release_health_state', 'post-save cache visibility verification');
requireText(releaseHealth, 'lookup-only: true', 'side-effect-free cache visibility verification');
requireText(releaseHealth, 'fail-on-cache-miss: true', 'fail-closed missing changed-state cache');
requireText(releaseHealth, 'STATE_CACHE_HIT: ${{ steps.verify_release_health_state.outputs.cache-hit }}', 'cache feature-availability output gate');
requireText(releaseHealth, 'MATCHED_STATE_KEY: ${{ steps.verify_release_health_state.outputs.cache-matched-key }}', 'exact persisted cache identity gate');
requireText(releaseHealth, 'id: require_release_health_state', 'exact persistence assertion outcome gate');
requireText(releaseHealth, '::error::Release-health monitor failed closed', 'generic fail-closed state-persistence error');
rejectPattern(releaseHealth, /Changed release-health incident state was not durably persisted/, 'detailed public state-persistence error');
rejectPattern(releaseHealth, /continue-on-error:\s*true/, 'state restore/save failure suppression');
requireText(releaseHealth, 'notification_reconciliation_required', 'schedule-time incident reconciliation gate');
requireText(releaseHealth, "needs.scan.result == 'success'", 'successful scan job before incident reconciliation');
requireText(releaseHealth, "needs.scan.outputs.scan_completed == 'true'", 'explicit completed-scan delivery gate');
requireText(releaseHealth, "needs.scan.outputs.notification_reconciliation_required == 'true'", 'explicit notification reconciliation gate');
requireText(releaseHealth, "needs.scan.outputs.health_degraded == 'true'", 'degraded scheduled conclusion restored after delivery');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_DEFER_DEGRADED_EXIT:', 'scheduled scan and health conclusion decoupling');
requireText(deliveryJob, 'GITHUB_TOKEN: ${{ github.token }}', 'job-scoped same-repository issue token');
requireText(deliveryJob, 'SSAI_RELEASE_MONITOR_INCIDENT_STATE: ${{ needs.scan.outputs.incident_state }}', 'desired managed issue state handoff');
requireText(deliveryJob, 'SSAI_RELEASE_MONITOR_NOTIFICATION_OUTCOME: ${{ needs.scan.outputs.notification_outcome }}', 'allowlisted incident outcome handoff');
requireText(deliveryJob, 'SSAI_RELEASE_MONITOR_DELIVERY_IDENTITY: ${{ needs.scan.outputs.incident_delivery_identity }}', 'durable non-sensitive delivery identity handoff');
requireText(releaseHealth, 'node scripts/sync-release-health-incident-issue.mjs', 'managed issue incident delivery');
requireText(releaseHealth, "await import('./scripts/verify-org-release-health.mjs')", 'workflow-attested dynamic monitor bootstrap');
requireText(releaseHealth, 'executeReleaseHealthMonitorEntryPoint(monitor.runReleaseHealthMonitor)', 'redacted organization release-health entry point');
rejectPattern(releaseHealth, /run:\s*node scripts\/verify-org-release-health\.mjs/, 'unwrapped hosted monitor execution');
requireText(releaseHealthVerifier, 'latestByIdentity(', 'latest current-check selection');
requireText(releaseHealthVerifier, 'evaluateNoHistoryAllowance(', 'evidence-gated manual workflow allowance');
requireText(releaseHealthVerifier, 'collectWorkflowSource(', 'exact no-history workflow source verification');
requireText(releaseHealthVerifier, 'sourceSha256:', 'approved workflow source digest');
requireText(releaseHealthVerifier, 'partitionWorkflowHealth(', 'exhaustive workflow health categorization');
requireText(releaseHealthVerifier, 'workflow_categories_complete', 'workflow category completeness assertion');
requireText(releaseHealthVerifier, 'unresolved_no_history_workflows', 'explicit unresolved no-history accounting');
requireText(releaseHealthVerifier, 'allowed_no_history_evidence', 'auditable no-history evidence summary');
requireText(releaseHealthVerifier, 'workflow_id: row.no_history_workflow_id', 'no-history workflow ID evidence handoff');
requireText(releaseHealthVerifier, 'observe_stage_expires_at: row.no_history_observe_stage_expires_at', 'no-history expiry evidence handoff');
requireText(releaseHealthVerifier, 'recovery_evidence: row.no_history_recovery_evidence', 'no-history recovery classification handoff');
requireText(releaseHealthVerifier, 'verifyAuthorizedDisabledWorkflowHold(', 'source-hashed authorized disabled workflow hold');
requireText(releaseHealthVerifier, 'authorized_disabled_workflow_hold_evidence', 'auditable disabled workflow hold summary');
requireText(releaseHealthVerifier, "if (!isUtf8(source)) throw new Error(repoName + ' workflow source for ' + path + ' is not valid UTF-8.');", 'fail-closed workflow source encoding gate');
requireText(releaseHealthVerifier, "return Buffer.from(source.toString('utf8').replace(/\\r\\n?/g, '\\n'), 'utf8');", 'runtime LF-normalized workflow source digest');
requireText(releaseHealthVerifier, 'verifyForwardFixRecoveryPolicy(', 'source-hashed current-main forward-fix policy');
requireText(releaseHealthVerifier, 'findForwardFixWorkflowRun(', 'bounded cross-trigger workflow forward-fix recovery');
requireText(releaseHealthVerifier, 'findForwardFixCheck(', 'bounded cross-trigger check forward-fix recovery');
const productionQaPolicyFields = [
  ['workflowId: 299211649', 'workflow identity'],
  ["name: 'Production Service Delivery Canaries'", 'workflow name'],
  ["path: '.github/workflows/production-service-canaries.yml'", 'workflow path'],
  ["state: 'disabled_manually'", 'exact authorized disabled state'],
  ["sourceSha256: '50e5c6f7f01364f2b24c7dc7e3082f60959af9b2f048784c73a697677d179591'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Production_QA'", 'repository boundary'],
  ['reason:', 'explicit hold rationale'],
];
const productionQaPolicyBlock = requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Production_QA:299211649',
  productionQaPolicyFields,
);
rejectPattern(
  productionQaPolicyBlock,
  /failedEvents|recoveryEvents|jobNames|recoveryDisplayTitles|monitorSelfRecovery/,
  'authorized disabled workflow hold carrying recovery semantics',
);
const retiredPropagationPolicyFields = [
  ['workflowId: 247016064', 'workflow identity'],
  ["name: 'Propagate to consumer apps'", 'workflow name'],
  ["path: '.github/workflows/propagate.yml'", 'workflow path'],
  ["state: 'disabled_manually'", 'exact authorized disabled state'],
  ["sourceSha256: '28650c6de12cfc94c165b2cb9c3dab1cb6bf1caf8de3815d67cf8bbe6c6b9ba2'", 'exact retired tombstone source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Shared'", 'repository boundary'],
  ['reason:', 'explicit permanent-retirement rationale'],
];
const retiredPropagationPolicyBlock = requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Shared:247016064',
  retiredPropagationPolicyFields,
);
rejectPattern(
  retiredPropagationPolicyBlock,
  /failedEvents|recoveryEvents|jobNames|recoveryDisplayTitles|monitorSelfRecovery/,
  'retired propagation hold carrying recovery semantics',
);
assert.equal(
  (releaseHealthVerifier.match(/SSAI_Shared:247016064/g) || []).length,
  1,
  'the retired propagation hold must have exactly one policy definition',
);
const forwardFixPolicySection = releaseHealthVerifier.slice(
  releaseHealthVerifier.indexOf('const forwardFixRecoveryPolicies = new Map(['),
);
rejectPattern(
  forwardFixPolicySection,
  /SSAI_Production_QA:299211649/,
  'obsolete Production QA forward-fix recovery policy',
);
rejectPattern(
  forwardFixPolicySection,
  /SSAI_Shared:247016064/,
  'retired propagation forward-fix recovery policy',
);
const rrPolicyFields = [
  ['workflowId: 289080389', 'workflow identity'],
  ["path: '.github/workflows/deploy-supabase-functions.yml'", 'workflow path'],
  ["sourceSha256: '44fcccc745924b8c70d75ca999ac7fad8cdb8ecdfa521e34018884bcf754e972'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_RR'", 'repository boundary'],
  ["failedEvents: ['push']", 'failed trigger boundary'],
  ["recoveryEvents: ['workflow_dispatch']", 'recovery trigger boundary'],
  ["jobNames: ['production-schema-preflight']", 'failed production job boundary'],
  ["recoveryDisplayTitles: ['Deploy R&R Supabase Functions']", 'recovery run identity'],
];
requireRecoveryPolicyBlock(releaseHealthVerifier, 'SSAI_RR:289080389', rrPolicyFields);
const dashboardSharedProofNoHistoryFields = [
  ['workflowId: 319513883', 'workflow identity'],
  ["path: '.github/workflows/prove-shared-update-release.yml'", 'workflow path'],
  ["sourceSha256: 'b923e5d10b1a47514c276edcc9ff20af41e9f0714e3877e7cc5cfe52bff3b679'", 'current-main source digest'],
  ["name: 'Dashboard full gate'", 'witness workflow name'],
  ["path: '.github/workflows/dashboard-full-gate.yml'", 'witness workflow path'],
  ["headRepository: 'ScaleSmall/SSAI_Dashboard'", 'witness repository boundary'],
  ["allowedEvents: ['push']", 'witness trigger boundary'],
  ['maxAgeHours: 168', 'witness freshness boundary'],
];
requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Dashboard:Prove Shared update release',
  dashboardSharedProofNoHistoryFields,
);
const connectSharedProofNoHistoryFields = [
  ['workflowId: 325199090', 'workflow identity'],
  ["path: '.github/workflows/prove-shared-update-release.yml'", 'workflow path'],
  ["sourceSha256: 'c928cf671d724a788e56a91a65c2eb6a4555e56e6e6d57b6931faadc3cd3787c'", 'current-main source digest'],
  ["name: 'Validate Connect app'", 'witness workflow name'],
  ["path: '.github/workflows/validate.yml'", 'witness workflow path'],
  ["headRepository: 'ScaleSmall/SSAI_Connect'", 'witness repository boundary'],
  ["allowedEvents: ['push']", 'witness trigger boundary'],
  ['maxAgeHours: 168', 'witness freshness boundary'],
];
requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Connect:Prove Shared update release',
  connectSharedProofNoHistoryFields,
);
const powTrustedPrNoHistoryFields = [
  ['workflowId: 342400655', 'workflow identity'],
  ["path: '.github/workflows/trusted-pr-boundaries.yml'", 'workflow path'],
  ["sourceSha256: '1d9f006139fa9586541b66fdad000893adebbed725d4cd37122f2075693fce4e'", 'current-main source digest'],
  ["name: 'Validate boundaries'", 'witness workflow name'],
  ["path: '.github/workflows/validate-boundaries.yml'", 'witness workflow path'],
  ["headRepository: 'ScaleSmall/SSAI_PoW'", 'witness repository boundary'],
  ["allowedEvents: ['push']", 'witness trigger boundary'],
  ['maxAgeHours: 168', 'witness freshness boundary'],
];
requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_PoW:Trusted PR boundaries',
  powTrustedPrNoHistoryFields,
);
const napEntityForwardFixFields = [
  ['workflowId: 281872550', 'workflow identity'],
  ["path: '.github/workflows/deploy.yml'", 'workflow path'],
  ["sourceSha256: 'c9498d70b4ad923090329e50872bee115d5bda50e512a64a0c0b4a94fb0aa8cb'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_NAP_Entity'", 'repository boundary'],
  ["failedEvents: ['workflow_dispatch']", 'failed trigger boundary'],
  ["recoveryEvents: ['push']", 'recovery trigger boundary'],
  ["jobNames: ['deploy']", 'failed production job boundary'],
  ["recoveryDisplayTitles: ['fix: adopt canonical production inventory verifier']", 'recovery run identity'],
];
requireRecoveryPolicyBlock(releaseHealthVerifier, 'SSAI_NAP_Entity:281872550', napEntityForwardFixFields);
const analyticsMonthlyForwardFixFields = [
  ['workflowId: 296737111', 'workflow identity'],
  ["path: '.github/workflows/monthly-reporting.yml'", 'workflow path'],
  ["sourceSha256: '4fbc2bc41f5aad6bae046ae058c9ba31147f0c2df34df4bb0537af130b0d6ff0'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Analytics_Reporting'", 'repository boundary'],
  ["failedEvents: ['workflow_dispatch']", 'failed trigger boundary'],
  ["recoveryEvents: ['schedule']", 'recovery trigger boundary'],
  ["jobNames: ['full-crawler']", 'failed production job boundary'],
  ["recoveryDisplayTitles: ['Monthly Reporting Collection']", 'recovery run identity'],
];
requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Analytics_Reporting:296737111',
  analyticsMonthlyForwardFixFields,
);
assert.throws(
  () => assertRecoveryPolicyFields(
    productionQaPolicyBlock.replace("state: 'disabled_manually'", "state: 'active'"),
    'SSAI_Production_QA:299211649',
    productionQaPolicyFields,
  ),
  /exact authorized disabled state/,
  'a mutated disabled hold state must fail the policy contract',
);
requireText(releaseHealthVerifier, 'findProvisionalForwardFixWorkflowRecovery(', 'bounded forward-fix workflow self-latch');
requireText(releaseHealthVerifier, 'findProvisionalForwardFixCheckRecovery(', 'bounded forward-fix check self-latch');
requireText(releaseHealthVerifier, 'findTrustedMonitorCheckRecovery(', 'source-verified monitor check recovery');
requireText(releaseHealthVerifier, 'findProvisionalTrustedMonitorCheckRecoveryFromRun(', 'check-index-independent monitor self-latch');
requireText(releaseHealthVerifier, 'isTrustedMonitorRecoveryPolicy(', 'explicit trusted-monitor policy gate');
requireText(releaseHealthVerifier, 'isControlledDisabledMonitorRecoveryWorkflow(', 'exact controlled runbook re-disable policy gate');
requireText(releaseHealthVerifier, 'repo.name,\n    allWorkflows,\n    headSha,\n    { recentRuns, defaultBranch },', 'disabled monitor policy resolution without active-health inclusion');
requireText(releaseHealthVerifier, 'findPolicyBoundWorkflowRecovery(', 'coverage-aware workflow recovery selection');
requireText(releaseHealthVerifier, 'findPolicyBoundCheckRecovery(', 'coverage-aware check recovery selection');
requireText(releaseHealthVerifier, 'const directRecovery = trustedMonitorPolicy ? null : policyBoundRecovery;', 'trusted monitor generic-recovery bypass prevention');
requireText(releaseHealthVerifier, "monitorSelfRecoveryContract: 'release-health-monitor-v1'", 'trusted monitor recovery contract');
requireText(releaseHealthUtils, 'export const releaseHealthMonitorWorkflowIdentities = Object.freeze({', 'canonical workflow identity registry');
requireText(releaseHealthUtils, 'active: authoritativeNativeWorkflowIdentity', 'canonical native authoritative workflow identity');
requireText(releaseHealthUtils, 'predecessor: schedulerCanaryWorkflowIdentity', 'canonical rejected canary identity');
requireText(releaseHealthUtils, 'fallback: fallbackWorkflowIdentity', 'canonical rejected fallback identity');
requireText(releaseHealthUtils, 'export const releaseHealthIncidentProducerPolicies = Object.freeze({', 'producer policy registry');
requireText(releaseHealthUtils, "policy: 'native-schedule-v1'", 'native producer policy identifier');
requireText(releaseHealthUtils, "events: Object.freeze(['schedule'])", 'native schedule-only producer event boundary');
requireText(releaseHealthUtils, 'export function resolveReleaseHealthIncidentProducer(', 'central producer authorization resolver');
requireText(releaseHealthVerifier, "const activeReleaseHealthPolicyKey = 'SSAI_Shared:'\n  + releaseHealthMonitorWorkflowIdentities.active.workflowId;", 'derived active recovery-policy key');
requireText(releaseHealthVerifier, 'releaseHealthIncidentProducerPolicies,', 'verifier producer policy import');
requireText(releaseHealthVerifier, 'resolveReleaseHealthIncidentProducer,', 'verifier producer resolver import');
rejectPattern(releaseHealthVerifier, /export const releaseHealthMonitorWorkflowIdentities\s*=\s*Object\.freeze/, 'duplicate verifier workflow identity registry');
requireText(releaseHealthDelivery, 'releaseHealthIncidentProducerPolicies,', 'incident delivery producer policy import');
requireText(releaseHealthDelivery, 'resolveReleaseHealthIncidentProducer,', 'incident delivery producer resolver import');
requireText(releaseHealthDelivery, 'export const activeIncidentWorkflowId = releaseHealthIncidentProducerPolicies.nativeSchedule.workflowId;', 'derived authoritative incident workflow identity');
requireText(releaseHealthDelivery, 'export const rejectedCanaryWorkflowId = releaseHealthMonitorWorkflowIdentities.canary.workflowId;', 'explicit canary incident delivery rejection identity');
requireText(releaseHealthDelivery, 'export const fallbackIncidentWorkflowId = releaseHealthIncidentProducerPolicies.fallbackDispatch.workflowId;', 'explicit fallback incident delivery authorization identity');
requireText(releaseHealthDelivery, "'/attempts/' + runAttempt", 'exact issue-delivery run-attempt provider fetch');
requireText(releaseHealthDelivery, 'compareAuthoritativeRuns(', 'authoritative stale issue-write ordering');
requireText(releaseHealthDelivery, 'parseIssueDeliveryReference(', 'v1 and v2 managed issue marker decoder');
requireText(releaseHealthDelivery, 'incidentDeliveryMarker(deliveryIdentity, producer.workflowId)', 'producer-authenticated v2 issue marker writer');
requireText(releaseHealthVerifier, 'const exactNativeProducer = workflowId === releaseHealthMonitorWorkflowIdentities.active.workflowId', 'native self-deployment workflow identity binding');
requireText(releaseHealthVerifier, 'source_run_attempt:', 'exact current run-attempt binding');
requireText(releaseHealthVerifier, "'incident_delivery_identity=' + exactIncidentDeliveryIdentity", 'authenticated stable delivery identity output');
requireText(releaseHealthVerifier, 'incidentDeliveryIdentity: state.delivery_identity', 'restored delivery identity reconciliation');
requireText(releaseHealthVerifier, 'const incidentStateSchema = 6', 'producer-neutral authenticated v6 incident-state schema');
requireText(releaseHealthVerifier, 'const predecessorIncidentStateSchema = 4', 'authenticated predecessor v4 state schema');
requireText(releaseHealthVerifier, 'const previousIncidentStateSchema = 3', 'explicit previous-state migration schema');
requireText(releaseHealthVerifier, 'const legacyIncidentStateSchema = 2', 'explicit legacy-state migration schema');
requireText(releaseHealthVerifier, 'validatePredecessorPersistedIncidentState(', 'authenticated v4-to-v6 predecessor migration');
requireText(releaseHealthVerifier, 'validatePreviousPersistedIncidentState(', 'authenticated v3-to-v6 state migration');
requireText(releaseHealthVerifier, 'validateLegacyPersistedIncidentState(', 'authenticated v2-to-v6 state migration');
requireText(releaseHealthVerifier, "const expectedCachePrefix = 'ssai-release-health-state-v6-'", 'active v6 cache provenance boundary');
requireText(releaseHealthVerifier, "const predecessorCachePrefix = 'ssai-release-health-state-v4-'", 'predecessor v4 cache provenance boundary');
requireText(releaseHealthVerifier, "const previousCachePrefix = 'ssai-release-health-state-v3-'", 'previous-state cache provenance boundary');
requireText(releaseHealthVerifier, "const legacyCachePrefix = 'ssai-release-health-state-v2-'", 'legacy-state cache provenance boundary');
requireText(releaseHealthVerifier, 'const producerAuthorityAdvanced = Boolean(producer !== null && previous?.producerAuthority);', 'strictly newer authenticated producer watermark detection');
requireText(releaseHealthVerifier, 'const statePersistenceRequired = stateMigrationRequired || changed || producerAuthorityAdvanced;', 'mandatory v6 persistence after migration, semantic change, or authority advance');
requireText(releaseHealthVerifier, 'decision.changed || decision.stateMigrationRequired || decision.producerAuthorityAdvanced', 'authority-only persistence decision validation');
requireText(releaseHealthVerifier, 'producerAuthority: Object.freeze({', 'authenticated v6 producer authority restoration');
requireText(releaseHealthVerifier, 'compareScheduledIncidentProducerAuthority(producer, previous.producerAuthority) <= 0', 'stale and equal cache producer suppression');
requireText(releaseHealthVerifier, "!/^ssai-release-health-state-v6-v1-at-", 'v6 content-digested cache-key validation');
requireText(releaseHealthVerifier, 'export function validateScheduledIncidentProducerRun(run, expected)', 'provider-attested producer run validator');
for (const field of [
  'producer_policy',
  'producer_kind',
  'producer_workflow_id',
  'producer_workflow_path',
  'producer_event',
  'producer_run_id',
  'producer_run_attempt',
  'producer_head_sha',
  'producer_created_at',
]) {
  requireText(releaseHealthVerifier, `${field}: producerExecution.`, `authenticated v6 ${field} field`);
}
requireText(releaseHealthVerifier, 'const createdAt = canonicalGitHubTimestamp(run.created_at);', 'authoritative provider run creation time');
requireText(releaseHealthVerifier, "const currentWorkflowHeadSha = String(process.env.GITHUB_SHA || '').trim().toLowerCase();", 'immutable executing workflow SHA binding');
requireText(releaseHealthVerifier, 'headSha: currentWorkflowHeadSha', 'provider evidence bound to immutable GITHUB_SHA');
requireText(releaseHealthVerifier, 'await mapLimit(repositories, 4, (repo) => inspectRepository(repo, scheduledStateEnabled));', 'scheduled incident-state gate passed explicitly into repository scans');
requireText(releaseHealthVerifier, 'async function inspectRepository(repo, scheduledStateEnabled)', 'repository scan scheduled-state gate parameter');
requireText(releaseHealthVerifier, "if (typeof scheduledStateEnabled !== 'boolean')", 'repository scan scheduled-state gate type guard');
requireText(releaseHealthVerifier, 'incident_state_producer: incidentStateProducer', 'provider record threaded into repository scan output');
requireText(releaseHealthVerifier, 'const stateProducers = rows.map((row) => row.incident_state_producer).filter(Boolean);', 'single provider-attested producer selection');
requireText(releaseHealthVerifier, 'stateProducers.length !== 1', 'fail-closed producer cardinality');
requireText(releaseHealthVerifier, 'producer: stateProducers[0] || null', 'provider execution threaded into scheduled state persistence');
requireText(releaseHealthDelivery, 'assertSameMarkerSnapshotUnchanged(initialIssue, exactIssue);', 'same-marker issue snapshot mutation fence');
requireText(releaseHealthDelivery, 'const initialRun = await validatePriorRun(api, initialReference);', 'initial marker provider metadata prefetch before final issue read');
requireText(releaseHealthDelivery, 'let exactIssue = validateExactManagedIssue(await api(issuePath), number);', 'single immediate exact issue re-read before PATCH');
requireText(releaseHealthDelivery, 'priorRun = await validatePriorRun(api, priorReference);', 'bounded advanced-marker metadata prefetch');
requireText(releaseHealthDelivery, 'exactIssue = validateExactManagedIssue(await api(issuePath), number);', 'second and final exact issue read after bounded marker prefetch');
requireText(releaseHealthDelivery, 'the authoritative delivery marker advanced again during bounded revalidation.', 'repeated marker advance fail-closed boundary');
requireText(releaseHealthDelivery, 'the managed issue changed without an authoritative delivery-marker advance.', 'operator-edit fail-closed boundary');
requireText(releaseHealthVerifier, 'auditedMonitorOrigins:', 'immutable audited monitor-origin policy');
requireText(releaseHealthVerifier, 'collectMonitorImplementationSource(', 'historical monitor implementation source verification');
requireText(releaseHealthVerifier, 'auditedOriginSources', 'historical workflow/script/utils/delivery digest handoff');
requireText(releaseHealthVerifier, "'scripts/sync-release-health-incident-issue.mjs'", 'source-attested incident delivery implementation');
requireText(releaseHealthVerifier, 'candidates.size * 4', 'four-file trusted monitor source request budget');
requireText(releaseHealthVerifier, 'exact four-file implementation', 'four-file trusted monitor recovery warning');
requireText(releaseHealthVerifier, 'attestTrustedMonitorRecoverySuccesses(', 'durable cross-SHA monitor recovery attestation');
requireText(releaseHealthVerifier, 'maxMonitorImplementationAttestations = 32', 'bounded monitor implementation attestation inventory');
requireText(releaseHealthVerifier, 'maxRecoveryAncestorComparisons = 64', 'bounded recovery ancestor verification inventory');
requireText(releaseHealthVerifier, 'ensureAdditionalRequestBudget(', 'source-attestation request-budget reservation');
requireText(releaseHealthVerifier, '29638546298', 'first exact legacy monitor run identity');
requireText(releaseHealthVerifier, '29704911896', 'source-verified incident failure identity');
requireText(releaseHealthVerifier, '29705959736', 'rate-gated incident failure identity');
requireText(releaseHealthVerifier, '29703046855', 'CI deployment incident failure identity');
requireText(releaseHealthVerifier, '29703666102', 'second rate-gated incident failure identity');
requireText(releaseHealthVerifier, '29706178612', 'transitive monitor incident failure identity');
const auditedMonitorOriginCalls = releaseHealthVerifier.match(/auditedMonitorOrigin\(\d+/g) || [];
if (auditedMonitorOriginCalls.length !== 29) {
  throw new Error(`Expected exactly 29 immutable audited monitor origins; found ${auditedMonitorOriginCalls.length}`);
}
requireText(
  releaseHealthVerifier,
  `export const currentMonitorWorkflowSourceSha256 = '${createHash('sha256').update(releaseHealth).digest('hex')}'`,
  'release-health recovery policy exact normalized workflow digest',
);
requireText(releaseHealthVerifier, 'sourceSha256: currentMonitorWorkflowSourceSha256', 'current monitor policy digest reference');
requireText(
  releaseHealthVerifier,
  "export const auditedPriorMonitorWorkflowSourceSha256 = '3672ed17290279e20d75336e810d9327a59786c16a77332aa5be2f4adb0238a1'",
  'immutable historical monitor workflow digest',
);
requireText(releaseHealthVerifier, 'const excludedRepositories = new Set();', 'empty release-health exclusion set');
requireText(releaseHealthRunbook, 'including `SSAI_Connect`', 'Connect-inclusive GitHub App inventory runbook');
requireText(releaseHealthRunbook, 'update\n`SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256`', 'inventory-digest rotation runbook');
requireText(
  releaseHealthRunbook,
  '1b0f98d54264554fdc81d3f7d5b89e2324f9660ebe15526e49e878d2a932df4b',
  'reviewed Connect-inclusive inventory digest',
);
requireText(releaseHealthRunbook, 'Do not reuse the superseded 20-repository digest', 'superseded inventory rejection');
requireText(releaseHealthRunbook, 'Do not use `workflow_dispatch` as scheduler proof', 'natural scheduler proof runbook');
rejectPattern(releaseHealthRunbook, /Exclude `SSAI_Connect`|Keep the existing `SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256`/, 'stale Connect exclusion or inventory digest instructions');
requireText(releaseHealthVerifier, 'findDeploymentCheckRecovery(', 'cross-trigger deployment recovery proof');
requireText(releaseHealthVerifier, 'findMergedPullCheckRecovery(', 'merged pull-request recovery proof');
requireText(releaseHealthVerifier, 'associateChecksWithPulls(', 'force-pushed pull-request recovery association');
requireText(releaseHealthVerifier, 'findSupersedingCommitStatus(', 'recent classic commit-status recovery selection');
requireText(releaseHealthVerifier, 'findSupersedingDeployment(', 'recent deployment failure recovery selection');
requireText(releaseHealthVerifier, "'/attempts/' + attemptNumber", 'rerun-attempt failure inventory');
requireText(releaseHealthVerifier, 'collectWorkflows(repo.name)', 'paginated workflow inventory');
requireText(releaseHealthVerifier, 'collectBranches(repo.name)', 'independent all-branch commit inventory');
requireText(releaseHealthVerifier, 'collectRecentCommitStatuses(', 'recent classic commit-status inventory');
requireText(releaseHealthVerifier, "identity_source = 'github-actions-job'", 'deployment-to-job stream binding');
requireText(releaseHealthVerifier, 'findPolicyBoundProvisionalWorkflowRecovery(', 'policy-bound workflow self-latch guard');
requireText(releaseHealthVerifier, 'findPolicyBoundProvisionalCheckRecovery(', 'policy-bound check self-latch guard');
requireText(releaseHealthVerifier, 'createConcurrencyGate(apiConcurrency)', 'global GitHub API concurrency gate');
requireText(releaseHealthVerifier, 'GitHub API request budget exhausted', 'fail-closed API request budget');
requireText(releaseHealthVerifier, "await api('/installation/repositories?per_page=1&page=1')", 'installation-authenticated core rate-limit preflight');
requireText(releaseHealthVerifier, "await api('/installation/repositories?per_page=100&page=' + page)", 'installation-scoped repository inventory');
requireText(releaseHealthVerifier, 'validateInstallationRepositoryPage(', 'fail-closed installation pagination validation');
requireText(releaseHealthVerifier, 'verifyInstallationRepositoryScope(', 'least-privilege installation repository scope validation');
rejectPattern(releaseHealthVerifier, /api\('\/user(?:\/repos)?(?:\?|')/, 'PAT-only user repository inventory');
requireText(releaseHealthVerifier, "rateDecision === 'defer'", 'continuous rate-limit backpressure');
requireText(releaseHealthVerifier, "rateDecision === 'fail'", 'incident rate-limit fail-closed gate');
assert.ok(
  releaseHealthVerifier.indexOf('verifyInstallationRepositoryScope(installationRepositories);')
    < releaseHealthVerifier.indexOf('const rateDecision = rateHeadroomDecision('),
  'GitHub App installation scope must fail closed before any quota-deferred return',
);
assert.ok(
  releaseHealthVerifier.indexOf('verifyExpectedInventoryAttestation(repositories, expectedInventorySha256);')
    < releaseHealthVerifier.indexOf('const rateDecision = rateHeadroomDecision('),
  'the exact expected repository inventory must be attested before any quota-deferred return',
);
requireText(releaseHealthVerifier, 'throw truncationError(', 'fail-closed pagination');
requireText(releaseHealthVerifier, 'export function releaseHealthPageLimits(mode)', 'mode-bounded release-health pagination policy');
requireText(releaseHealthVerifier, 'export function releaseHealthCheckPageDisposition(page, batchSize, pageLimit)', 'fail-closed check pagination decision');
requireText(releaseHealthVerifier, 'export function validateReleaseHealthCheckRunPage(', 'validated check-run pagination response');
requireText(releaseHealthVerifier, '!Array.isArray(payload.check_runs)', 'malformed check-run page rejection');
requireText(releaseHealthVerifier, 'checkRun.head_sha !== expectedHeadSha', 'check-run page SHA binding');
requireText(releaseHealthVerifier, 'duplicate check-run identity', 'cross-page check-run identity uniqueness');
requireText(releaseHealthVerifier, "type: 'unageable-current-check-run'", 'fail-closed current-check age attestation');
requireText(releaseHealthVerifier, 'source_run_occurrence_at:', 'source-run occurrence fallback evidence');
requireText(releaseHealthVerifier, 'source_run_activity_at:', 'source-run recent-activity fallback evidence');
requireText(releaseHealthVerifier, 'releaseHealthCheckRecentActivityTime(check)', 'source-run activity separated from occurrence ordering');
requireText(releaseHealthVerifier, 'validateReleaseHealthCheckSourceRun(', 'source-run repository, commit, and identity binding');
requireText(releaseHealthVerifier, 'validateReleaseHealthActionsRunPage(', 'bounded SHA-batched source-run hydration validation');
requireText(releaseHealthVerifier, "'/actions/runs?head_sha='", 'bounded SHA-batched Actions source-run collection');
requireText(releaseHealthVerifier, 'releaseHealthActionsRunHydrationMode(', 'request-minimizing source-run hydration strategy');
requireText(releaseHealthVerifier, "String(check.app?.slug || '') === 'github-actions'", 'GitHub Actions-only source-run provenance');
requireText(releaseHealthVerifier, 'sourceRun.repository?.full_name !== expectedRepository', 'source-run repository binding');
requireText(releaseHealthVerifier, 'check._release_health_current_head === true', 'post-enrichment current-head retention');
requireText(releaseHealthVerifier, 'const currentHead = sha === currentHeadSha;', 'single-pass current-head check classification');
requireText(releaseHealthVerifier, '_release_health_current_head: currentHead', 'unfiltered bounded current-head retention evidence');
assert.ok(
  !releaseHealthVerifier.includes('async function collectCurrentChecks('),
  'current-head checks must not be fetched a second time after the complete all-check pass',
);
requireText(releaseHealthVerifier, "return 'check-run:' + checkRunId", 'unageable failure episode identity');
requireText(releaseHealthVerifier, 'checks: 50', 'bounded 1012+ check-run pagination coverage');
requireText(releaseHealthVerifier, 'fingerprintReleaseHealthIncident(', 'typed immutable incident fingerprinting');
requireText(releaseHealthVerifier, 'decodeScheduledIncidentState(', 'cache-key/content integrity validation');
requireText(releaseHealthVerifier, 'evaluateIncidentNotification(', 'scheduled-only incident notification policy');
requireText(releaseHealthVerifier, 'validateIncidentClusterKey(', 'stable notification cluster validation');
requireText(releaseHealthVerifier, 'failureEpisodeAnchor(', 'success-bounded failure episode identity');
requireText(releaseHealthVerifier, 'evidenceDigestByCluster', 'set-deduplicated stable cluster counting');
requireText(releaseHealthVerifier, 'verifyExpectedInventoryAttestation(', 'protected complete repository inventory attestation');
requireText(releaseHealthVerifier, 'timingSafeEqual(', 'constant-time inventory/state attestation comparison');
requireText(releaseHealthVerifier, 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY', 'dedicated state HMAC key consumption');
requireText(releaseHealthVerifier, 'decodeScheduledIncidentStateOrNull(', 'safe corrupt-state reinitialization');
requireText(releaseHealthVerifier, 'isExactSelfMonitorEnvironmentDeployment(', 'exact monitor-environment deployment loop exclusion');
requireText(releaseHealthVerifier, 'durableTrustedMonitorRecoveryRuns(', 'manual-only durable workflow recovery filter');
requireText(releaseHealthVerifier, 'durableTrustedMonitorRecoveryChecks(', 'manual-only durable check recovery filter');
requireText(releaseHealthVerifier, 'trustedMonitorPolicy ? durableTrustedMonitorRecoveryRuns(runs, trustedMonitorPolicy, defaultBranch) : runs', 'trusted workflow recovery candidate filtering');
requireText(releaseHealthVerifier, 'trustedMonitorPolicy ? durableTrustedMonitorRecoveryChecks(checks, trustedMonitorPolicy, defaultBranch) : checks', 'trusted check recovery candidate filtering');
requireText(releaseHealthVerifier, '|| !isExactManualIncidentRecoveryRun(run, policy, defaultBranch)', 'manual-only cross-SHA recovery attestation');
requireText(releaseHealthVerifier, "run?.display_title === 'Release health monitor [incident:168h]'", 'exact manual incident durable run identity');
requireText(releaseHealthVerifier, "check?.source_run_display_title === 'Release health monitor [incident:168h]'", 'exact manual incident durable check identity');
requireText(releaseHealthVerifier, "recoveryDisplayTitles: ['Release health monitor [incident:168h]']", 'manual exhaustive trusted-monitor recovery title');
requireText(releaseHealthVerifier, 'isHostedPublicReleaseHealthOutput(environment = process.env)', 'exact hosted-public output boundary');
requireText(releaseHealthVerifier, "String(environment?.GITHUB_ACTIONS || '').toLowerCase() === 'true'", 'all-hosted-Actions redaction boundary');
requireText(releaseHealthVerifier, 'releaseHealthLogPayload(deferredSummary)', 'aggregate-only deferred stdout');
requireText(releaseHealthVerifier, 'releaseHealthLogPayload(summary)', 'aggregate-only completed stdout');
requireText(releaseHealthVerifier, 'renderReleaseHealthStepSummary(result)', 'hosted-public step-summary renderer');
requireText(releaseHealthVerifier, 'executeReleaseHealthMonitorEntryPoint(runReleaseHealthMonitor)', 'redacted direct monitor entry point');
requireText(releaseHealthVerifier, 'const releaseHealthMonitorFailureStages = new Set([', 'closed hosted-public failure-stage allowlist');
requireText(releaseHealthVerifier, 'Release-health monitor failed closed before aggregate reporting${stageSuffix}.', 'allowlisted staged hosted-public fail-closed error');
rejectPattern(releaseHealthVerifier, /console\.log\(JSON\.stringify\((?:deferredSummary|summary),/, 'unredacted release-health JSON stdout');

requireBalancedExpressions(releaseHealth, 'release-health workflow');
requireSpaceIndentation(releaseHealth, 'release-health workflow');

rejectPattern(combined, /ubuntu-latest/, 'floating GitHub runner label');
rejectPattern(combined, /peter-evans\/repository-dispatch@v\d+/i, 'floating repository-dispatch action');
rejectPattern(combined, /^\s*uses:\s+[^@\s]+\/[^@\s]+@v\d+\s*$/im, 'unpinned version-tag action');

console.log('Shared workflow hardening contract verified.');
