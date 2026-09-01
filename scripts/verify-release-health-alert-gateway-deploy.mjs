import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const normalizeLf = (value) => value.replace(/\r\n?/g, '\n');
const sourceDirectory = new URL('workers/release-health-alert-gateway/src/', root);
const sourceNames = (await readdir(sourceDirectory)).sort();
assert.deepEqual(sourceNames, ['index.mjs']);
const sourceHash = createHash('sha256');
for (const name of sourceNames) sourceHash.update(name).update('\0').update(normalizeLf(await readFile(new URL(name, sourceDirectory), 'utf8'))).update('\0');
const sourceDigest = sourceHash.digest('hex');
const configText = normalizeLf(await readFile(new URL('workers/release-health-alert-gateway/wrangler.jsonc', root), 'utf8'));
const configDigest = createHash('sha256').update(configText).digest('hex');
const config = JSON.parse(configText);
const workflow = normalizeLf(await readFile(new URL('.github/workflows/deploy-release-health-alert-gateway.yml', root), 'utf8'));

assert.equal(config.name, 'ssai-release-health-alert-gateway');
assert.equal(config.main, 'src/index.mjs');
assert.equal(config.workers_dev, false);
assert.equal(config.preview_urls, true);
assert.deepEqual(config.routes, [{ pattern: 'alerts.scalesmall.ai', custom_domain: true }]);
assert.deepEqual(config.ratelimits, [{ name: 'ALERT_INGEST_RATE_LIMITER', namespace_id: '735104001', simple: { limit: 60, period: 60 } }]);
assert.deepEqual(config.version_metadata, { binding: 'CF_VERSION_METADATA' });
assert.deepEqual(config.observability, { enabled: true, head_sampling_rate: 1, logs: { enabled: true, head_sampling_rate: 1, invocation_logs: true } });
for (const key of ['vars', 'durable_objects', 'kv_namespaces', 'd1_databases', 'r2_buckets', 'services', 'triggers']) assert.equal(key in config, false);

for (const required of [
  'on:\n  workflow_dispatch:', 'allow_first_bootstrap:', 'environment:\n      name: release-health-controller-production',
  'github.workflow_sha == inputs.expected_sha', 'github.run_attempt == 1', "test '${{ github.run_attempt }}' = 1",
  'persist-credentials: false', "version!=='4.127.1'", 'versions upload', '--preview-alias', '--strict --dry-run',
  'CLOUDFLARE_ACCOUNT_ID: ${{ secrets.SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID }}',
  'CLOUDFLARE_API_TOKEN: ${{ secrets.SSAI_RELEASE_CONTROLLER_CLOUDFLARE_API_TOKEN }}',
  'ALERT_HMAC_KEY: ${{ secrets.SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY }}',
  'GATEWAY_ZONE_NAME: scalesmall.ai', 'RATE_LIMITER_NAMESPACE_ID: \'735104001\'', 'X-SSAI-Preview-Health-Host:', '$metadata.hasPreview?', '$metadata.has_preview?',
  '.result.annotations//.result.metadata.annotations//{}', 'workers/tag', 'workers/message', 'workers/alias',
  'previous_deployment_id', 'previous_version_id', 'candidate_deployment_id', 'traffic_mutated=true', 'automatic rollback after',
  'api_get_status()', 'api_post_json()', 'api_put_json()', 'api_delete()', 'mktemp "${output}.tmp.XXXXXX"',
  'make_deployment_body "$candidate_version_id" "$promotion_message"', '.result.source=="api"', '.result.strategy=="percentage"',
  'api_post_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/deployments"',
  'test "$ALLOW_FIRST_BOOTSTRAP" = true',
  'latest_deployment_id()', 'latest_version_id()', '.result.deployments|select(type=="array" and length>0)|.[0]',
  'deployments/$previous_deployment_id', 'deployments/$candidate_deployment_id',
  'deployment_ok "$RUNNER_TEMP/gateway-previous-deployment.json"',
  'deployment_ok "$RUNNER_TEMP/gateway-recheck-deployment.json"',
  'deployment_ok "$RUNNER_TEMP/gateway-post-deployment.json"',
  'binding_inventory_ok()', 'legacy_binding_ok()', 'settings_binding_ok()', 'legacy_settings_binding_ok()', 'known_settings_binding_ok()',
  'legacy_contained_version_ok()', 'legacy_bootstrap_parent_ok()', 'legacy_secret_successor_ok()', 'legacy_successor_timestamp_ok()',
  'legacy_bootstrap_sha=e864778adb9b38e266afb18c672661d0b85e8b67', 'legacy_bootstrap_version_id=48d208dd-f054-4c54-bf67-918e126c49e0',
  'legacy_contained_previous=true', 'legacy_secret_successor_previous=true', 'CF_VERSION_METADATA', '.type=="version_metadata"',
  'rm -f -- "$RUNNER_TEMP/gateway-candidate.jsonl"',
  '[.[]|select(.type=="version-upload")] as $events|($events|length)==1',
  'candidate_secrets="$RUNNER_TEMP/gateway-candidate-secrets.json"', '--secrets-file "$candidate_secrets"',
  'bootstrap_dir="$RUNNER_TEMP/gateway-bootstrap"', 'install -d -m 700 -- "$bootstrap_dir"',
  'cp -R -- "$(dirname "$GATEWAY_CONFIG")/." "$bootstrap_dir/"',
  'bootstrap_config="$bootstrap_dir/$(basename "$GATEWAY_CONFIG")"',
  'bootstrap_secrets="$bootstrap_dir/bootstrap-secrets.json"',
  'jq \'.routes=[]\' "$GATEWAY_CONFIG" > "$bootstrap_config"',
  'process.env.ALERT_HMAC_KEY', 'JSON.stringify({ALERT_HMAC_KEY:secret})', '{mode:0o600}',
  'timeout --signal=TERM --kill-after=15s 3m ./node_modules/.bin/wrangler deploy --config "$bootstrap_config" --name "$GATEWAY_NAME" --secrets-file "$bootstrap_secrets" --dry-run --outdir "$RUNNER_TEMP/gateway-bootstrap-dry-run"',
  'timeout --signal=TERM --kill-after=15s 10m ./node_modules/.bin/wrangler deploy --config "$bootstrap_config" --name "$GATEWAY_NAME" --secrets-file "$bootstrap_secrets"',
  'if test -n "$bootstrap_dir"; then rm -rf -- "$bootstrap_dir"', 'unset ALERT_HMAC_KEY',
  'bootstrap_mutation_attempted=true', 'contain_bootstrap()', 'contain_bootstrap bootstrap-containment', 'bootstrap_version_owned()',
  '{enabled:false,previews_enabled:true}', 'wait_domain_absent bootstrap-post-deploy',
  '/workers/domains', '/deployments', '/versions/$candidate_version_id', '/settings', '/secrets', '/subdomain',
  'workers/domains?service=$GATEWAY_NAME', 'workers/domains?hostname=$GATEWAY_DOMAIN', 'domain_list_complete()', 'script_routes_absent()', 'domain_list_complete "$input" || return 1', 'workers/scripts',
  'has("result_info")|not', '(.result_info|has("page")|not)', '(.result_info|has("per_page")|not)', '(.result_info|has("count")|not)', '(.result_info|has("total_pages")|not)', '(.result_info.total_pages|floor)==.result_info.total_pages', 'domain_preexisting=true', 'domain_attach_attempted=true', 'domain_created_by_run=true', 'reconcile_domain_attach_response()',
  '(.result.zone_id|type)=="string"', '.result.zone_id|test("^[a-f0-9]{32}$")',
  '(.result.cert_id|type)=="string"', '.result.cert_id|test("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")',
  'test "$domain_created_by_run" != true || ! valid_domain_id "$candidate_domain_id"',
  '{hostname:$hostname,service:$service,zone_name:$zone_name}', 'domain_ok()', 'wait_domain()', 'wait_domain_absent()',
  'api_delete "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains/$observed_domain"', 'reconcile_owned_domain_rollback()',
  'observability_ok()', '.result.observability.enabled==true', '.result.observability.logs.invocation_logs==true', '.result.logpush==false', '.result.tail_consumers//[]',
  'wait_health()', 'deadline=$((SECONDS+180))', 'reconcile_traffic_rollback()', 'deployments?force=true', 'attest_previous_provider_state()', 'attest_candidate_ingress()', 'attest_candidate_provider_state()', 'trap - EXIT', 'set +e',
  'name=="ALERT_HMAC_KEY" and .type=="secret_text"',
  'expected_secret_names:["ALERT_HMAC_KEY"]', 'domain_preexisting:$domain_preexisting', '.result.enabled==false and .result.previews_enabled==true', 'ssai-release-health-alert-gateway-deployment-evidence-v3',
  'ssai-release-health-alert-gateway-health-v2', 'version_id', 'committed=false', 'committed=true',
  'Record hard job budget', 'GATEWAY_JOB_STARTED_EPOCH', 'gateway_rollback_reserve_seconds=1200', 'gateway_promotion_deadline_epoch', 'test "$now_epoch" -le "$gateway_promotion_deadline_epoch"',
  'request_timeout_seconds()', 'bounded_sleep()', 'require_forward_budget 900', 'require_forward_budget 360', 'require_forward_budget 300', 'require_forward_budget 30', 'rollback_mode=true', '--max-time "$request_timeout"',
  'rm -rf -- "$RUNNER_TEMP/gateway-dry-run"',
]) assert.ok(workflow.includes(required), `Missing gateway deployment contract: ${required}`);

const jobPrefix = workflow.slice(0, workflow.indexOf('    steps:'));
assert.doesNotMatch(jobPrefix, /CLOUDFLARE_(?:ACCOUNT_ID|API_TOKEN)/);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID/g) ?? []).length, 1);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_CLOUDFLARE_API_TOKEN/g) ?? []).length, 1);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY/g) ?? []).length, 2);
for (const use of workflow.matchAll(/^\s*- uses:\s*([^\s]+)$/gm)) assert.match(use[1], /^[^@]+@[a-f0-9]{40}$/);
assert.doesNotMatch(workflow, /\b(?:push|pull_request|schedule|repository_dispatch|workflow_run):/);
assert.doesNotMatch(workflow, /cloudflare\/wrangler-action|npx\s+wrangler|npm\s+install/i);
assert.doesNotMatch(workflow, /wrangler\s+(?:delete|rollback|triggers\s+delete|secret\s+delete)/i);
assert.doesNotMatch(workflow, /wrangler\s+secret\s+put/i);
assert.doesNotMatch(workflow, /wrangler\s+versions\s+deploy|wrangler\s+triggers\s+deploy/i);
assert.doesNotMatch(workflow, /sort_by\(\.created_on\)|\|last\|/);
assert.doesNotMatch(workflow, /["']force["']\s*:\s*true/i);
assert.equal((workflow.match(/\?force=true/g) ?? []).length, 1, 'Only the exact provenance-gated traffic rollback may force a deployment');
const trafficRollbackFunction = workflow.split('          reconcile_traffic_rollback() {')[1].split('          attest_rollback_active() {')[0];
assert.ok(trafficRollbackFunction.includes('deployments?force=true'), 'Changed candidate secrets require the provider-supported forced rollback path');
assert.ok(trafficRollbackFunction.indexOf('promoted_deployment_ok "$RUNNER_TEMP/gateway-${label}-deployment.json"') < trafficRollbackFunction.indexOf('deployments?force=true'), 'Forced rollback requires exact active candidate provenance before mutation');
assert.equal((workflow.match(/gateway-promotion-body\.json/g) ?? []).length > 0, true);
assert.doesNotMatch(workflow.split('          traffic_mutated=true')[1], /gateway-promotion-body\.json[^\n]*\?force=true/, 'Normal promotion must remain unforced');
assert.doesNotMatch(workflow, /\b(?:domain_snapshot|previous_domain_snapshot)\b/, 'Repeated domain_ok checks supersede brittle serialized snapshots');
const domainOkLine = workflow.split('\n').find((line) => line.includes('domain_ok()'));
assert.ok(domainOkLine, 'The exact custom-domain identity validator must exist');
for (const requiredIdentityCheck of ['.result.id==$id', '.result.hostname==$h', '.result.service==$s', '.result.zone_name==$z', '(.result.environment//"production")=="production"']) {
  assert.ok(domainOkLine.includes(requiredIdentityCheck), `Domain identity must retain ${requiredIdentityCheck}`);
}
const exactSecretFunction = workflow.split('          exact_secret_ok() {')[1].split('\n')[0];
for (const requiredSecretCheck of ['(.result|type)=="array"', '(.result|length)==1', '.result[0].name=="ALERT_HMAC_KEY"', '.result[0].type=="secret_text"']) {
  assert.ok(exactSecretFunction.includes(requiredSecretCheck), `Exact secret inventory must retain ${requiredSecretCheck}`);
}
assert.doesNotMatch(workflow, /\[\.result\[\]\|select\([^']+\)\]\|length==1 and \(\.result\|length\)==1/, 'A jq pipeline must not replace the response object before the total secret count is evaluated');
assert.equal((workflow.match(/^\s+exact_secret_ok "\$RUNNER_TEMP\/gateway-secrets\.json"$/gm) ?? []).length, 2, 'Preflight and final evidence must share the exact secret validator');
assert.equal((workflow.match(/^\s+exact_secret_ok "\$RUNNER_TEMP\/gateway-[^"]+"(?: \|\| return 1)?$/gm) ?? []).length, 5, 'All five secret attestations must use the single exact validator');
const exactSecretInventory = (payload) => Array.isArray(payload?.result)
  && payload.result.length === 1
  && payload.result[0]?.name === 'ALERT_HMAC_KEY'
  && payload.result[0]?.type === 'secret_text';
assert.equal(exactSecretInventory({ result: [{ name: 'ALERT_HMAC_KEY', type: 'secret_text', provider_metadata: 'ignored' }] }), true, 'The exact required secret inventory must pass with harmless provider metadata');
assert.equal(exactSecretInventory({}), false, 'A missing result inventory must fail closed');
assert.equal(exactSecretInventory({ result: null }), false, 'A null result inventory must fail closed');
assert.equal(exactSecretInventory({ result: [] }), false, 'A missing required secret must fail closed');
assert.equal(exactSecretInventory({ result: [{ name: 'ALERT_HMAC_KEY', type: 'secret_text' }, { name: 'EXTRA', type: 'secret_text' }] }), false, 'An additional script secret must fail closed');
assert.equal(exactSecretInventory({ result: [{ name: 'ALERT_HMAC_KEY', type: 'secret_text' }, { name: 'ALERT_HMAC_KEY', type: 'secret_text' }] }), false, 'Duplicate authorized entries must fail closed');
assert.equal(exactSecretInventory({ result: [{ name: 'WRONG', type: 'secret_text' }] }), false, 'A substituted secret name must fail closed');
assert.equal(exactSecretInventory({ result: [{ name: 'ALERT_HMAC_KEY', type: 'plain_text' }] }), false, 'A non-secret binding type must fail closed');
assert.equal(exactSecretInventory({ result: { name: 'ALERT_HMAC_KEY', type: 'secret_text' } }), false, 'A malformed non-array inventory must fail closed');
assert.equal((workflow.match(/-X DELETE/g) ?? []).length, 1, 'Only the exact-ID domain rollback helper may issue DELETE');
assert.equal((workflow.match(/api_delete "accounts\/\$CLOUDFLARE_ACCOUNT_ID\/workers\/domains\/\$observed_domain"/g) ?? []).length, 1);
assert.ok(workflow.indexOf('traffic_mutated=true') < workflow.indexOf('api_post_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/deployments" "$RUNNER_TEMP/gateway-promotion-body.json"'));
assert.ok(workflow.indexOf('      - name: Record hard job budget') < workflow.indexOf('      - uses: actions/checkout@'), 'The hard job budget must start before checkout and setup');
assert.ok(workflow.indexOf('api_post_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/deployments" "$RUNNER_TEMP/gateway-promotion-body.json"') < workflow.indexOf('domain_attach_attempted=true'));
assert.ok(workflow.indexOf('domain_attach_attempted=true') < workflow.indexOf('candidate_domain_id="$(reconcile_domain_attach_response domain-attach)"'));
const bootstrapDeployMutation = 'wrangler deploy --config "$bootstrap_config" --name "$GATEWAY_NAME" --secrets-file "$bootstrap_secrets" --message';
assert.ok(workflow.indexOf('require_forward_budget 900') < workflow.indexOf('bootstrap_mutation_attempted=true'), 'Bootstrap must reserve a complete forward and containment budget before mutation');
assert.ok(workflow.indexOf('bootstrap_mutation_attempted=true') < workflow.indexOf(bootstrapDeployMutation), 'Bootstrap containment must be armed before the real Wrangler deploy');
assert.ok(workflow.indexOf('timeout --signal=TERM --kill-after=15s 10m') < workflow.indexOf(bootstrapDeployMutation), 'The live bootstrap deploy must reserve a bounded containment window before the job timeout');
const wranglerMutationLines = workflow.split('\n').filter((line) => line.includes('./node_modules/.bin/wrangler'));
assert.equal(wranglerMutationLines.length, 4, 'Every expected Wrangler phase must be explicit');
for (const line of wranglerMutationLines) assert.ok(line.includes('timeout --signal=TERM --kill-after=15s'), `Unbounded Wrangler phase: ${line.trim()}`);
assert.match(workflow, /timeout --signal=TERM --kill-after=15s 5m npm ci/);
assert.equal((workflow.match(/\bcommitted=true\b/g) ?? []).length, 1, 'Success must have one atomic commit point');
assert.match(workflow, /if test "\$committed" != true && test "\$rc" -eq 0; then rc=93; fi/);
assert.equal((workflow.match(/^\s+sleep "\$delay"$/gm) ?? []).length, 1, 'Only bounded_sleep itself may call sleep directly');
assert.equal((workflow.match(/bounded_sleep "\$delay" \|\| return 1/g) ?? []).length, 8, 'Every provider reconciliation loop must honor the forward deadline');
assert.doesNotMatch(workflow, /^\s+(?:traffic_mutated|domain_attach_attempted|domain_created_by_run|bootstrap_mutation_attempted)=false\s*$/gm, 'Success must not disarm rollback flags sequentially');
assert.ok(workflow.indexOf('attest_candidate_provider_state final') < workflow.indexOf('ssai-release-health-alert-gateway-deployment-evidence-v3'));
assert.ok(workflow.indexOf('ssai-release-health-alert-gateway-deployment-evidence-v3') < workflow.indexOf('committed=true'));
const candidateUploadStart = workflow.indexOf('          require_forward_budget 360');
const candidateUploadEnd = workflow.indexOf('          jq -se --arg worker', candidateUploadStart);
const candidateUpload = workflow.slice(candidateUploadStart, candidateUploadEnd);
assert.ok(candidateUploadStart >= 0 && candidateUploadEnd > candidateUploadStart, 'Candidate upload must have a complete fixed-command budget');
assert.ok(candidateUpload.includes('--secrets-file "$candidate_secrets"'), 'The immutable candidate must atomically receive the authorized signing key');
assert.ok(candidateUpload.indexOf('--secrets-file "$candidate_secrets"') < candidateUpload.indexOf('rm -f -- "$candidate_secrets"'), 'Candidate signing material must remain available through upload and then be deleted');
const deadlineGuard = 'test "$traffic_mutated" = true || test "$bootstrap_mutation_attempted" = true';
assert.equal((workflow.match(new RegExp(deadlineGuard.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? []).length, 2, 'API calls and sleeps must honor the forward deadline after either bootstrap or promotion mutation');
const finishFunction = workflow.split('          finish() {')[1].split('          trap finish EXIT')[0];
assert.ok(finishFunction.indexOf('reconcile_owned_domain_rollback rollback-domain') < finishFunction.indexOf('reconcile_traffic_rollback rollback-traffic'), 'A newly attached domain must be removed before predecessor traffic can be restored');
assert.ok(finishFunction.includes('safe_to_rollback_traffic=false'), 'Failed domain cleanup must retain safe candidate traffic');
assert.ok(finishFunction.indexOf('test "$safe_to_rollback_traffic" = true') < finishFunction.indexOf('reconcile_traffic_rollback rollback-traffic'), 'Traffic rollback must be gated by proven ingress cleanup');
const gatewayFailureStages = [
  'account-id-shape', 'api-token-shape', 'signing-key-shape', 'secret-file-write', 'secret-file-mode',
  'account-get', 'account-validate', 'service-domain-get', 'service-domain-validate', 'hostname-domain-get',
  'hostname-domain-validate', 'domain-count', 'preexisting-domain-id', 'preexisting-domain-hostname',
  'preexisting-domain-detail-get', 'preexisting-domain-detail-validate', 'deployments-get', 'deployment-list-validate',
  'deployment-id', 'version-id', 'bootstrap-authorization', 'bootstrap-script-routes', 'bootstrap-staging', 'bootstrap-dry-run',
  'bootstrap-deploy', 'deployment-ids-validate', 'deployment-detail-get', 'deployment-detail-validate',
  'version-detail-get', 'version-detail-validate', 'secrets-get', 'secrets-validate', 'settings-get',
  'settings-observability', 'settings-bindings', 'subdomain-get', 'subdomain-validate', 'scripts-get',
  'script-routes', 'active-version-bindings', 'legacy-successor-parent-get', 'legacy-successor-validate', 'bootstrap-domain-absence', 'domain-ready', 'live-health', 'preflight-secret-cleanup',
  'candidate-upload', 'candidate-preview', 'promotion', 'ingress', 'final-attestation', 'unclassified',
];
const reporterStart = workflow.indexOf('          report_gateway_failure_stage() {');
const reporterEnd = workflow.indexOf('          request_timeout_seconds() {', reporterStart);
assert.ok(reporterStart >= 0 && reporterEnd > reporterStart, 'Gateway diagnostics must have one bounded reporter');
const reporterFunction = workflow.slice(reporterStart, reporterEnd);
const reporterAllowlistLine = reporterFunction.split('\n').find((line) => line.trim().endsWith(') ;;') && line.includes('|'));
assert.ok(reporterAllowlistLine, 'Gateway diagnostic reporter must use one literal allowlist');
assert.deepEqual(reporterAllowlistLine.trim().slice(0, -4).split('|'), gatewayFailureStages, 'Gateway diagnostic stage allowlist must remain exact and closed');
assert.ok(reporterFunction.includes('*) stage=unclassified ;;'), 'Unknown gateway diagnostic stages must fail closed to unclassified');
assert.doesNotMatch(reporterFunction, /BASH_COMMAND|CLOUDFLARE_|RUNNER_TEMP|GATEWAY_DOMAIN|https?:|response|headers|GITHUB_(?:ENV|OUTPUT|STEP_SUMMARY)/i, 'Gateway diagnostic output must not expose command, provider, URL, environment, or response data');
assert.equal((workflow.match(/Gateway deployment failed at an allowlisted stage/g) ?? []).length, 1, 'Gateway failure diagnostics must emit one fixed annotation');
assert.ok(finishFunction.includes('if test "$forward_rc" -ne 0; then report_gateway_failure_stage "$gateway_failure_stage"; fi'), 'Only failed forward execution may emit the allowlisted diagnostic stage');
const stageAssignments = [...workflow.matchAll(/^\s+gateway_failure_stage=([^\s]+)\s*$/gm)].map((match) => match[1]);
assert.equal((workflow.match(/gateway_failure_stage=/g) ?? []).length, stageAssignments.length, 'Gateway failure stages must only use bare literal assignments');
assert.deepEqual([...new Set(stageAssignments)].sort(), gatewayFailureStages.filter((stage) => stage !== 'unclassified').sort(), 'Every non-fallback gateway stage must be reachable and allowlisted');
const assertStageOwnsCommand = (stage, command) => {
  const stageIndex = workflow.indexOf(`gateway_failure_stage=${stage}`);
  const nextStageIndex = workflow.indexOf('gateway_failure_stage=', stageIndex + 1);
  const commandIndex = workflow.indexOf(command, stageIndex);
  assert.ok(stageIndex >= 0 && commandIndex > stageIndex && (nextStageIndex < 0 || commandIndex < nextStageIndex), `${stage} must remain active through ${command}`);
};
for (const [stage, command] of [
  ['account-id-shape', '[[ "$CLOUDFLARE_ACCOUNT_ID" =~ ^[a-f0-9]{32}$ ]]'],
  ['api-token-shape', 'test "${#CLOUDFLARE_API_TOKEN}" -ge 20'],
  ['signing-key-shape', 'const v=process.env.ALERT_HMAC_KEY'],
  ['account-get', 'api_get "accounts/$CLOUDFLARE_ACCOUNT_ID"'],
  ['service-domain-get', 'api_get "$domain_inventory_path" "$RUNNER_TEMP/gateway-domain-preflight-list.json"'],
  ['bootstrap-staging', 'node -e \'const fs=require("node:fs");const secret=process.env.ALERT_HMAC_KEY'],
  ['deployment-ids-validate', 'valid_uuid "$previous_deployment_id"; valid_uuid "$previous_version_id"'],
  ['active-version-bindings', 'if binding_ok "$RUNNER_TEMP/gateway-previous.json"; then'],
  ['legacy-successor-parent-get', 'versions/$legacy_bootstrap_version_id'],
  ['legacy-successor-validate', 'legacy_secret_successor_ok "$RUNNER_TEMP/gateway-previous.json"'],
  ['domain-ready', 'test "$(wait_domain "$previous_domain_id" preflight-existing)" = "$previous_domain_id"'],
  ['live-health', 'wait_health "https://$GATEWAY_DOMAIN/healthz" preflight-live "$previous_version_id"'],
  ['preflight-secret-cleanup', 'if test -n "$bootstrap_secrets"; then rm -f -- "$bootstrap_secrets"'],
  ['candidate-upload', 'require_forward_budget 360'],
  ['candidate-preview', 'check_health "https://$preview_host/healthz" preview'],
  ['promotion', 'promoted="$(date -u +%Y-%m-%dT%H:%M:%SZ)"'],
  ['ingress', 'api_get "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/settings" "$RUNNER_TEMP/gateway-settings.json"'],
  ['final-attestation', 'attest_candidate_provider_state final'],
]) assertStageOwnsCommand(stage, command);
if (process.platform !== 'win32') {
  const runnableReporter = reporterFunction.replace(/^ {10}/gm, '');
  const runDiagnosticHarness = (stage) => spawnSync('bash', ['--noprofile', '--norc', '-c', `set -euo pipefail\n${runnableReporter}\ngateway_failure_stage=${stage}\nfinish_test() { rc=$?; trap - EXIT; set +e; if test "$rc" -ne 0; then report_gateway_failure_stage "$gateway_failure_stage"; fi; exit "$rc"; }\ntrap finish_test EXIT\nfalse\n`], { encoding: 'utf8' });
  const classifiedFailure = runDiagnosticHarness('settings-bindings');
  assert.equal(classifiedFailure.status, 1, 'Gateway diagnostics must preserve a representative failure exit code');
  assert.equal(classifiedFailure.stdout.trim(), '::error::Gateway deployment failed at an allowlisted stage (stage=settings-bindings).');
  const unclassifiedFailure = runDiagnosticHarness('not-an-allowlisted-stage');
  assert.equal(unclassifiedFailure.status, 1, 'Unknown diagnostic stages must preserve the original failure exit code');
  assert.equal(unclassifiedFailure.stdout.trim(), '::error::Gateway deployment failed at an allowlisted stage (stage=unclassified).');
}
const candidateAttestation = workflow.split('          attest_candidate_provider_state() {')[1].split('          attest_previous_provider_state() {')[0];
const healthIndex = candidateAttestation.indexOf('check_health "https://$GATEWAY_DOMAIN/healthz"');
const postHealthIngressIndex = candidateAttestation.indexOf('attest_candidate_ingress "${label}-after-health"');
const finalDeploymentIndex = candidateAttestation.indexOf('gateway-${label}-end-list.json');
assert.ok(healthIndex >= 0 && healthIndex < postHealthIngressIndex && postHealthIngressIndex < finalDeploymentIndex, 'Final commit proof must bracket health with a later ingress recheck and then close on exact active deployment');
const containmentFunction = workflow.split('          contain_bootstrap() {')[1].split('          check_health() {')[0];
assert.ok(containmentFunction.indexOf('bootstrap_version_owned') < containmentFunction.indexOf('api_post_json "accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$GATEWAY_NAME/subdomain"'), 'Bootstrap correction must prove exact run ownership before mutation');
assert.ok((workflow.match(/rm -f -- "\$output"/g) ?? []).length >= 5, 'Every reusable API destination must be cleared before a request');
assert.ok((workflow.match(/mv -f -- "\$temporary" "\$output"/g) ?? []).length >= 5, 'Only validated temporary API responses may become evidence');
assert.doesNotMatch(workflow, /local[^\n]*label="\$2"[^\n]*\$\{label\}/, 'Bash locals must not expand label before assignment under nounset');
assert.doesNotMatch(workflow, /SSAI_RELEASE_CONTROLLER_(?:GITHUB|ADMISSION|ACTIVATION)/);
assert.doesNotMatch(workflow, /\$RUNNER_TEMP\/gateway-bootstrap\.jsonc/);

const bootstrapRoot = await mkdtemp(join(tmpdir(), 'ssai-alert-gateway-bootstrap-'));
try {
  const stagedDirectory = join(bootstrapRoot, 'gateway');
  const stagedConfigPath = join(stagedDirectory, 'wrangler.jsonc');
  const candidateConfigPath = join(stagedDirectory, 'candidate-wrangler.jsonc');
  const stagedSecretsPath = join(stagedDirectory, 'bootstrap-secrets.json');
  const dryRunDirectory = join(bootstrapRoot, 'dry-run');
  const candidateDryRunDirectory = join(bootstrapRoot, 'candidate-dry-run');
  const syntheticSecretBytes = Buffer.alloc(32, 0x5a);
  const syntheticSecret = syntheticSecretBytes.toString('base64');
  await cp(fileURLToPath(new URL('workers/release-health-alert-gateway/', root)), stagedDirectory, { recursive: true, errorOnExist: true });
  await writeFile(stagedConfigPath, `${JSON.stringify({ ...config, routes: [] }, null, 2)}\n`, { mode: 0o600 });
  await writeFile(candidateConfigPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  const stagedConfig = JSON.parse(await readFile(stagedConfigPath, 'utf8'));
  assert.equal(stagedConfig.main, config.main);
  assert.deepEqual(stagedConfig.routes, []);
  await readFile(join(stagedDirectory, stagedConfig.main));
  await writeFile(stagedSecretsPath, `${JSON.stringify({ ALERT_HMAC_KEY: syntheticSecret })}\n`, { mode: 0o600 });
  if (process.platform !== 'win32') assert.equal((await stat(stagedSecretsPath)).mode & 0o777, 0o600, 'Bootstrap secret file must be mode 0600');
  const dryRunOutput = execFileSync(process.execPath, [
    fileURLToPath(new URL('node_modules/wrangler/bin/wrangler.js', root)),
    'deploy', '--config', stagedConfigPath, '--name', config.name, '--secrets-file', stagedSecretsPath, '--dry-run', '--outdir', dryRunDirectory,
  ], {
    cwd: fileURLToPath(root),
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: 'pipe',
    timeout: 60_000,
  });
  assert.equal(dryRunOutput.includes(Buffer.from(syntheticSecret)), false, 'Wrangler dry-run stdout leaked the encoded bootstrap secret');
  assert.equal(dryRunOutput.includes(syntheticSecretBytes), false, 'Wrangler dry-run stdout leaked the decoded bootstrap secret');
  assert.ok((await readdir(dryRunDirectory)).length > 0, 'Staged bootstrap dry-run must emit a bundle');
  const candidateDryRunOutput = execFileSync(process.execPath, [
    fileURLToPath(new URL('node_modules/wrangler/bin/wrangler.js', root)),
    'versions', 'upload', '--config', candidateConfigPath, '--name', config.name, '--secrets-file', stagedSecretsPath,
    '--preview-alias', 'c-aaaaaaaaaaaa', '--tag', 'a'.repeat(40), '--message', 'candidate secret contract', '--strict', '--dry-run', '--outdir', candidateDryRunDirectory,
  ], {
    cwd: fileURLToPath(root),
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: 'pipe',
    timeout: 60_000,
  });
  assert.equal(candidateDryRunOutput.includes(Buffer.from(syntheticSecret)), false, 'Wrangler candidate dry-run stdout leaked the encoded signing key');
  assert.equal(candidateDryRunOutput.includes(syntheticSecretBytes), false, 'Wrangler candidate dry-run stdout leaked the decoded signing key');
  assert.ok((await readdir(candidateDryRunDirectory)).length > 0, 'Immutable candidate dry-run must emit a bundle');
  const inspectArtifacts = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await inspectArtifacts(path);
      else {
        const artifact = await readFile(path);
        assert.equal(artifact.includes(Buffer.from(syntheticSecret)), false, `Dry-run artifact ${entry.name} leaked the encoded bootstrap secret`);
        assert.equal(artifact.includes(syntheticSecretBytes), false, `Dry-run artifact ${entry.name} leaked the decoded bootstrap secret`);
      }
    }
  };
  await inspectArtifacts(dryRunDirectory);
  await inspectArtifacts(candidateDryRunDirectory);
} finally {
  await rm(bootstrapRoot, { recursive: true, force: true });
}

const latestDeployment = (payload) => {
  assert.ok(Array.isArray(payload?.result?.deployments) && payload.result.deployments.length > 0);
  const deployment = payload.result.deployments[0];
  assert.match(deployment.id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.equal(deployment.versions.length, 1);
  assert.equal(deployment.versions[0].percentage, 100);
  return deployment;
};
const activeFixture = {
  result: {
    deployments: [
      { id: '11111111-1111-1111-1111-111111111111', created_on: '2026-09-01T18:00:00Z', versions: [{ version_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', percentage: 100 }] },
      { id: '22222222-2222-2222-2222-222222222222', created_on: '2026-09-01T18:01:00Z', versions: [{ version_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', percentage: 100 }] },
    ],
  },
};
assert.equal(latestDeployment(activeFixture).id, '11111111-1111-1111-1111-111111111111', 'Cloudflare guarantees element zero is active; timestamps must not be re-sorted');

const previewEnabled = (metadata) => {
  const flags = [metadata.hasPreview, metadata.has_preview].filter((value) => typeof value === 'boolean');
  return flags.length >= 1 && flags.every((value) => value === true);
};
assert.equal(previewEnabled({ hasPreview: true }), true, 'Documented camelCase preview flag must pass');
assert.equal(previewEnabled({ has_preview: true }), true, 'Observed provider snake_case preview flag must pass');
assert.equal(previewEnabled({ hasPreview: true, has_preview: false }), false, 'Contradictory provider flags must fail closed');
assert.equal(previewEnabled({}), false, 'Missing provider preview evidence must fail closed');

const timestampGte = (actual, bound) => Number.isFinite(Date.parse(actual)) && Number.isFinite(Date.parse(bound)) && Date.parse(actual) >= Date.parse(bound);
assert.equal(timestampGte('2026-09-01T18:00:00.123Z', '2026-09-01T18:00:00Z'), true, 'Fractional RFC3339 timestamps in the same second must compare chronologically');
assert.equal(timestampGte('not-a-time', '2026-09-01T18:00:00Z'), false, 'Invalid provider timestamps must fail closed');
assert.doesNotMatch(workflow, /\.created_on\s*>?=\s*\$|\.timestamp\s*>?=\s*\$/m, 'Provider timestamps must not use lexical shell or jq ordering');

const replaceEvidenceAtomically = (previous, attempt) => attempt.transportOk && attempt.schemaOk ? attempt.payload : undefined;
const oldEvidence = { success: true, result: { id: 'stale' } };
assert.equal(replaceEvidenceAtomically(oldEvidence, { transportOk: false, schemaOk: false }), undefined, 'A failed request must remove stale prior evidence');

const mayDeleteAttachedDomain = ({ domainCreatedByRun, candidateDomainId, observedDomainId }) =>
  domainCreatedByRun === true
  && /^[a-f0-9]{32}$/.test(candidateDomainId ?? '')
  && candidateDomainId === observedDomainId;
assert.equal(mayDeleteAttachedDomain({ domainCreatedByRun: false, candidateDomainId: '', observedDomainId: 'a'.repeat(32) }), false, 'An ambiguous PUT must never delete a matching domain created concurrently by another actor');
assert.equal(mayDeleteAttachedDomain({ domainCreatedByRun: true, candidateDomainId: 'a'.repeat(32), observedDomainId: 'b'.repeat(32) }), false, 'Rollback must never delete a domain whose immutable ID differs from this run response');
assert.equal(mayDeleteAttachedDomain({ domainCreatedByRun: true, candidateDomainId: 'a'.repeat(32), observedDomainId: 'a'.repeat(32) }), true, 'Rollback may delete only the exact immutable domain ID proven to have been returned to this run');
const intendedDomain = { id: 'a'.repeat(32), hostname: 'alerts.scalesmall.ai', service: config.name, zone_name: 'scalesmall.ai', environment: 'production' };
const reconcileDomainAttach = (attempts) => {
  for (const attempt of attempts) {
    if (attempt.put?.success === true) {
      if (JSON.stringify(attempt.put.result) === JSON.stringify(intendedDomain)) return { status: 'owned', id: intendedDomain.id };
      return { status: 'conflict' };
    }
    const service = attempt.serviceInventory;
    const hostname = attempt.hostnameInventory;
    if (!Array.isArray(service) || !Array.isArray(hostname)) continue;
    if (service.length === 0 && hostname.length === 0) continue;
    if (service.length === 1 && hostname.length === 1 && JSON.stringify(service[0]) === JSON.stringify(intendedDomain) && JSON.stringify(hostname[0]) === JSON.stringify(intendedDomain) && attempt.directDomainValid === true) return { status: 'owned', id: intendedDomain.id };
    return { status: 'conflict' };
  }
  return { status: 'timeout' };
};
assert.deepEqual(reconcileDomainAttach([
  { put: { success: false }, serviceInventory: [intendedDomain], hostnameInventory: [intendedDomain], directDomainValid: true },
]), { status: 'owned', id: intendedDomain.id }, 'A committed PUT with a lost response must converge from exact dual-inventory and direct-detail proof without another mutation');
assert.deepEqual(reconcileDomainAttach([
  { put: { success: false }, serviceInventory: [], hostnameInventory: [] },
  { put: { success: true, result: intendedDomain } },
]), { status: 'owned', id: intendedDomain.id }, 'An uncommitted ambiguous PUT may be retried from complete empty inventories');
assert.deepEqual(reconcileDomainAttach([
  { put: { success: false }, serviceInventory: [intendedDomain], hostnameInventory: [{ ...intendedDomain, id: 'b'.repeat(32) }], directDomainValid: true },
]), { status: 'conflict' }, 'Conflicting service and hostname domain identities must fail closed');
assert.deepEqual(reconcileDomainAttach([
  { put: { success: false }, serviceInventory: [intendedDomain], hostnameInventory: [intendedDomain], directDomainValid: false },
]), { status: 'conflict' }, 'A matching inventory without direct immutable-detail proof must fail closed');
assert.deepEqual(reconcileDomainAttach([
  { put: { success: false }, serviceInventory: [intendedDomain, intendedDomain], hostnameInventory: [intendedDomain], directDomainValid: true },
]), { status: 'conflict' }, 'A duplicate service inventory must fail closed');
const domainAttachFunction = workflow.split('          reconcile_domain_attach_response() {')[1].split('          reconcile_owned_domain_rollback() {')[0];
const reconciledDomainProof = 'domain_ok "$RUNNER_TEMP/gateway-${label}-domain.json" "$observed_domain" || return 2';
assert.ok(domainAttachFunction.indexOf(reconciledDomainProof) < domainAttachFunction.indexOf('printf \'%s\' "$observed_domain"', domainAttachFunction.indexOf(reconciledDomainProof)), 'Exact direct domain proof must precede returning the reconciled immutable ID');
assert.ok(domainAttachFunction.indexOf('printf \'%s\' "$observed_domain"', domainAttachFunction.indexOf(reconciledDomainProof)) < domainAttachFunction.indexOf('return 0', domainAttachFunction.indexOf(reconciledDomainProof)), 'Read-after-write reconciliation must return success immediately after emitting the exact ID');
const rollbackOrder = ({ domainPreexisting, domainAttempted, domainCleanupProven, domainAbsenceProven }) => {
  if (domainPreexisting) return ['traffic', 'previous-attestation'];
  if (domainAttempted && !domainCleanupProven) return ['leave-candidate'];
  if (!domainAttempted && !domainAbsenceProven) return ['leave-candidate'];
  return domainAttempted ? ['domain', 'traffic', 'previous-attestation'] : ['absence', 'traffic', 'previous-attestation'];
};
assert.deepEqual(rollbackOrder({ domainPreexisting: false, domainAttempted: true, domainCleanupProven: true }), ['domain', 'traffic', 'previous-attestation']);
assert.deepEqual(rollbackOrder({ domainPreexisting: false, domainAttempted: true, domainCleanupProven: false }), ['leave-candidate'], 'A failed domain cleanup must never expose the predecessor');
assert.deepEqual(rollbackOrder({ domainPreexisting: false, domainAttempted: false, domainAbsenceProven: false }), ['leave-candidate'], 'Traffic rollback requires proof that no new domain exists even when attach was never armed');
const trafficRollbackDecision = ({ activeVersion, activeDeploymentOwned, previousVersion, candidateVersion }) => {
  if (activeVersion === previousVersion && activeDeploymentOwned) return 'safe';
  if (activeVersion === candidateVersion && activeDeploymentOwned) return 'retry-rollback';
  return 'conflict';
};
assert.equal(trafficRollbackDecision({ activeVersion: 'previous', activeDeploymentOwned: true, previousVersion: 'previous', candidateVersion: 'candidate' }), 'safe');
assert.equal(trafficRollbackDecision({ activeVersion: 'candidate', activeDeploymentOwned: true, previousVersion: 'previous', candidateVersion: 'candidate' }), 'retry-rollback');
assert.equal(trafficRollbackDecision({ activeVersion: 'candidate', activeDeploymentOwned: false, previousVersion: 'previous', candidateVersion: 'candidate' }), 'conflict', 'Rollback must not overwrite a concurrent deployment of the same version');
assert.equal(trafficRollbackDecision({ activeVersion: 'third-party', activeDeploymentOwned: false, previousVersion: 'previous', candidateVersion: 'candidate' }), 'conflict');

const bootstrapContained = ({ workerStatus, subdomain, domains, routes }) => {
  if (!Array.isArray(domains) || domains.length !== 0 || !Array.isArray(routes) || routes.length !== 0) return false;
  if (workerStatus === 404) return true;
  return workerStatus === 200 && subdomain?.enabled === false && subdomain?.previews_enabled === true;
};
const postUploadSubdomainFailure = { workerStatus: 200, subdomain: { enabled: true, previews_enabled: true }, domains: [], routes: [] };
assert.equal(bootstrapContained(postUploadSubdomainFailure), false, 'A bootstrap upload followed by a subdomain failure is not contained until provider state is corrected');
assert.equal(bootstrapContained({ ...postUploadSubdomainFailure, subdomain: { enabled: false, previews_enabled: true } }), true, 'Corrected provider subdomain state and no custom domain contain a post-upload bootstrap failure');
assert.equal(bootstrapContained({ workerStatus: 200, subdomain: { enabled: false, previews_enabled: true }, domains: [{ id: 'concurrent' }], routes: [] }), false, 'Bootstrap containment must fail closed when any custom domain exists');
assert.equal(bootstrapContained({ workerStatus: 200, subdomain: { enabled: false, previews_enabled: true }, domains: [], routes: [{ pattern: 'other.example/*', script: config.name }] }), false, 'Bootstrap containment must fail closed when any ordinary Worker route exists');
const mayCorrectBootstrapSubdomain = ({ exactRunOwnedVersion, domains, hostnameDomains, routes }) => exactRunOwnedVersion === true
  && Array.isArray(domains) && domains.length === 0
  && Array.isArray(hostnameDomains) && hostnameDomains.length === 0
  && Array.isArray(routes) && routes.length === 0;
assert.equal(mayCorrectBootstrapSubdomain({ exactRunOwnedVersion: false, domains: [], hostnameDomains: [], routes: [] }), false, 'Containment must not mutate a concurrent Worker with the same name');
assert.equal(mayCorrectBootstrapSubdomain({ exactRunOwnedVersion: true, domains: [], hostnameDomains: [], routes: [] }), true, 'Containment may correct only the exact run-owned bootstrap when all ingress inventories are empty');
const mayAcceptLegacyContainedPrevious = ({ provenance, legacyBindings, serviceDomains, hostnameDomains, routes, subdomain }) => provenance === true
  && legacyBindings === true
  && Array.isArray(serviceDomains) && serviceDomains.length === 0
  && Array.isArray(hostnameDomains) && hostnameDomains.length === 0
  && Array.isArray(routes) && routes.length === 0
  && subdomain?.enabled === false && subdomain?.previews_enabled === true;
assert.equal(mayAcceptLegacyContainedPrevious({ provenance: true, legacyBindings: true, serviceDomains: [], hostnameDomains: [], routes: [], subdomain: { enabled: false, previews_enabled: true } }), true);
assert.equal(mayAcceptLegacyContainedPrevious({ provenance: false, legacyBindings: true, serviceDomains: [], hostnameDomains: [], routes: [], subdomain: { enabled: false, previews_enabled: true } }), false, 'Legacy binding upgrade requires contained-bootstrap provenance');
assert.equal(mayAcceptLegacyContainedPrevious({ provenance: true, legacyBindings: true, serviceDomains: [{ id: 'public' }], hostnameDomains: [{ id: 'public' }], routes: [], subdomain: { enabled: false, previews_enabled: true } }), false, 'A public legacy predecessor must never bypass version metadata');
const sortedKeysEqual = (value, expected) => value !== null
  && typeof value === 'object'
  && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
const rateLimiterBindingAccepted = (binding) => sortedKeysEqual(binding, ['name', 'namespace_id', 'simple', 'type'])
  && binding.name === 'ALERT_INGEST_RATE_LIMITER'
  && binding.type === 'ratelimit'
  && binding.namespace_id === '735104001'
  && (sortedKeysEqual(binding.simple, ['limit', 'period']) || sortedKeysEqual(binding.simple, ['limit', 'period', 'mitigation_timeout']))
  && binding.simple.limit === 60
  && binding.simple.period === 60
  && (!Object.hasOwn(binding.simple, 'mitigation_timeout') || (typeof binding.simple.mitigation_timeout === 'number' && binding.simple.mitigation_timeout === 0));
const bindingInventoryAccepted = (payload, view, expectedCount) => {
  const bindings = view === 'version' ? payload?.result?.resources?.bindings : view === 'settings' ? payload?.result?.bindings : null;
  if (![1, 2, 3].includes(expectedCount) || !Array.isArray(bindings) || bindings.length !== expectedCount) return false;
  const rateLimiters = bindings.filter(rateLimiterBindingAccepted);
  const secrets = bindings.filter((binding) => binding?.name === 'ALERT_HMAC_KEY' && binding?.type === 'secret_text');
  const metadata = bindings.filter((binding) => binding?.name === 'CF_VERSION_METADATA' && binding?.type === 'version_metadata');
  return rateLimiters.length === 1
    && secrets.length === (expectedCount >= 2 ? 1 : 0)
    && metadata.length === (expectedCount === 3 ? 1 : 0);
};
const rateLimitBinding = { name: 'ALERT_INGEST_RATE_LIMITER', type: 'ratelimit', namespace_id: '735104001', simple: { limit: 60, period: 60 } };
const normalizedRateLimitBinding = { type: 'ratelimit', simple: { mitigation_timeout: 0, period: 60, limit: 60 }, namespace_id: '735104001', name: 'ALERT_INGEST_RATE_LIMITER' };
const secretBinding = { name: 'ALERT_HMAC_KEY', type: 'secret_text', provider_metadata: 'ignored' };
const metadataBinding = { name: 'CF_VERSION_METADATA', type: 'version_metadata' };
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [normalizedRateLimitBinding, secretBinding] } } }, 'version', 2), true, 'Version details may normalize disabled mitigation_timeout to numeric zero');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [secretBinding, metadataBinding, rateLimitBinding] } } }, 'version', 3), true, 'Current version details must retain exactly the three authorized bindings');
assert.equal(bindingInventoryAccepted({ result: { bindings: [secretBinding, metadataBinding, rateLimitBinding] } }, 'settings', 3), true, 'Current settings must be read only from the settings binding path');
assert.equal(bindingInventoryAccepted({ result: { bindings: [secretBinding, rateLimitBinding] } }, 'settings', 2), true, 'Legacy settings may contain only the authorized secret and rate limiter');
assert.equal(bindingInventoryAccepted({ result: { bindings: [secretBinding, metadataBinding, rateLimitBinding] } }, 'version', 3), false, 'A version validator must not fall back to the settings path');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [secretBinding, metadataBinding, rateLimitBinding] } } }, 'settings', 3), false, 'A settings validator must not fall back to the version path');
for (const invalidTimeout of [10, null, '0', false, 0.5, -1]) {
  assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [{ ...rateLimitBinding, simple: { ...rateLimitBinding.simple, mitigation_timeout: invalidTimeout } }, secretBinding] } } }, 'version', 2), false, `Invalid mitigation_timeout ${String(invalidTimeout)} must fail closed`);
}
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [{ ...rateLimitBinding, unexpected: true }, secretBinding] } } }, 'version', 2), false, 'Unknown rate-limiter fields must fail closed');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [{ ...rateLimitBinding, simple: { ...rateLimitBinding.simple, unexpected: 0 } }, secretBinding] } } }, 'version', 2), false, 'Unknown rate-limiter behavior fields must fail closed');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [{ ...rateLimitBinding, namespace_id: 'wrong' }, secretBinding] } } }, 'version', 2), false, 'A different rate-limit namespace must fail closed');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [rateLimitBinding, secretBinding, { name: 'EXTRA', type: 'plain_text' }] } } }, 'version', 2), false, 'An additional binding must fail closed');
assert.equal(bindingInventoryAccepted({ result: { resources: { bindings: [rateLimitBinding, secretBinding, secretBinding] } } }, 'version', 3), false, 'A duplicate secret cannot substitute for version metadata');
const bindingInventoryFunction = workflow.split('          binding_inventory_ok() {')[1].split('          binding_ok() {')[0];
assert.ok(bindingInventoryFunction.includes('if $view=="version" then .result.resources.bindings elif $view=="settings" then .result.bindings else null end'), 'Binding validation must select the documented response path explicitly');
assert.doesNotMatch(bindingInventoryFunction, /resources\.bindings\/\//, 'Malformed or missing version bindings must not be defaulted');

const legacyBootstrapSha = 'e864778adb9b38e266afb18c672661d0b85e8b67';
const legacyBootstrapVersionId = '48d208dd-f054-4c54-bf67-918e126c49e0';
const legacyActiveVersionId = '9b7ef3f4-1111-2222-3333-444444444444';
const cloneJson = (value) => JSON.parse(JSON.stringify(value));
const legacyParent = {
  result: {
    id: legacyBootstrapVersionId,
    number: 7,
    annotations: { 'workers/tag': legacyBootstrapSha, 'workers/message': `contained bootstrap ${legacyBootstrapSha}` },
    metadata: { created_on: '2026-09-01T17:43:58.706Z', source: 'wrangler' },
    resources: { script: { etag: 'same-code-etag' }, bindings: [rateLimitBinding] },
  },
};
const legacySuccessor = {
  result: {
    id: legacyActiveVersionId,
    number: 8,
    metadata: { created_on: '2026-09-01T17:44:00.239Z', source: 'unknown' },
    resources: { script: { etag: 'same-code-etag' }, bindings: [normalizedRateLimitBinding, secretBinding] },
  },
};
const legacyBootstrapParentAccepted = (parent) => {
  const result = parent?.result;
  const annotations = [result?.annotations, result?.metadata?.annotations].filter((value) => value !== null && value !== undefined);
  return result?.id === legacyBootstrapVersionId
    && annotations.length >= 1
    && annotations.every((value) => value?.['workers/tag'] === legacyBootstrapSha && value?.['workers/message'] === `contained bootstrap ${legacyBootstrapSha}`)
    && Number.isSafeInteger(result?.number) && result.number > 0
    && typeof result?.metadata?.created_on === 'string'
    && typeof result?.resources?.script?.etag === 'string' && result.resources.script.etag.length > 0
    && bindingInventoryAccepted(parent, 'version', 1);
};
const legacySecretSuccessorAccepted = (active, parent, activeId) => {
  const parentResult = parent?.result;
  const activeResult = active?.result;
  const parentCreated = Date.parse(parentResult?.metadata?.created_on);
  const activeCreated = Date.parse(activeResult?.metadata?.created_on);
  return legacyBootstrapParentAccepted(parent)
    && bindingInventoryAccepted(active, 'version', 2)
    && activeResult?.id === activeId
    && activeResult.id !== legacyBootstrapVersionId
    && Number.isSafeInteger(activeResult?.number)
    && activeResult.number === parentResult.number + 1
    && typeof activeResult?.resources?.script?.etag === 'string' && activeResult.resources.script.etag.length > 0
    && activeResult.resources.script.etag === parentResult.resources.script.etag
    && Number.isFinite(parentCreated) && Number.isFinite(activeCreated)
    && activeCreated > parentCreated && activeCreated - parentCreated <= 600_000;
};
assert.equal(legacySecretSuccessorAccepted(legacySuccessor, legacyParent, legacyActiveVersionId), true, 'The exact immediate code-identical secret successor must pass without depending on optional source metadata');
for (const [label, mutate] of [
  ['wrong parent id', (active, parent) => { parent.result.id = 'wrong'; }],
  ['wrong parent tag', (active, parent) => { parent.result.annotations['workers/tag'] = 'f'.repeat(40); }],
  ['conflicting parent annotations', (active, parent) => { parent.result.metadata.annotations = { 'workers/tag': 'f'.repeat(40), 'workers/message': 'wrong' }; }],
  ['non-adjacent number', (active) => { active.result.number += 1; }],
  ['different script', (active) => { active.result.resources.script.etag = 'different'; }],
  ['late successor', (active) => { active.result.metadata.created_on = '2026-09-01T18:00:00Z'; }],
  ['invalid timestamp', (active) => { active.result.metadata.created_on = 'invalid'; }],
  ['extra binding', (active) => { active.result.resources.bindings.push({ name: 'EXTRA', type: 'plain_text' }); }],
]) {
  const active = cloneJson(legacySuccessor);
  const parent = cloneJson(legacyParent);
  mutate(active, parent);
  assert.equal(legacySecretSuccessorAccepted(active, parent, legacyActiveVersionId), false, `Legacy successor with ${label} must fail closed`);
}
assert.equal(legacySecretSuccessorAccepted(legacySuccessor, legacyParent, 'different-active-id'), false, 'The fallback must bind to the exact active deployment version ID');
assert.doesNotMatch(workflow.split('          legacy_secret_successor_ok() {')[1].split('          candidate_version_ok() {')[0], /metadata\.source/, 'Optional provider source metadata must not become a brittle authorization gate');

const domainInventoryComplete = (payload) => {
  const { result, result_info: info } = payload;
  if (!Array.isArray(result)) return false;
  if (!Object.hasOwn(payload, 'result_info') || info === null) return true;
  if (typeof info !== 'object' || Array.isArray(info)) return false;
  return (!Object.hasOwn(info, 'page') || (Number.isInteger(info.page) && info.page === 1))
    && (!Object.hasOwn(info, 'per_page') || (Number.isInteger(info.per_page) && info.per_page >= result.length))
    && (!Object.hasOwn(info, 'count') || (Number.isInteger(info.count) && info.count === result.length))
    && (!Object.hasOwn(info, 'total_pages') || (Number.isInteger(info.total_pages) && info.total_pages >= 0 && info.total_pages <= 1 && (result.length === 0 || info.total_pages === 1)));
};
assert.equal(domainInventoryComplete({ result: [] }), true, 'The pinned Worker Domains API is an authoritative single-page result without pagination metadata');
assert.equal(domainInventoryComplete({ result: [], result_info: { page: 1, per_page: 20, count: 0, total_pages: 0 } }), true, 'A complete empty service-filtered domain inventory must pass');
assert.equal(domainInventoryComplete({ result: [], result_info: null }), true, 'Null non-contract pagination metadata must not invalidate an authoritative single-page result');
assert.equal(domainInventoryComplete({ result: [], result_info: {} }), true, 'Non-contract metadata fields are not required by the pinned single-page endpoint');
assert.equal(domainInventoryComplete({ result: [], result_info: 'unexpected' }), false, 'A non-object metadata extension must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { total_pages: '1' } }), false, 'An explicitly malformed page count must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { total_pages: null } }), false, 'An explicitly null page count must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { total_pages: false } }), false, 'An explicitly boolean page count must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { total_pages: 0.5 } }), false, 'An explicitly fractional page count must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { page: 1, per_page: 20, count: 0, total_pages: 2 } }), false, 'A truncated domain inventory must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { page: 2 } }), false, 'An explicitly contradictory page must fail closed');
assert.equal(domainInventoryComplete({ result: [], result_info: { count: 1 } }), false, 'An explicitly contradictory result count must fail closed');
assert.equal(domainInventoryComplete({ result: [{}], result_info: { per_page: 0 } }), false, 'An explicitly insufficient page size must fail closed');
assert.equal(domainInventoryComplete({ result: [{}], result_info: { total_pages: 0 } }), false, 'Zero explicit pages must contradict and reject a non-empty inventory');
assert.equal(domainInventoryComplete({ result: [], result_info: { page: 1, per_page: 0, count: 0 } }), true, 'Consistent optional pagination metadata must be accepted');
const domainListCompleteLine = workflow.split('\n').find((line) => line.includes('domain_list_complete()'));
assert.ok(domainListCompleteLine, 'The Worker Domain single-page validator must exist');
for (const field of ['page', 'per_page', 'count', 'total_pages']) {
  assert.match(domainListCompleteLine, new RegExp(`\\.result_info\\|has\\("${field}"\\)\\|not`), `Optional ${field} metadata must be validated only when present`);
}
const scriptRouteInventoryAccepted = (payload, expectedPresent) => {
  if (!domainInventoryComplete(payload)) return false;
  const matches = payload.result.filter((item) => item?.id === config.name);
  if (!expectedPresent) return matches.length === 0;
  if (matches.length !== 1) return false;
  const [script] = matches;
  return !Object.hasOwn(script, 'routes') || script.routes === null || (Array.isArray(script.routes) && script.routes.length === 0);
};
const containedScript = { id: config.name };
assert.equal(scriptRouteInventoryAccepted({ result: [containedScript] }, true), true, 'The documented omitted routes field must represent no ordinary routes');
assert.equal(scriptRouteInventoryAccepted({ result: [{ ...containedScript, routes: null }] }, true), true, 'The documented null routes field must represent no ordinary routes');
assert.equal(scriptRouteInventoryAccepted({ result: [{ ...containedScript, routes: [] }] }, true), true, 'An explicit empty routes inventory must pass');
assert.equal(scriptRouteInventoryAccepted({ result: [{ id: 'unrelated' }, containedScript] }, true), true, 'Unrelated Workers must not invalidate the exact target route proof');
assert.equal(scriptRouteInventoryAccepted({ result: [] }, true), false, 'A missing target Worker must fail closed when presence is required');
assert.equal(scriptRouteInventoryAccepted({ result: [containedScript, containedScript] }, true), false, 'Duplicate target Workers must fail closed');
for (const routes of [false, 'unexpected', {}, [{ pattern: 'scalesmall.ai/*' }]]) {
  assert.equal(scriptRouteInventoryAccepted({ result: [{ ...containedScript, routes }] }, true), false, 'Malformed or non-empty route metadata must fail closed');
}
assert.equal(scriptRouteInventoryAccepted({ result: [{ id: 'unrelated' }] }, false), true, 'Target absence must pass when only unrelated Workers exist');
assert.equal(scriptRouteInventoryAccepted({ result: [containedScript] }, false), false, 'Any exact target match must fail when absence is required');
assert.equal(scriptRouteInventoryAccepted({ result: [containedScript], result_info: { total_pages: 2 } }, true), false, 'A contradictory multi-page script inventory must fail closed');
assert.equal(scriptRouteInventoryAccepted({ result: null }, true), false, 'A malformed script inventory must fail closed');
const scriptRoutesFunction = workflow.split('          script_routes_absent() {')[1].split('          timestamp_gte() {')[0];
assert.ok(scriptRoutesFunction.includes('domain_list_complete "$input" || return 1'), 'Script route absence must reject incomplete or contradictory list metadata');
assert.ok(scriptRoutesFunction.includes('($matches[0]|has("routes")|not)'), 'The documented omitted routes representation must be accepted explicitly');
assert.ok(scriptRoutesFunction.includes('$matches[0].routes==null'), 'The documented null routes representation must be accepted explicitly');
assert.ok(scriptRoutesFunction.includes('($matches[0].routes|type)=="array" and ($matches[0].routes|length)==0'), 'Only explicit empty route arrays may pass');
assert.doesNotMatch(scriptRoutesFunction, /routes\s*\/\/\s*\[\]/, 'Defaulting route metadata must not hide malformed false values');
const routedDomain = {
  id: 'a'.repeat(32),
  cert_id: '11111111-1111-4111-8111-111111111111',
  hostname: 'alerts.scalesmall.ai',
  service: config.name,
  zone_id: 'b'.repeat(32),
  zone_name: 'scalesmall.ai',
  environment: 'production',
};
const exactDomainDetail = ({ id, cert_id, hostname, service, zone_id, zone_name, environment }) => id === routedDomain.id
  && hostname === routedDomain.hostname
  && service === routedDomain.service
  && zone_name === routedDomain.zone_name
  && /^[a-f0-9]{32}$/.test(zone_id)
  && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(cert_id)
  && (environment ?? 'production') === 'production';
assert.equal(exactDomainDetail(routedDomain), true, 'The exact intended domain must pass');
assert.equal(exactDomainDetail({ ...routedDomain, cert_id: '22222222-2222-4222-8222-222222222222' }), true, 'A rotated valid provider certificate remains the same validated route');
assert.equal(exactDomainDetail({ ...routedDomain, zone_id: 'c'.repeat(32) }), true, 'A well-formed provider-returned zone ID remains subordinate to immutable domain and exact routing names');
for (const [field, value] of [
  ['id', 'd'.repeat(32)],
  ['hostname', 'other.scalesmall.ai'],
  ['service', 'other-worker'],
  ['zone_name', 'other.example'],
  ['environment', 'staging'],
]) {
  assert.equal(exactDomainDetail({ ...routedDomain, [field]: value }), false, `Domain validation must reject a changed ${field}`);
}
assert.equal(exactDomainDetail({ ...routedDomain, zone_id: 'not-a-zone-id' }), false, 'Malformed provider zone identity must fail closed');
assert.equal(exactDomainDetail({ ...routedDomain, cert_id: 'not-a-certificate-id' }), false, 'Malformed provider certificate identity must fail closed');
const exactNormalIngress = ({ domains, hostnameDomains, routes, subdomain }) => Array.isArray(domains)
  && domains.length === 1
  && domains[0].hostname === 'alerts.scalesmall.ai'
  && domains[0].service === config.name
  && Array.isArray(hostnameDomains)
  && hostnameDomains.length === 1
  && hostnameDomains[0].id === domains[0].id
  && hostnameDomains[0].hostname === domains[0].hostname
  && hostnameDomains[0].service === domains[0].service
  && Array.isArray(routes)
  && routes.length === 0
  && subdomain?.enabled === false
  && subdomain?.previews_enabled === true;
const safeSubdomain = { enabled: false, previews_enabled: true };
const exactDomain = { id: 'a'.repeat(32), hostname: 'alerts.scalesmall.ai', service: config.name };
assert.equal(exactNormalIngress({ domains: [exactDomain], hostnameDomains: [exactDomain], routes: [], subdomain: safeSubdomain }), true, 'The exact intended custom domain and no ordinary routes must pass');
assert.equal(exactNormalIngress({ domains: [exactDomain, { id: 'b'.repeat(32), hostname: 'shadow.scalesmall.ai', service: config.name }], hostnameDomains: [exactDomain], routes: [], subdomain: safeSubdomain }), false, 'A different hostname bound to the same service must fail closed');
assert.equal(exactNormalIngress({ domains: [exactDomain], hostnameDomains: [{ ...exactDomain, id: 'b'.repeat(32), service: 'other-worker' }], routes: [], subdomain: safeSubdomain }), false, 'A hostname attached to another Worker must fail closed');
assert.equal(exactNormalIngress({ domains: [exactDomain], hostnameDomains: [exactDomain], routes: [{ pattern: 'scalesmall.ai/*', script: config.name }], subdomain: safeSubdomain }), false, 'An ordinary route bound to the service must fail closed');
assert.equal(exactNormalIngress({ domains: [exactDomain], hostnameDomains: [exactDomain], routes: [], subdomain: { enabled: true, previews_enabled: true } }), false, 'A public workers.dev ingress must fail closed');
assert.equal(exactNormalIngress({ domains: [exactDomain], hostnameDomains: [exactDomain], subdomain: safeSubdomain }), false, 'Missing ordinary-route evidence must fail closed');

const expectedConfig = process.env.SSAI_EXPECTED_ALERT_GATEWAY_CONFIG_SHA256;
const expectedSource = process.env.SSAI_EXPECTED_ALERT_GATEWAY_SOURCE_SHA256;
if (expectedConfig !== undefined) { assert.match(expectedConfig, /^[a-f0-9]{64}$/); assert.equal(expectedConfig, configDigest); }
if (expectedSource !== undefined) { assert.match(expectedSource, /^[a-f0-9]{64}$/); assert.equal(expectedSource, sourceDigest); }
console.log(JSON.stringify({ alert_gateway_config_sha256: configDigest, alert_gateway_source_sha256: sourceDigest }));
