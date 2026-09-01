import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
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
for (const key of ['vars', 'durable_objects', 'kv_namespaces', 'd1_databases', 'r2_buckets', 'services', 'triggers']) assert.equal(key in config, false);

for (const required of [
  'on:\n  workflow_dispatch:', 'allow_first_bootstrap:', 'environment:\n      name: release-health-controller-production',
  'github.workflow_sha == inputs.expected_sha', 'github.run_attempt == 1', "test '${{ github.run_attempt }}' = 1",
  'persist-credentials: false', "version!=='4.127.1'", 'versions upload', '--preview-alias', '--strict --dry-run',
  'CLOUDFLARE_ACCOUNT_ID: ${{ secrets.SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID }}',
  'CLOUDFLARE_API_TOKEN: ${{ secrets.SSAI_RELEASE_CONTROLLER_CLOUDFLARE_API_TOKEN }}',
  'ALERT_HMAC_KEY: ${{ secrets.SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY }}',
  'RATE_LIMITER_NAMESPACE_ID: \'735104001\'', 'X-SSAI-Preview-Health-Host:', 'metadata.has_preview==true',
  'workers/alias', 'previous_version_id', 'traffic_mutated=true', 'automatic rollback after',
  'versions deploy "${previous_version_id}@100%"', 'versions deploy "${candidate_version_id}@100%"',
  'wrangler triggers deploy', 'test "$ALLOW_FIRST_BOOTSTRAP" = true',
  'bootstrap_dir="$RUNNER_TEMP/gateway-bootstrap"', 'install -d -m 700 -- "$bootstrap_dir"',
  'cp -R -- "$(dirname "$GATEWAY_CONFIG")/." "$bootstrap_dir/"',
  'bootstrap_config="$bootstrap_dir/$(basename "$GATEWAY_CONFIG")"',
  'jq \'.routes=[]\' "$GATEWAY_CONFIG" > "$bootstrap_config"',
  'wrangler deploy --config "$bootstrap_config" --name "$GATEWAY_NAME" --dry-run --outdir "$RUNNER_TEMP/gateway-bootstrap-dry-run"',
  'wrangler deploy --config "$bootstrap_config"', 'wrangler secret put ALERT_HMAC_KEY --config "$bootstrap_config"',
  'test -z "$bootstrap_dir" || rm -rf -- "$bootstrap_dir"',
  '/workers/domains', '/deployments', '/versions/$candidate_version_id', '/settings', '/secrets', '/subdomain',
  'wrangler secret put ALERT_HMAC_KEY', 'name=="ALERT_HMAC_KEY" and .type=="secret_text"',
  'expected_secret_names:["ALERT_HMAC_KEY"]', '.result.enabled==false and .result.previews_enabled==true', 'ssai-release-health-alert-gateway-deployment-evidence-v2',
  'rm -rf -- "$RUNNER_TEMP/gateway-dry-run"',
]) assert.ok(workflow.includes(required), `Missing gateway deployment contract: ${required}`);

const jobPrefix = workflow.slice(0, workflow.indexOf('    steps:'));
assert.doesNotMatch(jobPrefix, /CLOUDFLARE_(?:ACCOUNT_ID|API_TOKEN)/);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_CLOUDFLARE_ACCOUNT_ID/g) ?? []).length, 1);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_CLOUDFLARE_API_TOKEN/g) ?? []).length, 1);
assert.equal((workflow.match(/SSAI_RELEASE_CONTROLLER_ALERT_SIGNING_KEY/g) ?? []).length, 1);
for (const use of workflow.matchAll(/^\s*- uses:\s*([^\s]+)$/gm)) assert.match(use[1], /^[^@]+@[a-f0-9]{40}$/);
assert.doesNotMatch(workflow, /\b(?:push|pull_request|schedule|repository_dispatch|workflow_run):/);
assert.doesNotMatch(workflow, /cloudflare\/wrangler-action|npx\s+wrangler|npm\s+install/i);
assert.doesNotMatch(workflow, /wrangler\s+(?:delete|rollback|triggers\s+delete|secret\s+delete)/i);
assert.doesNotMatch(workflow, /\bDELETE\b|workers\/domains[^\n]*(?:delete|remove)/i);
assert.doesNotMatch(workflow, /SSAI_RELEASE_CONTROLLER_(?:GITHUB|ADMISSION|ACTIVATION)/);
assert.doesNotMatch(workflow, /\$RUNNER_TEMP\/gateway-bootstrap\.jsonc/);

const bootstrapRoot = await mkdtemp(join(tmpdir(), 'ssai-alert-gateway-bootstrap-'));
try {
  const stagedDirectory = join(bootstrapRoot, 'gateway');
  const stagedConfigPath = join(stagedDirectory, 'wrangler.jsonc');
  const dryRunDirectory = join(bootstrapRoot, 'dry-run');
  await cp(fileURLToPath(new URL('workers/release-health-alert-gateway/', root)), stagedDirectory, { recursive: true, errorOnExist: true });
  await writeFile(stagedConfigPath, `${JSON.stringify({ ...config, routes: [] }, null, 2)}\n`, { mode: 0o600 });
  const stagedConfig = JSON.parse(await readFile(stagedConfigPath, 'utf8'));
  assert.equal(stagedConfig.main, config.main);
  assert.deepEqual(stagedConfig.routes, []);
  await readFile(join(stagedDirectory, stagedConfig.main));
  execFileSync(process.execPath, [
    fileURLToPath(new URL('node_modules/wrangler/bin/wrangler.js', root)),
    'deploy', '--config', stagedConfigPath, '--name', config.name, '--dry-run', '--outdir', dryRunDirectory,
  ], {
    cwd: fileURLToPath(root),
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    stdio: 'pipe',
    timeout: 60_000,
  });
  assert.ok((await readdir(dryRunDirectory)).length > 0, 'Staged bootstrap dry-run must emit a bundle');
} finally {
  await rm(bootstrapRoot, { recursive: true, force: true });
}

const expectedConfig = process.env.SSAI_EXPECTED_ALERT_GATEWAY_CONFIG_SHA256;
const expectedSource = process.env.SSAI_EXPECTED_ALERT_GATEWAY_SOURCE_SHA256;
if (expectedConfig !== undefined) { assert.match(expectedConfig, /^[a-f0-9]{64}$/); assert.equal(expectedConfig, configDigest); }
if (expectedSource !== undefined) { assert.match(expectedSource, /^[a-f0-9]{64}$/); assert.equal(expectedSource, sourceDigest); }
console.log(JSON.stringify({ alert_gateway_config_sha256: configDigest, alert_gateway_source_sha256: sourceDigest }));
