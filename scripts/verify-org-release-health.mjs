import { appendFile } from 'node:fs/promises';

const token = requiredSecret(process.env.SSAI_RELEASE_MONITOR_GITHUB_TOKEN, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN');
const owner = safeName(process.env.SSAI_RELEASE_MONITOR_OWNER || 'ScaleSmall', 'SSAI_RELEASE_MONITOR_OWNER');
const repoPrefix = safeName(process.env.SSAI_RELEASE_MONITOR_REPO_PREFIX || 'SSAI_', 'SSAI_RELEASE_MONITOR_REPO_PREFIX');
const stuckMinutes = boundedNumber(process.env.SSAI_RELEASE_MONITOR_STUCK_MINUTES, 45, 15, 240);
const stuckMs = stuckMinutes * 60_000;
const allowedNoHistory = new Set(['SSAI_CI_Engine:Retire Production CI Test Token Broker']);
const acceptableConclusions = new Set(['success', 'neutral', 'skipped']);
const failedConclusions = new Set(['failure', 'cancelled', 'timed_out', 'action_required', 'startup_failure', 'stale']);
const failures = [];
const warnings = [];
const rows = [];

const repositories = (await listRepositories())
  .filter((repo) => repo.owner?.login === owner && !repo.archived && String(repo.name).startsWith(repoPrefix))
  .sort((left, right) => left.name.localeCompare(right.name));

if (repositories.length === 0) {
  throw new Error(`No active ${owner}/${repoPrefix}* repositories were visible to the monitor token.`);
}

await mapLimit(repositories, 4, inspectRepository);

const workflowRows = rows.flatMap((row) => row.workflows);
const greenWorkflows = workflowRows.filter((row) => row.status === 'completed' && acceptableConclusions.has(row.conclusion));
const pendingWorkflows = workflowRows.filter((row) => row.status !== 'completed' && row.status !== 'no_history');
const noHistoryWorkflows = workflowRows.filter((row) => row.status === 'no_history');
const summary = {
  ok: failures.length === 0,
  checked_at: new Date().toISOString(),
  owner,
  repository_prefix: repoPrefix,
  repositories: repositories.length,
  active_workflows: workflowRows.length,
  green_workflows: greenWorkflows.length,
  pending_workflows: pendingWorkflows.length,
  allowed_no_history_workflows: noHistoryWorkflows.length,
  current_commit_checks: rows.reduce((total, row) => total + row.checks.length + row.statuses.length, 0),
  failures,
  warnings,
};

console.log(JSON.stringify(summary, null, 2));
await writeStepSummary(summary);

if (failures.length > 0) process.exit(1);

async function inspectRepository(repo) {
  const defaultBranch = String(repo.default_branch || 'main');
  const [workflowPayload, commit] = await Promise.all([
    api(`/repos/${owner}/${repo.name}/actions/workflows?per_page=100`),
    api(`/repos/${owner}/${repo.name}/commits/${encodeURIComponent(defaultBranch)}`),
  ]);
  const workflows = (workflowPayload.workflows || []).filter((workflow) => workflow.state === 'active');
  const workflowHealth = await mapLimit(workflows, 5, async (workflow) => {
    const payload = await api(`/repos/${owner}/${repo.name}/actions/workflows/${workflow.id}/runs?branch=${encodeURIComponent(defaultBranch)}&per_page=1`);
    const run = payload.workflow_runs?.[0] || null;
    const key = `${repo.name}:${workflow.name}`;
    if (!run) {
      if (!allowedNoHistory.has(key)) failures.push(issue(repo.name, workflow.name, 'active workflow has no default-branch run history'));
      return { name: workflow.name, id: workflow.id, status: 'no_history', conclusion: 'no_history', run_id: null, url: workflow.html_url };
    }

    const ageMs = Date.now() - new Date(run.run_started_at || run.created_at || 0).getTime();
    const conclusion = String(run.conclusion || '');
    if (run.status === 'completed' && !acceptableConclusions.has(conclusion)) {
      failures.push(issue(repo.name, workflow.name, `latest run ${run.id} concluded ${conclusion}`, run.html_url));
    } else if (run.status !== 'completed' && ageMs > stuckMs) {
      failures.push(issue(repo.name, workflow.name, `run ${run.id} is stuck in ${run.status} for more than ${stuckMinutes} minutes`, run.html_url));
    }
    return { name: workflow.name, id: workflow.id, status: run.status, conclusion, run_id: run.id, url: run.html_url };
  });

  const headSha = String(commit.sha || '');
  const [checkPayload, statusPayload] = await Promise.all([
    api(`/repos/${owner}/${repo.name}/commits/${headSha}/check-runs?filter=latest&per_page=100`),
    api(`/repos/${owner}/${repo.name}/commits/${headSha}/statuses?per_page=100`),
  ]);
  const checks = (checkPayload.check_runs || []).map((check) => {
    const ageMs = Date.now() - new Date(check.started_at || check.created_at || 0).getTime();
    const conclusion = String(check.conclusion || '');
    if (check.status === 'completed' && failedConclusions.has(conclusion)) {
      failures.push(issue(repo.name, check.name, `current commit check concluded ${conclusion}`, check.details_url));
    } else if (check.status !== 'completed' && ageMs > stuckMs) {
      failures.push(issue(repo.name, check.name, `current commit check is stuck in ${check.status} for more than ${stuckMinutes} minutes`, check.details_url));
    }
    return { name: check.name, status: check.status, conclusion, url: check.details_url };
  });
  const seenStatusContexts = new Set();
  const latestStatuses = (statusPayload || []).filter((status) => {
    if (seenStatusContexts.has(status.context)) return false;
    seenStatusContexts.add(status.context);
    return true;
  });
  const statuses = latestStatuses.map((status) => {
    const ageMs = Date.now() - new Date(status.updated_at || status.created_at || 0).getTime();
    if (['error', 'failure'].includes(status.state)) {
      failures.push(issue(repo.name, status.context, `current commit status is ${status.state}`, status.target_url));
    } else if (status.state === 'pending' && ageMs > stuckMs) {
      failures.push(issue(repo.name, status.context, `current commit status is pending for more than ${stuckMinutes} minutes`, status.target_url));
    }
    return { name: status.context, status: status.state, conclusion: status.state, url: status.target_url };
  });

  rows.push({ repo: repo.name, default_branch: defaultBranch, head_sha: headSha, workflows: workflowHealth, checks, statuses });
}

async function listRepositories() {
  const all = [];
  for (let page = 1; page <= 10; page += 1) {
    const batch = await api(`/user/repos?affiliation=owner,organization_member&visibility=all&per_page=100&page=${page}`);
    if (!Array.isArray(batch)) throw new Error('GitHub repository list returned an invalid response.');
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}

async function api(pathname) {
  const url = `https://api.github.com${pathname}`;
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);
    try {
      const response = await fetch(url, {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'User-Agent': 'Scale-Small-AI-release-health-monitor',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        signal: controller.signal,
      });
      if (response.ok) return await response.json();
      const message = (await response.text()).slice(0, 500).replace(/\s+/g, ' ');
      lastError = new Error(`GitHub API ${pathname} returned HTTP ${response.status}: ${message}`);
      if (![429, 500, 502, 503, 504].includes(response.status)) break;
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
    if (attempt < 3) await sleep(attempt * 750);
  }
  throw lastError || new Error(`GitHub API request failed: ${pathname}`);
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }));
  return results;
}

async function writeStepSummary(result) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const lines = [
    '# Scale Small AI release health',
    '',
    `- Repositories: ${result.repositories}`,
    `- Active workflows: ${result.active_workflows}`,
    `- Green workflows: ${result.green_workflows}`,
    `- Pending workflows: ${result.pending_workflows}`,
    `- Allowed no-history workflows: ${result.allowed_no_history_workflows}`,
    `- Current commit checks/statuses: ${result.current_commit_checks}`,
    `- Failures: ${result.failures.length}`,
  ];
  if (result.failures.length) {
    lines.push('', '## Failures', '', ...result.failures.map((failure) => `- ${failure.url ? `[${failure.repo} / ${failure.owner}](${failure.url})` : `${failure.repo} / ${failure.owner}`}: ${failure.problem}`));
  }
  await appendFile(path, `${lines.join('\n')}\n`, 'utf8');
}

function issue(repo, ownerName, problem, url = '') {
  return { repo, owner: String(ownerName || 'unknown'), problem, url: String(url || '') };
}

function requiredSecret(value, name) {
  const text = String(value || '').trim();
  if (text.length < 20) throw new Error(`${name} is missing or too short.`);
  return text;
}

function safeName(value, name) {
  const text = String(value || '').trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(text)) throw new Error(`${name} contains unsupported characters.`);
  return text;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
