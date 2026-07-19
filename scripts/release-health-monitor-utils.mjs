import { createHash } from 'node:crypto';

export function latestByIdentity(records, identityOf) {
  if (!Array.isArray(records)) throw new TypeError('records must be an array');
  if (typeof identityOf !== 'function') throw new TypeError('identityOf must be a function');

  const latest = new Map();
  for (const record of records) {
    const identity = String(identityOf(record) || '').trim();
    if (!identity) throw new Error('release-health record identity must not be empty');
    const current = latest.get(identity);
    if (!current || compareOccurrence(record, current) > 0) latest.set(identity, record);
  }
  return [...latest.values()];
}

export function partitionWorkflowHealth(rows, acceptableConclusions) {
  if (!Array.isArray(rows)) throw new TypeError('rows must be an array');
  if (!(acceptableConclusions instanceof Set)) throw new TypeError('acceptableConclusions must be a Set');

  const green = [];
  const pending = [];
  const failed = [];
  const allowedNoHistory = [];
  const unresolvedNoHistory = [];
  for (const row of rows) {
    if (row?.status === 'no_history') {
      (row.allowed_no_history === true ? allowedNoHistory : unresolvedNoHistory).push(row);
    } else if (row?.status === 'completed') {
      (acceptableConclusions.has(row?.conclusion) ? green : failed).push(row);
    } else {
      pending.push(row);
    }
  }

  const categorized = green.length + pending.length + failed.length + allowedNoHistory.length + unresolvedNoHistory.length;
  if (categorized !== rows.length) throw new Error('workflow health categories do not cover the active workflow inventory');
  return { green, pending, failed, allowedNoHistory, unresolvedNoHistory, categorized };
}

export function evaluateNoHistoryAllowance({
  workflow,
  policy,
  workflowSource,
  workflows,
  runs,
  defaultBranch,
  expectedHeadSha,
  nowMs,
}) {
  if (!workflow || typeof workflow !== 'object') throw new TypeError('workflow must be an object');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    return { allowed: false, reason: 'no explicit no-history policy is configured' };
  }
  if (!Array.isArray(workflows)) throw new TypeError('workflows must be an array');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  if (!Number.isFinite(nowMs)) throw new TypeError('nowMs must be finite');

  const reason = String(policy.reason || '').trim();
  if (!reason) return { allowed: false, reason: 'the configured no-history policy has no rationale' };

  const expectedPath = String(policy.path || '').trim();
  if (!expectedPath || String(workflow.path || '') !== expectedPath) {
    return { allowed: false, reason: 'the workflow path does not match the explicitly approved release control' };
  }

  const expectedSourceSha256 = String(policy.sourceSha256 || '').trim().toLowerCase();
  const sourceBytes = typeof workflowSource === 'string' ? Buffer.from(workflowSource, 'utf8') : workflowSource;
  if (!/^[a-f0-9]{64}$/.test(expectedSourceSha256) || !Buffer.isBuffer(sourceBytes)) {
    return { allowed: false, reason: 'the approved workflow source digest or fetched source is invalid' };
  }
  const actualSourceSha256 = createHash('sha256').update(sourceBytes).digest('hex');
  if (actualSourceSha256 !== expectedSourceSha256) {
    return { allowed: false, reason: 'the workflow source changed after its no-history control was approved' };
  }

  if (!policy.witness || typeof policy.witness !== 'object' || Array.isArray(policy.witness)) {
    return { allowed: false, reason: 'the configured witness policy is invalid' };
  }

  const witnessName = String(policy.witness.name || '').trim();
  const witnessPath = String(policy.witness.path || '').trim();
  const witnessRepository = String(policy.witness.headRepository || '').trim();
  const allowedEvents = Array.isArray(policy.witness.allowedEvents)
    ? policy.witness.allowedEvents.map((event) => String(event || '').trim()).filter(Boolean)
    : [];
  const maxAgeHours = Number(policy.witness.maxAgeHours);
  if (!witnessName || !witnessPath || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(witnessRepository)
    || allowedEvents.length === 0 || !Number.isFinite(maxAgeHours) || maxAgeHours <= 0 || maxAgeHours > 168) {
    return { allowed: false, reason: 'the configured witness workflow contract is invalid' };
  }

  const witnessWorkflow = workflows.find((candidate) => candidate?.state === 'active'
    && candidate?.name === witnessName
    && candidate?.path === witnessPath);
  if (!witnessWorkflow) {
    return { allowed: false, reason: 'the required active witness workflow is missing or moved' };
  }

  const branch = String(defaultBranch || '').trim();
  const headSha = String(expectedHeadSha || '').trim();
  if (!/^[a-f0-9]{40}$/i.test(headSha)) {
    return { allowed: false, reason: 'the current default-branch commit cannot be bound to witness evidence' };
  }
  const witnessRun = runs
    .filter((run) => Number(run?.workflow_id) === Number(witnessWorkflow.id) && run?.head_branch === branch)
    .sort(compareNewestFirst)[0];
  if (!witnessRun) return { allowed: false, reason: 'the required witness workflow has no recent default-branch run evidence' };
  if (witnessRun.status !== 'completed' || witnessRun.conclusion !== 'success') {
    return { allowed: false, reason: 'the latest witness workflow run is not a completed success' };
  }
  if (String(witnessRun.head_sha || '').toLowerCase() !== headSha.toLowerCase()) {
    return { allowed: false, reason: 'the latest successful witness workflow run does not prove the current default-branch commit' };
  }
  const runEvent = String(witnessRun.event || '').trim();
  if (!allowedEvents.includes(runEvent)) {
    return { allowed: false, reason: 'the latest successful witness workflow run used an unapproved trigger' };
  }
  const runRepository = String(witnessRun.head_repository?.full_name || witnessRun.head_repository || '').trim();
  if (runRepository !== witnessRepository) {
    return { allowed: false, reason: 'the latest successful witness workflow run came from an unapproved repository' };
  }
  const runUrl = String(witnessRun.html_url || '').trim();
  if (!runUrl.startsWith('https://github.com/' + witnessRepository + '/actions/runs/')) {
    return { allowed: false, reason: 'the latest successful witness workflow run URL is not auditable' };
  }

  const occurredAtMs = occurrenceTime(witnessRun);
  const ageMs = nowMs - occurredAtMs;
  if (!occurredAtMs || ageMs < -300_000 || ageMs > maxAgeHours * 60 * 60_000) {
    return { allowed: false, reason: 'the latest successful witness workflow run is outside the approved freshness window' };
  }

  return {
    allowed: true,
    reason,
    workflow_source_sha256: actualSourceSha256,
    witness: {
      workflow: witnessWorkflow.name,
      workflow_id: witnessWorkflow.id,
      run_id: witnessRun.id,
      head_sha: headSha,
      event: runEvent,
      head_repository: runRepository,
      url: runUrl,
      occurred_at: new Date(occurredAtMs).toISOString(),
      max_age_hours: maxAgeHours,
    },
  };
}

export function rateHeadroomDecision(scanMode, remaining, reserve, requestBudget) {
  if (!['continuous', 'incident'].includes(scanMode)) throw new Error('scanMode must be continuous or incident');
  for (const [name, value] of [['remaining', remaining], ['reserve', reserve], ['requestBudget', requestBudget]]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(name + ' must be a non-negative integer');
  }
  if (remaining >= reserve + requestBudget) return 'run';
  return scanMode === 'continuous' ? 'defer' : 'fail';
}

export function workflowStreamIdentity(run) {
  if (!run || typeof run !== 'object') throw new TypeError('run must be an object');
  const branch = String(run.head_branch || '').trim()
    || ('sha-' + requiredIdentityPart(run.head_sha, 'head_sha'));
  const headRepository = String(run.head_repository?.full_name || run.head_repository?.id || run.head_repository || '').trim();
  const identity = [
    'workflow',
    requiredIdentityPart(run.workflow_id, 'workflow_id'),
  ];
  if (headRepository) identity.push('head-repository', headRepository);
  identity.push(
    'branch',
    branch,
    'event',
    requiredIdentityPart(run.event, 'event'),
  );
  return joinIdentity(identity);
}

export function checkStreamIdentity(check) {
  if (!check || typeof check !== 'object') throw new TypeError('check must be an object');
  if (String(check.stream_identity || '').trim()) return String(check.stream_identity).trim();

  const provider = String(check?.app?.slug || check?.app?.id || 'unknown-app');
  const name = requiredIdentityPart(check.name, 'check name');
  const branch = String(check.head_branch || '').trim();
  const headRepository = String(check.head_repository || '').trim();
  const workflowId = String(check.workflow_id || '').trim();
  const event = String(check.event || '').trim();

  if (provider === 'github-actions' && workflowId && branch && event) {
    const identity = ['check', provider, 'workflow', workflowId];
    if (headRepository) identity.push('head-repository', headRepository);
    identity.push('branch', branch, 'event', event, 'job', name);
    return joinIdentity(identity);
  }

  if (branch) {
    const identity = ['check', provider];
    if (headRepository) identity.push('head-repository', headRepository);
    identity.push('branch', branch, 'name', name);
    return joinIdentity(identity);
  }

  // A check without an authoritative branch cannot safely recover a check on a
  // different commit. Keeping the SHA in the identity is deliberately fail-closed.
  return joinIdentity([
    'check',
    provider,
    'sha',
    requiredIdentityPart(check.head_sha, 'head_sha'),
    'name',
    name,
  ]);
}

export function deploymentJobStreamIdentity(check) {
  if (!check || typeof check !== 'object') throw new TypeError('check must be an object');
  const provider = String(check?.app?.slug || check?.app?.id || 'unknown-app');
  if (provider !== 'github-actions') throw new Error('deployment job must be owned by GitHub Actions');
  const identity = [
    'deployment-job',
    provider,
    'workflow',
    requiredIdentityPart(check.workflow_id, 'workflow_id'),
  ];
  const headRepository = String(check.head_repository || '').trim();
  if (headRepository) identity.push('head-repository', headRepository);
  identity.push(
    'branch',
    requiredIdentityPart(check.head_branch, 'head_branch'),
    'job',
    requiredIdentityPart(check.name, 'check name'),
  );
  return joinIdentity(identity);
}

export function deploymentStreamIdentity(deployment) {
  if (!deployment || typeof deployment !== 'object') throw new TypeError('deployment must be an object');
  const explicit = String(deployment.stream_identity || '').trim();
  if (explicit) return explicit;

  // Without a check/job binding there is no safe cross-deployment recovery
  // identity. Restrict recovery to statuses on the same deployment.
  return joinIdentity([
    'deployment',
    requiredIdentityPart(deployment.deployment_id || deployment.id, 'deployment_id'),
  ]);
}

export function commitStatusStreamIdentity(status) {
  if (!status || typeof status !== 'object') throw new TypeError('status must be an object');
  if (String(status.stream_identity || '').trim()) return String(status.stream_identity).trim();
  const context = requiredIdentityPart(status.context, 'status context');
  const branch = String(status.head_branch || '').trim();
  const headRepository = String(status.head_repository || '').trim();
  if (branch) {
    const identity = ['status'];
    if (headRepository) identity.push('head-repository', headRepository);
    identity.push('branch', branch, 'context', context);
    return joinIdentity(identity);
  }
  return joinIdentity([
    'status',
    'sha',
    requiredIdentityPart(status.sha || status.head_sha, 'status sha'),
    'context',
    context,
  ]);
}

export function findSupersedingWorkflowRun(failedRun, runs) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const failedIdentity = workflowStreamIdentity(failedRun);
  const later = runs
    .filter((candidate) => workflowStreamIdentity(candidate) === failedIdentity
      && occurrenceTime(candidate) > occurrenceTime(failedRun)
      && candidate?.status === 'completed'
      && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function verifyForwardFixRecoveryPolicy({ workflow, policy, workflowSource }) {
  if (!workflow || typeof workflow !== 'object') throw new TypeError('workflow must be an object');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return null;
  const expectedWorkflowId = Number(policy.workflowId);
  const expectedPath = String(policy.path || '').trim();
  const expectedRepository = String(policy.headRepository || '').trim();
  const failedEvents = exactNonEmptyStringSet(policy.failedEvents);
  const recoveryEvents = exactNonEmptyStringSet(policy.recoveryEvents);
  const jobNames = exactNonEmptyStringSet(policy.jobNames);
  const recoveryDisplayTitles = exactNonEmptyStringSet(policy.recoveryDisplayTitles);
  const expectedSourceSha256 = String(policy.sourceSha256 || '').trim().toLowerCase();
  const sourceBytes = typeof workflowSource === 'string' ? Buffer.from(workflowSource, 'utf8') : workflowSource;
  if (!Number.isSafeInteger(expectedWorkflowId) || expectedWorkflowId < 1
    || Number(workflow.id) !== expectedWorkflowId
    || workflow.state !== 'active'
    || String(workflow.path || '') !== expectedPath
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(expectedRepository)
    || !failedEvents || !recoveryEvents || !jobNames || !recoveryDisplayTitles
    || !/^[a-f0-9]{64}$/.test(expectedSourceSha256)
    || !Buffer.isBuffer(sourceBytes)) return null;
  const actualSourceSha256 = createHash('sha256').update(sourceBytes).digest('hex');
  if (actualSourceSha256 !== expectedSourceSha256) return null;
  return Object.freeze({
    verified: true,
    workflowId: expectedWorkflowId,
    path: expectedPath,
    headRepository: expectedRepository,
    failedEvents,
    recoveryEvents,
    jobNames,
    recoveryDisplayTitles,
    sourceSha256: actualSourceSha256,
  });
}

export function findForwardFixWorkflowRun(failedRun, runs, {
  policy,
  currentHeadSha,
  defaultBranch,
  defaultCommitShas,
}) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleForwardFixOrigin(failedRun, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  const later = runs.filter((candidate) => Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.head_branch === defaultBranch
    && candidate?.head_sha === currentHeadSha
    && candidate?.head_repository?.full_name === policy.headRepository
    && policy.recoveryEvents.has(String(candidate?.event || ''))
    && policy.recoveryDisplayTitles.has(String(candidate?.display_title || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedRun)
    && candidate?.status === 'completed'
    && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findForwardFixCheck(failedCheck, checks, {
  policy,
  currentHeadSha,
  defaultBranch,
  defaultCommitShas,
}) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (String(failedCheck.app?.slug || '') !== 'github-actions'
    || !policy.jobNames.has(String(failedCheck.name || ''))
    || !isEligibleForwardFixOrigin(failedCheck, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  const later = checks.filter((candidate) => String(candidate?.app?.slug || '') === 'github-actions'
    && Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.name === failedCheck.name
    && candidate?.head_branch === defaultBranch
    && candidate?.head_sha === currentHeadSha
    && candidate?.head_repository === policy.headRepository
    && policy.recoveryEvents.has(String(candidate?.event || ''))
    && policy.recoveryDisplayTitles.has(String(candidate?.source_run_display_title || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedCheck)
    && candidate?.status === 'completed'
    && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findProvisionalForwardFixWorkflowRecovery(failedRun, runs, currentRunId, currentRunAttempt, options) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleForwardFixOrigin(failedRun, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  return runs.find((candidate) => Number(candidate?.id) === Number(currentRunId)
    && Number(candidate?.run_attempt || 1) === Number(currentRunAttempt || 1)
    && Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.head_branch === defaultBranch
    && candidate?.head_sha === currentHeadSha
    && candidate?.head_repository?.full_name === policy.headRepository
    && policy.recoveryEvents.has(String(candidate?.event || ''))
    && policy.recoveryDisplayTitles.has(String(candidate?.display_title || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedRun)
    && candidate?.status !== 'completed') || null;
}

export function findProvisionalForwardFixCheckRecovery(failedCheck, checks, currentRunId, options) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (String(failedCheck.app?.slug || '') !== 'github-actions'
    || !policy.jobNames.has(String(failedCheck.name || ''))
    || !isEligibleForwardFixOrigin(failedCheck, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  return checks.find((candidate) => Number(candidate?.source_run_id) === Number(currentRunId)
    && String(candidate?.app?.slug || '') === 'github-actions'
    && Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.name === failedCheck.name
    && candidate?.head_branch === defaultBranch
    && candidate?.head_sha === currentHeadSha
    && candidate?.head_repository === policy.headRepository
    && policy.recoveryEvents.has(String(candidate?.event || ''))
    && policy.recoveryDisplayTitles.has(String(candidate?.source_run_display_title || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedCheck)
    && candidate?.status !== 'completed') || null;
}

export function findProvisionalWorkflowRecovery(failedRun, runs, currentRunId, currentRunAttempt = 1) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const failedIdentity = workflowStreamIdentity(failedRun);
  return runs.find((candidate) => Number(candidate?.id) === Number(currentRunId)
    && Number(candidate?.run_attempt || 1) === Number(currentRunAttempt || 1)
    && workflowStreamIdentity(candidate) === failedIdentity
    && occurrenceTime(candidate) > occurrenceTime(failedRun)
    && candidate?.status !== 'completed') || null;
}

export function findSupersedingDeployment(failedDeployment, deployments) {
  if (!failedDeployment || typeof failedDeployment !== 'object') throw new TypeError('failedDeployment must be an object');
  if (!Array.isArray(deployments)) throw new TypeError('deployments must be an array');
  const failedIdentity = deploymentStreamIdentity(failedDeployment);
  const later = deployments
    .filter((candidate) => candidate?.id !== failedDeployment.id
      && deploymentStreamIdentity(candidate) === failedIdentity
      && occurrenceTime(candidate) > occurrenceTime(failedDeployment)
      && candidate?.state === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findSupersedingCheck(failedCheck, checks) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const failedIdentity = checkStreamIdentity(failedCheck);
  const later = checks
    .filter((candidate) => checkStreamIdentity(candidate) === failedIdentity
      && occurrenceTime(candidate) > occurrenceTime(failedCheck)
      && candidate?.status === 'completed'
      && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findProvisionalCheckRecovery(failedCheck, checks, currentRunId) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const failedIdentity = checkStreamIdentity(failedCheck);
  return checks.find((candidate) => Number(candidate?.source_run_id) === Number(currentRunId)
    && checkStreamIdentity(candidate) === failedIdentity
    && occurrenceTime(candidate) > occurrenceTime(failedCheck)
    && candidate?.status !== 'completed') || null;
}

export function findDeploymentCheckRecovery(failedCheck, deploymentStatuses, checks) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(deploymentStatuses)) throw new TypeError('deploymentStatuses must be an array');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  if (String(failedCheck.app?.slug || '') !== 'github-actions') return null;
  let identity;
  try {
    identity = deploymentJobStreamIdentity(failedCheck);
  } catch {
    return null;
  }
  const failedDeploymentStreams = new Set(deploymentStatuses
    .filter((status) => ['failure', 'error'].includes(String(status?.state || ''))
      && Number(status?.source_check_run_id) === Number(failedCheck.id)
      && String(status?.deployment_job_identity || '') === identity)
    .map((status) => String(status.stream_identity || ''))
    .filter(Boolean));
  if (failedDeploymentStreams.size === 0) return null;
  const successfulStatus = deploymentStatuses
    .filter((status) => status?.state === 'success'
      && status?.deployment_job_identity === identity
      && failedDeploymentStreams.has(String(status?.stream_identity || ''))
      && occurrenceTime(status) > occurrenceTime(failedCheck)
      && Number(status?.source_check_run_id) !== Number(failedCheck.id))
    .sort(compareNewestFirst)[0];
  if (!successfulStatus) return null;
  const recoveryCheck = checks.find((check) => Number(check?.id) === Number(successfulStatus.source_check_run_id));
  return recoveryCheck ? { status: successfulStatus, check: recoveryCheck } : null;
}

export function findMergedPullCheckRecovery(failedCheck, checks, pullByNumber, defaultBranch) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  if (!(pullByNumber instanceof Map)) throw new TypeError('pullByNumber must be a Map');
  const pullNumbers = [...new Set((failedCheck.pull_numbers || [])
    .map(Number)
    .filter((number) => Number.isSafeInteger(number) && number > 0))];
  if (pullNumbers.length !== 1) return null;
  const pull = pullByNumber.get(pullNumbers[0]);
  const mergedAt = Date.parse(String(pull?.merged_at || ''));
  const mergeCommitSha = String(pull?.merge_commit_sha || '');
  if (!Number.isFinite(mergedAt)
    || !/^[a-f0-9]{40}$/i.test(mergeCommitSha)
    || mergedAt <= occurrenceTime(failedCheck)) return null;
  const provider = String(failedCheck.app?.slug || failedCheck.app?.id || 'unknown-app');
  const recoveryCheck = checks
    .filter((candidate) => String(candidate?.app?.slug || candidate?.app?.id || 'unknown-app') === provider
      && candidate?.name === failedCheck.name
      && candidate?.head_sha === mergeCommitSha
      && candidate?.head_branch === defaultBranch
      && candidate?.status === 'completed'
      && candidate?.conclusion === 'success'
      && occurrenceTime(candidate) >= mergedAt)
    .sort(compareNewestFirst)[0];
  return recoveryCheck ? { pull, check: recoveryCheck } : null;
}

export function associateChecksWithPulls(checks, pulls) {
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  if (!Array.isArray(pulls)) throw new TypeError('pulls must be an array');
  return checks.map((check) => {
    const numbers = new Set(check?.pull_numbers || []);
    const branch = String(check?.head_branch || '');
    const headRepository = String(check?.head_repository || '');
    if (branch && headRepository) {
      for (const pull of pulls) {
        if (String(pull?.head?.ref || '') === branch
          && String(pull?.head?.repo?.full_name || '') === headRepository) {
          numbers.add(Number(pull.number));
        }
      }
    }
    return {
      ...check,
      pull_numbers: [...numbers]
        .filter((number) => Number.isSafeInteger(number) && number > 0)
        .sort((left, right) => left - right),
    };
  });
}

export function findSupersedingCommitStatus(failedStatus, statuses) {
  if (!failedStatus || typeof failedStatus !== 'object') throw new TypeError('failedStatus must be an object');
  if (!Array.isArray(statuses)) throw new TypeError('statuses must be an array');
  const failedIdentity = commitStatusStreamIdentity(failedStatus);
  const later = statuses
    .filter((candidate) => commitStatusStreamIdentity(candidate) === failedIdentity
      && occurrenceTime(candidate) > occurrenceTime(failedStatus)
      && candidate?.state === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function recordOccurrenceTime(record) {
  return occurrenceTime(record);
}

export function recordActivityTime(record) {
  if (!record || typeof record !== 'object') return 0;
  const timestamps = [
    record.run_started_at,
    record.started_at,
    record.created_at,
    record.updated_at,
    record.completed_at,
  ].map((value) => Date.parse(String(value || ''))).filter(Number.isFinite);
  return timestamps.length ? Math.max(...timestamps) : 0;
}

function compareOccurrence(left, right) {
  const timeDifference = occurrenceTime(left) - occurrenceTime(right);
  if (timeDifference !== 0) return timeDifference;
  return numericId(left?.id) - numericId(right?.id);
}

function validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas) {
  if (!policy || policy.verified !== true
    || !(policy.failedEvents instanceof Set)
    || !(policy.recoveryEvents instanceof Set)
    || !(policy.jobNames instanceof Set)
    || !(policy.recoveryDisplayTitles instanceof Set)) {
    throw new TypeError('forward-fix recovery policy must be verified');
  }
  if (!/^[a-f0-9]{40}$/i.test(String(currentHeadSha || ''))) {
    throw new Error('currentHeadSha must be an exact commit SHA');
  }
  if (!String(defaultBranch || '').trim()) throw new Error('defaultBranch must not be empty');
  if (!(defaultCommitShas instanceof Set)) throw new TypeError('defaultCommitShas must be a Set');
}

function isEligibleForwardFixOrigin(record, policy, currentHeadSha, defaultBranch, defaultCommitShas) {
  const failedSha = String(record?.head_sha || '');
  const headRepository = String(record?.head_repository?.full_name || record?.head_repository || '');
  return Number(record?.workflow_id) === policy.workflowId
    && record?.head_branch === defaultBranch
    && headRepository === policy.headRepository
    && policy.failedEvents.has(String(record?.event || ''))
    && /^[a-f0-9]{40}$/i.test(failedSha)
    && failedSha !== currentHeadSha
    && defaultCommitShas.has(failedSha)
    && defaultCommitShas.has(currentHeadSha);
}

function exactNonEmptyStringSet(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const normalized = value.map((item) => String(item || '').trim());
  if (normalized.some((item) => !item) || new Set(normalized).size !== normalized.length) return null;
  return new Set(normalized);
}

function compareNewestFirst(left, right) {
  const timeDifference = occurrenceTime(right) - occurrenceTime(left);
  if (timeDifference !== 0) return timeDifference;
  return numericId(right?.id) - numericId(left?.id);
}

function occurrenceTime(record) {
  const timestamp = record?.run_started_at || record?.started_at || record?.created_at || record?.updated_at || record?.completed_at;
  const parsed = Date.parse(String(timestamp || ''));
  return Number.isFinite(parsed) ? parsed : 0;
}

function requiredIdentityPart(value, name) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(name + ' must not be empty');
  return text;
}

function joinIdentity(parts) {
  return parts.map((part) => encodeURIComponent(String(part))).join(':');
}

function numericId(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : 0;
}
