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
