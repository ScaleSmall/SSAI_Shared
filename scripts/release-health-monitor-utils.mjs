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

export function githubRetryDelayMs({
  status,
  retryAfter,
  rateLimitRemaining,
  rateLimitReset,
  attempt,
  maxAttempts = 3,
  nowMs,
  jitterMs = 0,
}) {
  for (const [name, value] of [
    ['status', status],
    ['attempt', attempt],
    ['maxAttempts', maxAttempts],
    ['nowMs', nowMs],
    ['jitterMs', jitterMs],
  ]) {
    if (!Number.isFinite(value)) throw new TypeError(name + ' must be finite');
  }
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new RangeError('status must be a valid HTTP status');
  if (!Number.isSafeInteger(attempt) || attempt < 1) throw new RangeError('attempt must be a positive integer');
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new RangeError('maxAttempts must be a positive integer');
  if (nowMs < 0) throw new RangeError('nowMs must be non-negative');
  if (!Number.isSafeInteger(jitterMs) || jitterMs < 0 || jitterMs > 250) {
    throw new RangeError('jitterMs must be an integer between 0 and 250');
  }

  // A terminal attempt must surface the original HTTP failure. It must not
  // calculate a delay that cannot be used or replace that failure with a
  // retry-policy error.
  if (attempt >= maxAttempts) return null;

  const retryAfterValue = nonBlankHeaderValue(retryAfter);
  if (retryAfterValue !== null) {
    const retryAfterSeconds = Number(retryAfterValue);
    if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds >= 0) {
      return Math.max(250, retryAfterSeconds * 1000) + jitterMs;
    }
    if (/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(retryAfterValue)) {
      const retryAfterAtMs = Date.parse(retryAfterValue);
      if (Number.isFinite(retryAfterAtMs)) {
        return Math.max(250, retryAfterAtMs - nowMs) + jitterMs;
      }
    }
  }

  const remainingValue = nonBlankHeaderValue(rateLimitRemaining);
  const rateLimited = status === 429 || (status === 403 && remainingValue === '0');
  const resetValue = rateLimited ? nonBlankHeaderValue(rateLimitReset) : null;
  if (resetValue !== null) {
    const resetSeconds = Number(resetValue);
    if (Number.isFinite(resetSeconds) && resetSeconds > 0) {
      return Math.max(250, (resetSeconds * 1000) - nowMs) + jitterMs;
    }
  }

  return Math.min(10_000, (2 ** Math.max(0, attempt - 1)) * 750) + jitterMs;
}

function nonBlankHeaderValue(value) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim();
  return normalized || null;
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

export function verifyForwardFixRecoveryPolicy({
  workflow,
  policy,
  workflowSource,
  auditedOriginSources,
  monitorImplementationSource,
  currentHeadSha,
}) {
  if (!workflow || typeof workflow !== 'object') throw new TypeError('workflow must be an object');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return null;
  const expectedWorkflowId = Number(policy.workflowId);
  const expectedPath = String(policy.path || '').trim();
  const expectedRepository = String(policy.headRepository || '').trim();
  const failedEvents = exactNonEmptyStringSet(policy.failedEvents);
  const recoveryEvents = exactNonEmptyStringSet(policy.recoveryEvents);
  const jobNames = exactNonEmptyStringSet(policy.jobNames);
  const recoveryDisplayTitles = exactNonEmptyStringSet(policy.recoveryDisplayTitles);
  const monitorSelfRecoveryConfigured = policy.monitorSelfRecoveryContract !== undefined
    || policy.monitorSelfRecoveryEvents !== undefined;
  const monitorSelfRecoveryContract = String(policy.monitorSelfRecoveryContract || '').trim();
  const monitorSelfRecoveryEvents = monitorSelfRecoveryConfigured
    ? exactNonEmptyStringSet(policy.monitorSelfRecoveryEvents)
    : null;
  const auditedMonitorOrigins = verifyAuditedMonitorOrigins(policy.auditedMonitorOrigins);
  const expectedSourceSha256 = String(policy.sourceSha256 || '').trim().toLowerCase();
  const sourceBytes = normalizeSourceBytes(workflowSource);
  const normalizedCurrentHeadSha = String(currentHeadSha || '').trim().toLowerCase();
  const monitorImplementationIdentity = monitorSelfRecoveryConfigured
    ? exactMonitorImplementationIdentity(
      sourceBytes,
      monitorImplementationSource?.scriptSource,
      monitorImplementationSource?.utilsSource,
    )
    : null;
  if (!Number.isSafeInteger(expectedWorkflowId) || expectedWorkflowId < 1
    || Number(workflow.id) !== expectedWorkflowId
    || workflow.state !== 'active'
    || String(workflow.path || '') !== expectedPath
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(expectedRepository)
    || !failedEvents || !recoveryEvents || !jobNames || !recoveryDisplayTitles || !auditedMonitorOrigins
    || (monitorSelfRecoveryConfigured
      && (monitorSelfRecoveryContract !== 'release-health-monitor-v1' || !monitorSelfRecoveryEvents))
    || (!monitorSelfRecoveryConfigured && auditedMonitorOrigins.length > 0)
    || (monitorSelfRecoveryEvents
      && auditedMonitorOrigins.some((origin) => !monitorSelfRecoveryEvents.has(origin.event)))
    || (monitorSelfRecoveryConfigured
      && (!/^[a-f0-9]{40}$/.test(normalizedCurrentHeadSha) || !monitorImplementationIdentity))
    || !/^[a-f0-9]{64}$/.test(expectedSourceSha256)
    || !Buffer.isBuffer(sourceBytes)) return null;
  const actualSourceSha256 = createHash('sha256').update(sourceBytes).digest('hex');
  if (actualSourceSha256 !== expectedSourceSha256) return null;
  if (auditedMonitorOrigins.length > 0) {
    if (!(auditedOriginSources instanceof Map)) return null;
    for (const origin of auditedMonitorOrigins) {
      const sources = auditedOriginSources.get(origin.headSha);
      if (!sources || !sourceDigestMatches(sources.workflowSource, origin.workflowSourceSha256)
        || !sourceDigestMatches(sources.scriptSource, origin.scriptSourceSha256)
        || (origin.utilsSourceSha256 === null
          ? sources.utilsSource !== null
          : !sourceDigestMatches(sources.utilsSource, origin.utilsSourceSha256))) return null;
    }
  }
  return Object.freeze({
    verified: true,
    workflowId: expectedWorkflowId,
    path: expectedPath,
    headRepository: expectedRepository,
    failedEvents,
    recoveryEvents,
    jobNames,
    recoveryDisplayTitles,
    monitorSelfRecoveryContract,
    monitorSelfRecoveryEvents,
    auditedMonitorOrigins,
    monitorImplementationIdentity,
    currentMonitorHeadSha: monitorSelfRecoveryConfigured ? normalizedCurrentHeadSha : null,
    attestedMonitorHeadShas: monitorSelfRecoveryConfigured
      ? new Set([normalizedCurrentHeadSha])
      : null,
    sourceSha256: actualSourceSha256,
  });
}

export function isTrustedMonitorRecoveryPolicy(policy) {
  return policy?.verified === true
    && policy.monitorSelfRecoveryContract === 'release-health-monitor-v1'
    && policy.monitorSelfRecoveryEvents instanceof Set
    && policy.monitorSelfRecoveryEvents.size > 0
    && Array.isArray(policy.auditedMonitorOrigins)
    && /^[a-f0-9]{64}:[a-f0-9]{64}:[a-f0-9]{64}$/.test(String(policy.monitorImplementationIdentity || ''))
    && /^[a-f0-9]{40}$/.test(String(policy.currentMonitorHeadSha || ''))
    && policy.attestedMonitorHeadShas instanceof Set
    && policy.attestedMonitorHeadShas.has(policy.currentMonitorHeadSha);
}

export function attestTrustedMonitorImplementation(policy, {
  run,
  defaultBranch,
  defaultCommitShas,
  workflowSource,
  scriptSource,
  utilsSource,
}) {
  if (!isTrustedMonitorRecoveryPolicy(policy)) {
    throw new TypeError('trusted monitor recovery policy must be source-verified');
  }
  if (!isEligibleTrustedMonitorImplementationCandidate(run, policy, {
    defaultBranch,
    defaultCommitShas,
  })) return false;
  const headSha = run.head_sha;
  const normalizedHeadSha = String(headSha || '').trim().toLowerCase();
  const identity = exactMonitorImplementationIdentity(workflowSource, scriptSource, utilsSource);
  if (!/^[a-f0-9]{40}$/.test(normalizedHeadSha) || !identity
    || identity !== policy.monitorImplementationIdentity) return false;
  policy.attestedMonitorHeadShas.add(normalizedHeadSha);
  return true;
}

export function isEligibleTrustedMonitorImplementationCandidate(run, policy, {
  defaultBranch,
  defaultCommitShas,
}) {
  if (!run || typeof run !== 'object') throw new TypeError('run must be an object');
  if (!(defaultCommitShas instanceof Set)) throw new TypeError('defaultCommitShas must be a Set');
  if (!isTrustedMonitorRecoveryPolicy(policy)) return false;
  const headSha = String(run.head_sha || '').trim().toLowerCase();
  const headRepository = String(run.head_repository?.full_name || run.head_repository || '');
  return Number(run.workflow_id) === policy.workflowId
    && run.head_branch === defaultBranch
    && headRepository === policy.headRepository
    && policy.monitorSelfRecoveryEvents.has(String(run.event || ''))
    && run.status === 'completed'
    && run.conclusion === 'success'
    && parseTrustedReleaseHealthMonitorTitle(run.display_title) !== null
    && /^[a-f0-9]{40}$/.test(headSha)
    && defaultCommitShas.has(headSha);
}

export function findPolicyBoundWorkflowRecovery(failedRun, runs, policy, options) {
  return isTrustedMonitorRecoveryPolicy(policy)
    ? findTrustedMonitorWorkflowRecovery(failedRun, runs, { ...options, policy })
    : findSupersedingWorkflowRun(failedRun, runs);
}

export function findPolicyBoundProvisionalWorkflowRecovery(
  failedRun,
  runs,
  currentRunId,
  currentRunAttempt,
  policy,
  options,
) {
  return isTrustedMonitorRecoveryPolicy(policy)
    ? findProvisionalTrustedMonitorWorkflowRecovery(
      failedRun,
      runs,
      currentRunId,
      currentRunAttempt,
      { ...options, policy },
    )
    : findProvisionalWorkflowRecovery(failedRun, runs, currentRunId, currentRunAttempt);
}

export function findPolicyBoundCheckRecovery(failedCheck, checks, policy, options) {
  return isTrustedMonitorRecoveryPolicy(policy)
    ? findTrustedMonitorCheckRecovery(failedCheck, checks, { ...options, policy })
    : findSupersedingCheck(failedCheck, checks);
}

export function findPolicyBoundProvisionalCheckRecovery(
  failedCheck,
  checks,
  currentRunId,
  currentRunAttempt,
  policy,
  options,
) {
  return isTrustedMonitorRecoveryPolicy(policy)
    ? findProvisionalTrustedMonitorCheckRecovery(
      failedCheck,
      checks,
      currentRunId,
      currentRunAttempt,
      { ...options, policy },
    )
    : findProvisionalCheckRecovery(failedCheck, checks, currentRunId, currentRunAttempt);
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

export function findProvisionalForwardFixCheckRecovery(
  failedCheck,
  checks,
  currentRunId,
  currentRunAttempt,
  options,
) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (String(failedCheck.app?.slug || '') !== 'github-actions'
    || !policy.jobNames.has(String(failedCheck.name || ''))
    || !isEligibleForwardFixOrigin(failedCheck, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  return checks.find((candidate) => Number(candidate?.source_run_id) === Number(currentRunId)
    && Number(candidate?.source_run_attempt || 1) === Number(currentRunAttempt || 1)
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

export function findTrustedMonitorWorkflowRecovery(failedRun, runs, options) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleTrustedMonitorOrigin(failedRun, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  const later = runs.filter((candidate) => isTrustedMonitorWorkflowCandidate(
    candidate,
    failedRun,
    policy,
    currentHeadSha,
    defaultBranch,
    true,
  )
    && candidate?.status === 'completed'
    && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findProvisionalTrustedMonitorWorkflowRecovery(
  failedRun,
  runs,
  currentRunId,
  currentRunAttempt,
  options,
) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleTrustedMonitorOrigin(failedRun, policy, currentHeadSha, defaultBranch, defaultCommitShas)) return null;
  return runs.find((candidate) => Number(candidate?.id) === Number(currentRunId)
    && Number(candidate?.run_attempt || 1) === Number(currentRunAttempt || 1)
    && isTrustedMonitorWorkflowCandidate(
      candidate,
      failedRun,
      policy,
      currentHeadSha,
      defaultBranch,
    )
    && candidate?.status === 'in_progress') || null;
}

export function findTrustedMonitorCheckRecovery(failedCheck, checks, options) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleTrustedMonitorCheckOrigin(
    failedCheck,
    policy,
    currentHeadSha,
    defaultBranch,
    defaultCommitShas,
  )) return null;
  const later = checks.filter((candidate) => isTrustedMonitorCheckCandidate(
    candidate,
    failedCheck,
    policy,
    currentHeadSha,
    defaultBranch,
    true,
  )
    && candidate?.status === 'completed'
    && candidate?.conclusion === 'success')
    .sort(compareNewestFirst)[0];
  return later || null;
}

export function findProvisionalTrustedMonitorCheckRecovery(
  failedCheck,
  checks,
  currentRunId,
  currentRunAttempt,
  options,
) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleTrustedMonitorCheckOrigin(
    failedCheck,
    policy,
    currentHeadSha,
    defaultBranch,
    defaultCommitShas,
  )) return null;
  return checks.find((candidate) => Number(candidate?.source_run_id) === Number(currentRunId)
    && Number(candidate?.source_run_attempt || 1) === Number(currentRunAttempt || 1)
    && isTrustedMonitorCheckCandidate(
      candidate,
      failedCheck,
      policy,
      currentHeadSha,
      defaultBranch,
    )
    && candidate?.status === 'in_progress') || null;
}

export function findProvisionalTrustedMonitorCheckRecoveryFromRun(
  failedCheck,
  runs,
  currentRunId,
  currentRunAttempt,
  options,
) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  const { policy, currentHeadSha, defaultBranch, defaultCommitShas } = options;
  validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isEligibleTrustedMonitorCheckOrigin(
    failedCheck,
    policy,
    currentHeadSha,
    defaultBranch,
    defaultCommitShas,
  )) return null;
  return runs.find((candidate) => Number(candidate?.id) === Number(currentRunId)
    && Number(candidate?.run_attempt || 1) === Number(currentRunAttempt || 1)
    && isTrustedMonitorWorkflowCandidate(
      candidate,
      failedCheck,
      policy,
      currentHeadSha,
      defaultBranch,
    )
    && candidate?.status === 'in_progress') || null;
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

export function findProvisionalCheckRecovery(failedCheck, checks, currentRunId, currentRunAttempt = 1) {
  if (!failedCheck || typeof failedCheck !== 'object') throw new TypeError('failedCheck must be an object');
  if (!Array.isArray(checks)) throw new TypeError('checks must be an array');
  const failedIdentity = checkStreamIdentity(failedCheck);
  return checks.find((candidate) => Number(candidate?.source_run_id) === Number(currentRunId)
    && Number(candidate?.source_run_attempt || 1) === Number(currentRunAttempt || 1)
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

export function associateWorkflowRunsWithPulls(runs, pullCommits) {
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  if (!Array.isArray(pullCommits)) throw new TypeError('pullCommits must be an array');

  const associationsBySha = new Map();
  for (const commit of pullCommits) {
    const sha = String(commit?.sha || '').toLowerCase();
    const pullNumber = Number(commit?._pull_number);
    const branch = String(commit?._branch || '');
    const headRepository = String(commit?._head_repository || '');
    if (!/^[a-f0-9]{40}$/.test(sha)
      || !Number.isSafeInteger(pullNumber)
      || pullNumber <= 0
      || !branch
      || !headRepository) continue;
    const associations = associationsBySha.get(sha) || [];
    associations.push({ pullNumber, branch, headRepository });
    associationsBySha.set(sha, associations);
  }

  return runs.map((run) => {
    const sha = String(run?.head_sha || '').toLowerCase();
    const branch = String(run?.head_branch || '');
    const headRepository = String(run?.head_repository?.full_name || run?.head_repository || '');
    const pullNumbers = new Set((run?.pull_requests || [])
      .map((pull) => Number(pull?.number))
      .filter((number) => Number.isSafeInteger(number) && number > 0));
    for (const association of associationsBySha.get(sha) || []) {
      if (association.branch === branch && association.headRepository === headRepository) {
        pullNumbers.add(association.pullNumber);
      }
    }
    return { ...run, pull_numbers: [...pullNumbers].sort((left, right) => left - right) };
  });
}

export function findMergedPullWorkflowRecovery(failedRun, runs, pullByNumber, defaultBranch, defaultCommitShas) {
  if (!failedRun || typeof failedRun !== 'object') throw new TypeError('failedRun must be an object');
  if (!Array.isArray(runs)) throw new TypeError('runs must be an array');
  if (!(pullByNumber instanceof Map)) throw new TypeError('pullByNumber must be a Map');
  if (!(defaultCommitShas instanceof Set)) throw new TypeError('defaultCommitShas must be a Set');
  const branch = String(defaultBranch || '').trim();
  if (!branch) throw new Error('defaultBranch must not be empty');
  const workflowId = Number(failedRun.workflow_id);
  const failedEvent = String(failedRun.event || '');
  if (!Number.isSafeInteger(workflowId)
    || workflowId <= 0
    || !['push', 'pull_request'].includes(failedEvent)
    || String(failedRun.head_branch || '') === branch) return null;

  const pullNumbers = [...new Set((failedRun.pull_numbers || [])
    .map(Number)
    .filter((number) => Number.isSafeInteger(number) && number > 0))];
  if (pullNumbers.length !== 1) return null;
  const pull = pullByNumber.get(pullNumbers[0]);
  const mergedAt = Date.parse(String(pull?.merged_at || ''));
  const mergeCommitSha = String(pull?.merge_commit_sha || '').toLowerCase();
  const failedRepository = String(failedRun.head_repository?.full_name || failedRun.head_repository || '');
  const pullHeadRepository = String(pull?.head?.repo?.full_name || '');
  const pullHeadBranch = String(pull?.head?.ref || '');
  const baseRepository = String(pull?.base?.repo?.full_name || '');
  if (!Number.isFinite(mergedAt)
    || !/^[a-f0-9]{40}$/.test(mergeCommitSha)
    || !defaultCommitShas.has(mergeCommitSha)
    || mergedAt <= occurrenceTime(failedRun)
    || pullHeadRepository !== failedRepository
    || pullHeadBranch !== String(failedRun.head_branch || '')
    || !baseRepository) return null;

  const recoveryRun = runs
    .filter((candidate) => Number(candidate?.workflow_id) === workflowId
      && String(candidate?.head_repository?.full_name || candidate?.head_repository || '') === baseRepository
      && String(candidate?.head_sha || '').toLowerCase() === mergeCommitSha
      && candidate?.head_branch === branch
      && candidate?.event === 'push'
      && candidate?.status === 'completed'
      && candidate?.conclusion === 'success'
      && occurrenceTime(candidate) >= mergedAt)
    .sort(compareNewestFirst)[0];
  return recoveryRun ? { pull, run: recoveryRun } : null;
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

function validateTrustedMonitorSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas) {
  validateForwardFixSearch(policy, currentHeadSha, defaultBranch, defaultCommitShas);
  if (!isTrustedMonitorRecoveryPolicy(policy)) {
    throw new TypeError('trusted monitor recovery policy must be source-verified');
  }
  if (String(currentHeadSha || '').toLowerCase() !== policy.currentMonitorHeadSha) {
    throw new Error('currentHeadSha must match the source-verified trusted monitor implementation');
  }
}

function isEligibleTrustedMonitorOrigin(record, policy, currentHeadSha, defaultBranch, defaultCommitShas) {
  const failedSha = String(record?.head_sha || '');
  const headRepository = String(record?.head_repository?.full_name || record?.head_repository || '');
  return Number(record?.workflow_id) === policy.workflowId
    && record?.head_branch === defaultBranch
    && headRepository === policy.headRepository
    && policy.monitorSelfRecoveryEvents.has(String(record?.event || ''))
    && trustedMonitorOriginCoverage(record, policy) !== null
    && /^[a-f0-9]{40}$/i.test(failedSha)
    && defaultCommitShas.has(failedSha)
    && defaultCommitShas.has(currentHeadSha);
}

function isEligibleTrustedMonitorCheckOrigin(
  record,
  policy,
  currentHeadSha,
  defaultBranch,
  defaultCommitShas,
) {
  return String(record?.app?.slug || '') === 'github-actions'
    && policy.jobNames.has(String(record?.name || ''))
    && isEligibleTrustedMonitorOrigin(record, policy, currentHeadSha, defaultBranch, defaultCommitShas);
}

function isTrustedMonitorWorkflowCandidateIdentity(
  candidate,
  failedRun,
  policy,
  currentHeadSha,
  defaultBranch,
  allowAttestedAncestor,
) {
  const candidateHeadSha = String(candidate?.head_sha || '').toLowerCase();
  const sourceIsAttested = candidateHeadSha === String(currentHeadSha || '').toLowerCase()
    || (allowAttestedAncestor === true && policy.attestedMonitorHeadShas.has(candidateHeadSha));
  return Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.head_branch === defaultBranch
    && sourceIsAttested
    && candidate?.head_repository?.full_name === policy.headRepository
    && policy.monitorSelfRecoveryEvents.has(String(candidate?.event || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedRun);
}

function isTrustedMonitorWorkflowCandidate(
  candidate,
  failedRun,
  policy,
  currentHeadSha,
  defaultBranch,
  allowAttestedAncestor = false,
) {
  return isTrustedMonitorWorkflowCandidateIdentity(
    candidate,
    failedRun,
    policy,
    currentHeadSha,
    defaultBranch,
    allowAttestedAncestor,
  ) && trustedMonitorNominalCoverageDominates(
    candidate,
    trustedMonitorOriginCoverage(failedRun, policy),
  );
}

function isTrustedMonitorCheckCandidateIdentity(
  candidate,
  failedCheck,
  policy,
  currentHeadSha,
  defaultBranch,
  allowAttestedAncestor,
) {
  const candidateHeadSha = String(candidate?.head_sha || '').toLowerCase();
  const sourceIsAttested = candidateHeadSha === String(currentHeadSha || '').toLowerCase()
    || (allowAttestedAncestor === true && policy.attestedMonitorHeadShas.has(candidateHeadSha));
  return String(candidate?.app?.slug || '') === 'github-actions'
    && Number(candidate?.workflow_id) === policy.workflowId
    && candidate?.name === failedCheck.name
    && candidate?.head_branch === defaultBranch
    && sourceIsAttested
    && candidate?.head_repository === policy.headRepository
    && policy.monitorSelfRecoveryEvents.has(String(candidate?.event || ''))
    && occurrenceTime(candidate) > occurrenceTime(failedCheck);
}

function isTrustedMonitorCheckCandidate(
  candidate,
  failedCheck,
  policy,
  currentHeadSha,
  defaultBranch,
  allowAttestedAncestor = false,
) {
  return isTrustedMonitorCheckCandidateIdentity(
    candidate,
    failedCheck,
    policy,
    currentHeadSha,
    defaultBranch,
    allowAttestedAncestor,
  ) && trustedMonitorNominalCoverageDominates(
    candidate,
    trustedMonitorOriginCoverage(failedCheck, policy),
  );
}

function trustedMonitorNominalCoverageDominates(candidateRecord, failedCoverage) {
  // Every exact source-verified monitor run independently re-evaluates each
  // failure inside its requested lookback. Nominal dominance is therefore the
  // durable recovery contract: an underlying failure still relevant to the
  // newer window is rediscovered directly, while shifted equal-width monitor
  // failures cannot deadlock later scheduled scans. Ordinary workflow/check
  // recovery remains on its separate, unchanged stream selectors.
  const candidate = parseTrustedReleaseHealthMonitorTitle(
    candidateRecord?.source_run_display_title || candidateRecord?.display_title,
  );
  const failed = failedCoverage && typeof failedCoverage === 'object'
    ? failedCoverage
    : parseTrustedReleaseHealthMonitorTitle(failedCoverage);
  if (!candidate || !failed || candidate.hours < failed.hours) return false;
  return failed.mode !== 'incident' || candidate.mode === 'incident';
}

function trustedMonitorOriginCoverage(record, policy) {
  const runId = Number(record?.source_run_id ?? record?.id);
  const runAttempt = Number(record?.source_run_attempt ?? record?.run_attempt ?? 1);
  const headSha = String(record?.head_sha || '').toLowerCase();
  const event = String(record?.event || '');
  const displayTitle = String(record?.source_run_display_title || record?.display_title || '');
  const isCheckRun = record?.source_run_id !== undefined;
  const audited = policy.auditedMonitorOrigins.find((candidate) => candidate.runId === runId
    && candidate.runAttempt === runAttempt
    && (!isCheckRun || candidate.checkRunId === Number(record?.id))
    && candidate.headSha === headSha
    && candidate.event === event
    && candidate.displayTitle === displayTitle);
  if (audited) {
    return {
      mode: audited.coverageMode,
      hours: audited.coverageHours,
      startedAtMs: audited.coverageStartedAtMs
        ?? occurrenceTime(record) - (audited.coverageHours * 60 * 60_000),
    };
  }
  const modern = parseTrustedReleaseHealthMonitorTitle(
    record?.source_run_display_title || record?.display_title,
  );
  if (!modern) return null;
  return {
    ...modern,
    startedAtMs: occurrenceTime(record) - (modern.hours * 60 * 60_000),
  };
}

function parseTrustedReleaseHealthMonitorTitle(value) {
  const match = /^Release health monitor \[(continuous|incident):([1-9]\d{0,2})h\]$/.exec(String(value || ''));
  if (!match) return null;
  const hours = Number(match[2]);
  if (match[1] === 'continuous' ? hours > 6 : hours > 168) return null;
  return { mode: match[1], hours };
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

function verifyAuditedMonitorOrigins(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > 100) return null;
  const seen = new Set();
  const verified = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const runId = Number(item.runId);
    const runAttempt = Number(item.runAttempt);
    const checkRunId = Number(item.checkRunId);
    const headSha = String(item.headSha || '').trim().toLowerCase();
    const event = String(item.event || '').trim();
    const displayTitle = String(item.displayTitle || '').trim();
    const coverageMode = String(item.coverageMode || '').trim();
    const coverageHours = Number(item.coverageHours);
    const coverageStartedAt = item.coverageStartedAt === undefined
      ? ''
      : String(item.coverageStartedAt || '').trim();
    const coverageStartedAtMs = coverageStartedAt ? Date.parse(coverageStartedAt) : null;
    const workflowSourceSha256 = String(item.workflowSourceSha256 || '').trim().toLowerCase();
    const scriptSourceSha256 = String(item.scriptSourceSha256 || '').trim().toLowerCase();
    const utilsSourceSha256 = item.utilsSourceSha256 === null
      ? null
      : String(item.utilsSourceSha256 || '').trim().toLowerCase();
    const identity = runId + ':' + runAttempt;
    if (!Number.isSafeInteger(runId) || runId < 1
      || !Number.isSafeInteger(runAttempt) || runAttempt < 1 || runAttempt > 100
      || !Number.isSafeInteger(checkRunId) || checkRunId < 1
      || !/^[a-f0-9]{40}$/.test(headSha)
      || !event
      || (displayTitle !== 'Scale Small AI Release Health Monitor'
        && parseTrustedReleaseHealthMonitorTitle(displayTitle) === null)
      || !['continuous', 'incident'].includes(coverageMode)
      || !Number.isSafeInteger(coverageHours) || coverageHours < 1
      || (coverageMode === 'continuous' ? coverageHours > 6 : coverageHours > 168)
      || (coverageStartedAt && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(coverageStartedAt)
        || !Number.isFinite(coverageStartedAtMs)))
      || !/^[a-f0-9]{64}$/.test(workflowSourceSha256)
      || !/^[a-f0-9]{64}$/.test(scriptSourceSha256)
      || (utilsSourceSha256 !== null && !/^[a-f0-9]{64}$/.test(utilsSourceSha256))
      || seen.has(identity)) return null;
    seen.add(identity);
    verified.push(Object.freeze({
      runId,
      runAttempt,
      checkRunId,
      headSha,
      event,
      displayTitle,
      coverageMode,
      coverageHours,
      coverageStartedAt,
      coverageStartedAtMs,
      workflowSourceSha256,
      scriptSourceSha256,
      utilsSourceSha256,
    }));
  }
  return Object.freeze(verified);
}

function sourceDigestMatches(source, expectedSha256) {
  return Buffer.isBuffer(source)
    && createHash('sha256').update(source).digest('hex') === expectedSha256;
}

function normalizeSourceBytes(source) {
  if (Buffer.isBuffer(source)) return source;
  return typeof source === 'string' ? Buffer.from(source, 'utf8') : null;
}

function exactMonitorImplementationIdentity(workflowSource, scriptSource, utilsSource) {
  const sources = [workflowSource, scriptSource, utilsSource].map(normalizeSourceBytes);
  if (sources.some((source) => !source)) return null;
  return sources.map((source) => createHash('sha256').update(source).digest('hex')).join(':');
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
