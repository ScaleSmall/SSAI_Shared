import { githubApi, installationToken } from './github-app.mjs';
import { dispatchWorkflowOnce } from './github-api.mjs';
import { encodeEnvelope, signEnvelope } from './envelope.mjs';
import { verifyActivationProfileEnvironment } from './activation-profile.mjs';
import { deliverSignedAlert, prepareAlert } from './alerts.mjs';

export const slotMinutes = Object.freeze([1, 16, 31, 46]);
export const nativeMinutes = Object.freeze([9, 24, 39, 54]);
export const outstandingStatuses = Object.freeze(['queued', 'requested', 'waiting', 'pending', 'in_progress']);

const nativePath = '.github/workflows/release-health-monitor.yml';
const canaryPath = '.github/workflows/release-health-monitor-v3.yml';
const fallbackPath = '.github/workflows/release-health-monitor-fallback.yml';
const providerStatuses = new Set(['queued', 'requested', 'waiting', 'pending', 'in_progress', 'completed']);

export function currentLogicalSlot(nowMs) {
  const date = new Date(nowMs);
  let minute = [...slotMinutes].reverse().find((value) => value <= date.getUTCMinutes());
  if (minute === undefined) {
    date.setUTCHours(date.getUTCHours() - 1);
    minute = 46;
  }
  date.setUTCMinutes(minute, 0, 0);
  return Math.floor(date.getTime() / 60_000);
}

export function evaluationWindow(actualMs, slot, scheduledMs = actualMs) {
  const actualAge = Math.floor(actualMs / 60_000) - slot;
  const scheduledAge = Math.floor(scheduledMs / 60_000) - slot;
  const scheduled = new Date(scheduledMs);
  return Object.freeze({
    age: actualAge,
    eligible: scheduled.getUTCSeconds() === 0
      && scheduledAge >= 10 && scheduledAge < 15
      && actualAge >= 10 && actualAge < 15,
  });
}

export function normalizeProviderPath(value) {
  return String(value ?? '').replace(/@(?:main|refs\/heads\/main)$/, '');
}

export function validateTargetRun(run, workflowId, workflowPath, event = 'schedule') {
  const id = Number(run?.id);
  if (
    !run || !Number.isSafeInteger(id) || id < 1
    || Number(run.workflow_id) !== workflowId
    || normalizeProviderPath(run.path) !== workflowPath
    || run.event !== event
    || Number(run.repository?.id) !== 1183552904
    || run.repository?.full_name !== 'ScaleSmall/SSAI_Shared'
    || run.head_branch !== 'main'
    || !/^[a-f0-9]{40}$/.test(String(run.head_sha ?? ''))
    || !Number.isSafeInteger(Number(run.run_attempt)) || Number(run.run_attempt) < 1
    || !Number.isFinite(Date.parse(run.created_at))
    || !providerStatuses.has(run.status)
    || run.url !== `https://api.github.com/repos/ScaleSmall/SSAI_Shared/actions/runs/${id}`
    || run.html_url !== `https://github.com/ScaleSmall/SSAI_Shared/actions/runs/${id}`
  ) throw new Error('Target workflow evidence is malformed.');
  if (workflowId === 344170407 && Number(run.run_attempt) !== 1) {
    throw new Error('Fallback attempt is malformed.');
  }
  return run;
}

export function exactNativeBlocker(runs, slot) {
  const start = slot * 60_000;
  const end = (slot + 15) * 60_000;
  return runs.filter((run) => {
    const workflowId = Number(run.workflow_id);
    const workflowPath = workflowId === 315630665
      ? nativePath
      : workflowId === 344135917 ? canaryPath : null;
    if (!workflowPath) return false;
    validateTargetRun(run, workflowId, workflowPath);
    const created = Date.parse(run.created_at);
    return created >= start && created < end;
  });
}

export function twoConsecutiveCanarySlots(runs, slot) {
  return [slot - 15, slot].every((candidate) => (
    exactNativeBlocker(runs, candidate).some((run) => Number(run.workflow_id) === 344135917)
  ));
}

export function sanitizedAudit(previous, event) {
  const serialized = JSON.stringify(event);
  if (/token|signature|private.?key|hmac|authorization/i.test(serialized)) {
    throw new Error('Unsafe controller audit event.');
  }
  return Object.freeze({ ...event, previous_hash: previous || '0'.repeat(64) });
}

export function classifyFailure(error, fallback = 'internal') {
  if (['transport', 'rate-limit', 'provider-evidence', 'configuration', 'prepared-expired'].includes(error?.failureClass)) {
    return error.failureClass;
  }
  if (['AbortError', 'TimeoutError'].includes(error?.name)) return 'transport';
  return fallback;
}

function statusOf(error) {
  return Number.isSafeInteger(error?.status) && error.status >= 0 && error.status <= 599
    ? error.status
    : null;
}

function validateAuth(value, mode, nowEpochSecond) {
  if (
    !value || value.permissionMode !== mode
    || typeof value.token !== 'string' || value.token.length < 8 || value.token.length > 4096
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt < nowEpochSecond + 300
    || value.expiresAt > nowEpochSecond + 3_700
  ) throw Object.assign(new Error('Installation token evidence is invalid.'), { failureClass: 'configuration' });
  return value.token;
}

async function workflowRuns(fetchImpl, token, workflowId, event = 'schedule', requestOptions = {}) {
  const payload = await githubApi(
    fetchImpl,
    `/repos/ScaleSmall/SSAI_Shared/actions/workflows/${workflowId}/runs?event=${event}&branch=main&per_page=100`,
    token,
    requestOptions,
  );
  const workflowPath = workflowId === 315630665
    ? nativePath
    : workflowId === 344135917 ? canaryPath : fallbackPath;
  return payload.workflow_runs.map((run) => validateTargetRun(run, workflowId, workflowPath, event));
}

function receiptFromRun(run) {
  return Object.freeze({ workflow_run_id: Number(run.id), run_url: run.url, html_url: run.html_url });
}

function requestRun(runs, item) {
  const exactTitle = `Release health independent fallback [slot:${item.slot} request:${item.request_id}]`;
  const start = (item.slot + 10) * 60_000;
  const end = (item.slot + 15) * 60_000;
  return runs.find((run) => (
    run.display_title === exactTitle
    && run.head_sha === item.expected_sha
    && Date.parse(run.created_at) >= start
    && Date.parse(run.created_at) < end
  )) || null;
}

async function durableFailureAlert(payload) {
  return prepareAlert(payload);
}

async function abandonUnattempted({ ledger, slot, phase, nowMs, failureClass }) {
  const decision = phase === 'prepared' ? 'prepared-abandoned' : 'lease-abandoned';
  const alert = await durableFailureAlert({
    slot,
    failure_class: failureClass,
    status: null,
    phase: 'terminal',
    decision,
  });
  return ledger.abandonUnattempted(slot, phase, nowMs, failureClass, alert);
}

async function flushAlertOutbox({ env, ledger, fetchImpl, nowMs, timeoutSignal }) {
  if (env.MODE !== 'active') return Object.freeze({ attempted: 0, delivered: 0 });
  const records = await ledger.claimAlerts(nowMs, 3);
  let delivered = 0;
  for (const record of records) {
    try {
      const result = await deliverSignedAlert(record, {
        sink: env.ALERT_SINK_URL,
        keyBase64: env.ALERT_SIGNING_KEY,
        fetchImpl,
        timeoutSignal,
      });
      await ledger.acknowledgeAlert(record.alert_id, result.status, nowMs);
      delivered += 1;
    } catch (error) {
      await ledger.rejectAlert(
        record.alert_id,
        statusOf(error),
        ['AbortError', 'TimeoutError'].includes(error?.name) ? 'transport' : 'provider-evidence',
        nowMs,
      );
    }
  }
  return Object.freeze({ attempted: records.length, delivered });
}

async function reconcilePending({
  env,
  ledger,
  fetchImpl,
  token,
  nowMs,
  requestOptions,
}) {
  const pending = await ledger.listReconcileable(nowMs, 4);
  if (!pending.length) return Object.freeze({ checked: 0, confirmed: 0 });
  let runs = null;
  let readFailure = null;
  try {
    runs = await workflowRuns(fetchImpl, token, 344170407, 'workflow_dispatch', requestOptions);
  } catch (error) {
    readFailure = error;
  }
  let confirmed = 0;
  for (const item of pending) {
    const run = runs ? requestRun(runs, item) : null;
    if (run) {
      await ledger.confirmDispatch(
        item.slot,
        item.source_digest,
        item.profile_digest,
        receiptFromRun(run),
        'dispatch-reconciled',
        nowMs,
      );
      await ledger.terminalizeConfirmed(
        item.slot, item.source_digest, item.profile_digest, 'dispatch-reconciled', nowMs,
      );
      confirmed += 1;
      continue;
    }
    const failureClass = readFailure ? classifyFailure(readFailure) : 'dispatch-unknown';
    const unknownAlert = await durableFailureAlert({
      slot: item.slot,
      failure_class: failureClass === 'dispatch-unknown' ? 'dispatch-unknown' : failureClass,
      status: statusOf(readFailure),
      phase: 'unknown',
      decision: 'dispatch-unknown',
      request_id: item.request_id,
    });
    const circuitAlert = await durableFailureAlert({
      slot: item.slot,
      failure_class: 'circuit-open',
      status: null,
      phase: 'unknown',
      decision: 'circuit-open',
      request_id: item.request_id,
    });
    await ledger.markUnknown(
      item.slot,
      item.source_digest,
      item.profile_digest,
      { failure_class: failureClass, status: statusOf(readFailure) },
      nowMs,
      unknownAlert,
      circuitAlert,
    );
  }
  return Object.freeze({ checked: pending.length, confirmed });
}

function makeEnvelope(slot, expectedSha, nowMs, randomUUID) {
  const issued = Math.floor(nowMs / 1000);
  const envelope = Object.freeze({
    version: 'ssai-release-health-fallback-v1',
    repository: 'ScaleSmall/SSAI_Shared',
    repository_id: '1183552904',
    workflow_id: '344170407',
    workflow_path: fallbackPath,
    ref: 'refs/heads/main',
    expected_sha: expectedSha,
    slot_epoch_minute: String(slot),
    request_id: randomUUID().replaceAll('-', ''),
    issued_at_epoch_second: String(issued),
    expires_at_epoch_second: String(issued + 300),
  });
  if (!/^[a-f0-9]{32}$/.test(envelope.request_id)) throw new Error('Request ID source is invalid.');
  return envelope;
}

async function persistFailure({ env, ledger, slot, sourceDigest, profileDigest, error, nowMs }) {
  const failureClass = classifyFailure(error, env.MODE === 'active' ? 'internal' : 'configuration');
  const result = Object.freeze({ decision: 'failed-closed', failure_class: failureClass });
  const alert = await durableFailureAlert({
    slot,
    failure_class: failureClass,
    status: statusOf(error),
    phase: 'terminal',
    decision: 'failed-closed',
  }).catch(() => null);
  await ledger.recordFailureTerminal(slot, sourceDigest, profileDigest, result, nowMs, alert);
  return result;
}

export async function evaluateSlot({
  env,
  fetchImpl = fetch,
  scheduledTime = Date.now(),
  nowMs = Date.now(),
  ledger,
  authProvider = installationToken,
  randomUUID = () => crypto.randomUUID(),
  timeoutSignal = () => AbortSignal.timeout(10_000),
  requestOptions = {},
}) {
  if (!['observe', 'active'].includes(env.MODE)) throw new Error('Unknown controller mode.');
  if (!Number.isSafeInteger(scheduledTime) || !Number.isSafeInteger(nowMs)) {
    throw new Error('Controller evaluation time is invalid.');
  }
  const profileDigest = await verifyActivationProfileEnvironment(env);
  const sourceDigest = env.CONTROLLER_SOURCE_SHA256;
  const slot = currentLogicalSlot(scheduledTime);
  const nowEpochSecond = Math.floor(nowMs / 1000);
  let readToken = null;
  const getReadToken = async () => {
    if (readToken) return readToken;
    const auth = await authProvider(fetchImpl, env, nowEpochSecond, 'read', requestOptions);
    readToken = validateAuth(auth, 'read', nowEpochSecond);
    return readToken;
  };

  try {
    await flushAlertOutbox({ env, ledger, fetchImpl, nowMs, timeoutSignal });
    const recoverable = await ledger.listReconcileable(nowMs, 4);
    if (recoverable.length) {
      await reconcilePending({
        env,
        ledger,
        fetchImpl,
        token: await getReadToken(),
        nowMs,
        requestOptions,
      });
      await flushAlertOutbox({ env, ledger, fetchImpl, nowMs, timeoutSignal });
    }
    const unattempted = await ledger.listUnattempted(4);
    let abandoned = null;
    for (const item of unattempted) {
      if (item.slot < slot) {
        abandoned = await abandonUnattempted({
          ledger,
          slot: item.slot,
          phase: item.phase,
          nowMs,
          failureClass: item.phase === 'prepared' ? 'prepared-expired' : 'configuration',
        }) || abandoned;
      }
    }
    if (abandoned) return abandoned;
    if (!evaluationWindow(nowMs, slot, scheduledTime).eligible) return Object.freeze({ decision: 'outside-window' });

    let durable = await ledger.getSlot(slot, sourceDigest, profileDigest);
    if (durable?.decision === 'digest-mismatch') {
      const current = unattempted.find((item) => item.slot === slot);
      const mismatched = current ? await abandonUnattempted({
        ledger, slot, phase: current.phase, nowMs, failureClass: 'configuration',
      }) : null;
      return mismatched || durable;
    }
    if (durable?.phase === 'terminal') return durable.result;
    if (durable?.phase === 'confirmed') {
      return await ledger.terminalizeConfirmed(
        slot,
        sourceDigest,
        profileDigest,
        durable.result.terminal_decision,
        nowMs,
      );
    }
    if (['post-attempted', 'unknown'].includes(durable?.phase)) {
      return durable.result?.decision ? durable.result : Object.freeze({ decision: 'dispatch-unknown' });
    }
    if (!durable) {
      const leased = await ledger.lease(slot, sourceDigest, profileDigest, nowMs);
      if (!leased) return Object.freeze({ decision: 'claimed' });
      durable = await ledger.getSlot(slot, sourceDigest, profileDigest);
    }

    const token = await getReadToken();
    const mainBefore = await githubApi(
      fetchImpl,
      '/repos/ScaleSmall/SSAI_Shared/commits/main',
      token,
      requestOptions,
    );
    const native = await workflowRuns(fetchImpl, token, 315630665, 'schedule', requestOptions);
    const canary = await workflowRuns(fetchImpl, token, 344135917, 'schedule', requestOptions);
    const blockers = exactNativeBlocker([...native, ...canary], slot);
    const standby = twoConsecutiveCanarySlots(canary, slot);
    const standbyTransition = await ledger.updateStandby(
      sourceDigest,
      profileDigest,
      standby,
      slot,
      nowMs,
    );
    if (standby) {
      return await ledger.recordNoDispatch(
        slot,
        sourceDigest,
        profileDigest,
        { decision: 'standby', transition: standbyTransition.outcome },
        nowMs,
      );
    }
    if (blockers.length) {
      return await ledger.recordNoDispatch(
        slot,
        sourceDigest,
        profileDigest,
        { decision: 'native-blocked', count: blockers.length },
        nowMs,
      );
    }

    const finalNative = [
      ...await workflowRuns(fetchImpl, token, 315630665, 'schedule', requestOptions),
      ...await workflowRuns(fetchImpl, token, 344135917, 'schedule', requestOptions),
    ];
    if (exactNativeBlocker(finalNative, slot).length) {
      return await ledger.recordNoDispatch(
        slot,
        sourceDigest,
        profileDigest,
        { decision: 'native-blocked-final' },
        nowMs,
      );
    }
    const main = await githubApi(
      fetchImpl,
      '/repos/ScaleSmall/SSAI_Shared/commits/main',
      token,
      requestOptions,
    );
    if (mainBefore.sha !== main.sha) {
      throw Object.assign(new Error('Main SHA changed during evaluation.'), { failureClass: 'provider-evidence' });
    }
    const fallbackInventory = await workflowRuns(
      fetchImpl,
      token,
      344170407,
      'workflow_dispatch',
      requestOptions,
    );
    const outstanding = fallbackInventory.find((run) => outstandingStatuses.includes(run.status));
    if (outstanding) {
      return await ledger.recordNoDispatch(
        slot,
        sourceDigest,
        profileDigest,
        { decision: 'outstanding', status: outstanding.status },
        nowMs,
      );
    }

    durable = await ledger.getSlot(slot, sourceDigest, profileDigest);
    if (durable.phase === 'leased') {
      const envelope = makeEnvelope(slot, main.sha, nowMs, randomUUID);
      if (!await ledger.prepareDispatch(slot, sourceDigest, profileDigest, {
        request_id: envelope.request_id,
        expected_sha: envelope.expected_sha,
        expires_at_epoch_second: Number(envelope.expires_at_epoch_second),
        envelope,
      }, nowMs)) throw new Error('Prepared transition was lost.');
      durable = await ledger.getSlot(slot, sourceDigest, profileDigest);
    }

    if (env.MODE === 'observe') {
      return await ledger.recordObserve(
        slot,
        sourceDigest,
        profileDigest,
        { decision: 'would_dispatch', request_id: durable.request_id, sha: durable.expected_sha },
        nowMs,
      );
    }
    if (durable.expires_at_epoch_second <= nowEpochSecond) {
      return abandonUnattempted({
        ledger, slot, phase: 'prepared', nowMs, failureClass: 'prepared-expired',
      });
    }
    if (
      !env.ALERT_SIGNING_KEY || env.ALERT_SINK_URL !== 'https://alerts.scalesmall.ai/release-health-alert'
      || !await ledger.activationReady(sourceDigest, profileDigest, env.ACTIVATION_PROOF)
    ) {
      const error = Object.assign(new Error('Active mode interlock is not satisfied.'), { failureClass: 'configuration' });
      return persistFailure({ env, ledger, slot, sourceDigest, profileDigest, error, nowMs });
    }

    const permit = await ledger.consumePostPermit(
      slot,
      sourceDigest,
      profileDigest,
      env.ACTIVATION_PROOF,
      nowEpochSecond,
      nowMs,
    );
    if (!permit.permit) {
      if (permit.outcome === 'circuit-open' || permit.outcome === 'circuit-half-open-busy') {
        return await ledger.recordNoDispatch(
          slot,
          sourceDigest,
          profileDigest,
          { decision: 'circuit-open', reopen_at_slot: permit.reopen_at_slot ?? null },
          nowMs,
        );
      }
      const error = Object.assign(new Error('Post permit was denied.'), {
        failureClass: permit.outcome === 'prepared-expired' ? 'prepared-expired' : 'configuration',
      });
      return persistFailure({ env, ledger, slot, sourceDigest, profileDigest, error, nowMs });
    }

    const writeAuth = await authProvider(fetchImpl, env, nowEpochSecond, 'write', requestOptions);
    const writeToken = validateAuth(writeAuth, 'write', nowEpochSecond);
    const inputs = Object.freeze({
      envelope_base64url: encodeEnvelope(durable.envelope),
      slot_epoch_minute: durable.envelope.slot_epoch_minute,
      request_id: durable.envelope.request_id,
      signature_sha256: await signEnvelope(durable.envelope, env.ADMISSION_HMAC_KEY),
    });
    const dispatched = await dispatchWorkflowOnce(fetchImpl, writeToken, inputs, { timeoutSignal });
    if (dispatched.outcome === 'confirmed') {
      await ledger.confirmDispatch(
        slot,
        sourceDigest,
        profileDigest,
        dispatched.receipt,
        'dispatched',
        nowMs,
      );
      return await ledger.terminalizeConfirmed(slot, sourceDigest, profileDigest, 'dispatched', nowMs);
    }
    const unknownAlert = await durableFailureAlert({
      slot,
      failure_class: dispatched.failure_class,
      status: dispatched.status,
      phase: 'unknown',
      decision: 'dispatch-unknown',
      request_id: durable.request_id,
    });
    const circuitAlert = await durableFailureAlert({
      slot,
      failure_class: 'circuit-open',
      status: null,
      phase: 'unknown',
      decision: 'circuit-open',
      request_id: durable.request_id,
    });
    await ledger.markUnknown(
      slot,
      sourceDigest,
      profileDigest,
      { failure_class: dispatched.failure_class, status: dispatched.status },
      nowMs,
      unknownAlert,
      circuitAlert,
    );
    await flushAlertOutbox({ env, ledger, fetchImpl, nowMs, timeoutSignal });
    return Object.freeze({ decision: 'dispatch-unknown', request_id: durable.request_id });
  } catch (error) {
    const durable = await ledger.getSlot(slot, sourceDigest, profileDigest).catch(() => null);
    if (durable && ['post-attempted', 'unknown'].includes(durable.phase)) {
      const unknownAlert = await durableFailureAlert({
        slot,
        failure_class: classifyFailure(error),
        status: statusOf(error),
        phase: 'unknown',
        decision: 'dispatch-unknown',
        request_id: durable.request_id,
      }).catch(() => null);
      const circuitAlert = await durableFailureAlert({
        slot,
        failure_class: 'circuit-open',
        status: null,
        phase: 'unknown',
        decision: 'circuit-open',
        request_id: durable.request_id,
      }).catch(() => null);
      await ledger.markUnknown(
        slot,
        sourceDigest,
        profileDigest,
        { failure_class: classifyFailure(error), status: statusOf(error) },
        nowMs,
        unknownAlert,
        circuitAlert,
      );
      return Object.freeze({ decision: 'dispatch-unknown', request_id: durable.request_id });
    }
    if (durable?.phase === 'confirmed') {
      try {
        return await ledger.terminalizeConfirmed(
          slot,
          sourceDigest,
          profileDigest,
          durable.result.terminal_decision,
          nowMs,
        );
      } catch {
        return durable.result;
      }
    }
    if (durable && durable.phase !== 'terminal') {
      return persistFailure({ env, ledger, slot, sourceDigest, profileDigest, error, nowMs });
    }
    throw Object.assign(new Error('Controller failed closed.'), {
      cause: error,
      result: Object.freeze({ decision: 'failed-closed', failure_class: classifyFailure(error) }),
    });
  }
}
