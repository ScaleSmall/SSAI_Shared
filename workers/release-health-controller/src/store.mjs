import {
  activationProof,
  chainedAuditHash,
  controllerStateVersion,
  publicAuditEvent,
  sha256Hex,
} from './audit.mjs';

const phases = new Set(['leased', 'prepared', 'post-attempted', 'unknown', 'confirmed', 'terminal']);
const zeroHash = '0'.repeat(64);

function digest(value, label) {
  const result = String(value ?? '');
  if (!/^[a-f0-9]{64}$/.test(result)) throw new Error(`${label} is invalid.`);
  return result;
}

function exactSlot(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('Logical slot is invalid.');
  return value;
}

function exactNow(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Controller time is invalid.');
  return value;
}

function rows(sql, statement, ...parameters) {
  return [...sql.exec(statement, ...parameters)];
}

function parseJson(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function publicResult(value) {
  const serialized = publicAuditEvent(value);
  if (serialized.length > 8192) throw new Error('Controller result is oversized.');
  return serialized;
}

function validateAlertRecord(record) {
  if (
    !record || !/^[a-f0-9]{64}$/.test(String(record.alert_id ?? ''))
    || typeof record.body !== 'string' || record.body.length > 4096
  ) throw new Error('Alert outbox record is invalid.');
  return record;
}

export class ReleaseHealthSlotLedger {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.mutationQueue = Promise.resolve();
    this.initialize();
  }

  initialize() {
    this.state.storage.transactionSync(() => {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS generations(
        source_digest TEXT NOT NULL,
        profile_digest TEXT NOT NULL,
        observe_json TEXT NOT NULL DEFAULT '[]',
        activation_proof TEXT,
        standby INTEGER NOT NULL DEFAULT 0 CHECK(standby IN (0,1)),
        canary_streak INTEGER NOT NULL DEFAULT 0,
        last_canary_slot INTEGER,
        circuit_state TEXT NOT NULL DEFAULT 'closed' CHECK(circuit_state IN ('closed','open','half-open')),
        circuit_opened_slot INTEGER,
        circuit_open_until_slot INTEGER,
        circuit_episode INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY(source_digest, profile_digest)
      )`);
      this.sql.exec(`CREATE TABLE IF NOT EXISTS slots(
        slot INTEGER PRIMARY KEY,
        phase TEXT NOT NULL CHECK(phase IN ('leased','prepared','post-attempted','unknown','confirmed','terminal')),
        version INTEGER NOT NULL,
        source_digest TEXT NOT NULL,
        profile_digest TEXT NOT NULL,
        request_id TEXT,
        expected_sha TEXT,
        expires_at_epoch_second INTEGER,
        envelope_json TEXT,
        public_json TEXT NOT NULL DEFAULT '{}',
        post_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(post_attempt_count IN (0,1)),
        reconcile_count INTEGER NOT NULL DEFAULT 0,
        reconcile_after_ms INTEGER NOT NULL DEFAULT 0,
        alert_emitted INTEGER NOT NULL DEFAULT 0 CHECK(alert_emitted IN (0,1)),
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      )`);
      this.sql.exec(`CREATE TABLE IF NOT EXISTS audit(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        slot INTEGER NOT NULL,
        source_digest TEXT NOT NULL,
        profile_digest TEXT NOT NULL,
        controller_version TEXT NOT NULL,
        phase TEXT NOT NULL,
        result TEXT NOT NULL,
        result_digest TEXT NOT NULL,
        event_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE
      )`);
      this.sql.exec(`CREATE TABLE IF NOT EXISTS alert_outbox(
        alert_id TEXT PRIMARY KEY,
        slot INTEGER NOT NULL,
        source_digest TEXT NOT NULL,
        profile_digest TEXT NOT NULL,
        body TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending','sending','delivered','dead')),
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_ms INTEGER NOT NULL,
        lease_until_ms INTEGER,
        last_status INTEGER,
        error_class TEXT,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      )`);
    });
  }

  serialize(operation) {
    const pending = this.mutationQueue.then(operation, operation);
    this.mutationQueue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  generation(sourceDigest, profileDigest) {
    return rows(
      this.sql,
      'SELECT * FROM generations WHERE source_digest=? AND profile_digest=?',
      sourceDigest,
      profileDigest,
    )[0] || null;
  }

  latestAuditHash() {
    return rows(this.sql, 'SELECT event_hash FROM audit ORDER BY sequence DESC LIMIT 1')[0]?.event_hash || zeroHash;
  }

  async withAudit({ slot, sourceDigest, profileDigest, phase, result, publicValue = { decision: result } }, mutate) {
    return this.serialize(async () => {
      exactSlot(slot);
      digest(sourceDigest, 'Controller source digest');
      digest(profileDigest, 'Controller profile digest');
      if (!phases.has(phase) || !/^[a-z][a-z0-9-]{2,47}$/.test(result)) {
        throw new Error('Audit transition is invalid.');
      }
      const previousHash = this.latestAuditHash();
      const resultJson = publicResult(publicValue);
      const resultDigest = await sha256Hex('ssai-release-health-controller-result-v1', resultJson);
      const event = Object.freeze({
        controller_version: controllerStateVersion,
        phase,
        profile_digest: profileDigest,
        result,
        result_digest: resultDigest,
        slot,
        source_digest: sourceDigest,
      });
      const eventJson = publicAuditEvent(event);
      const eventHash = await chainedAuditHash(previousHash, event);
      return this.state.storage.transactionSync(() => {
        if (this.latestAuditHash() !== previousHash) throw new Error('Audit predecessor changed.');
        const changed = mutate(eventHash);
        if (changed && changed.skip) return changed.value;
        this.sql.exec(
          `INSERT INTO audit(
            slot,source_digest,profile_digest,controller_version,phase,result,result_digest,
            event_json,previous_hash,event_hash
          ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
          slot,
          sourceDigest,
          profileDigest,
          controllerStateVersion,
          phase,
          result,
          resultDigest,
          eventJson,
          previousHash,
          eventHash,
        );
        return changed;
      });
    });
  }

  async getSlot(slot, sourceDigest, profileDigest) {
    exactSlot(slot);
    digest(sourceDigest, 'Controller source digest');
    digest(profileDigest, 'Controller profile digest');
    const row = rows(this.sql, 'SELECT * FROM slots WHERE slot=?', slot)[0];
    if (!row) return null;
    if (row.source_digest !== sourceDigest || row.profile_digest !== profileDigest) {
      return Object.freeze({ decision: 'digest-mismatch', phase: 'terminal', slot });
    }
    return Object.freeze({
      slot: row.slot,
      phase: row.phase,
      source_digest: row.source_digest,
      profile_digest: row.profile_digest,
      request_id: row.request_id,
      expected_sha: row.expected_sha,
      expires_at_epoch_second: row.expires_at_epoch_second,
      envelope: row.envelope_json ? parseJson(row.envelope_json) : null,
      result: parseJson(row.public_json, {}),
      reconcile_count: row.reconcile_count,
      reconcile_after_ms: row.reconcile_after_ms,
      post_attempt_count: row.post_attempt_count,
    });
  }

  async result(slot, sourceDigest, profileDigest) {
    const row = await this.getSlot(slot, sourceDigest, profileDigest);
    if (!row) return null;
    return row.phase === 'terminal' ? row.result : row;
  }

  async abandonUnattempted(slot, expectedPhase, nowMs, failureClass, alertRecord) {
    exactSlot(slot);
    exactNow(nowMs);
    if (!['leased', 'prepared'].includes(expectedPhase)) {
      throw new Error('Unattempted abandonment phase is invalid.');
    }
    if (!['configuration', 'prepared-expired'].includes(failureClass)) {
      throw new Error('Prepared abandonment class is invalid.');
    }
    validateAlertRecord(alertRecord);
    const existing = rows(
      this.sql,
      'SELECT phase,source_digest,profile_digest,request_id FROM slots WHERE slot=?',
      slot,
    )[0];
    if (!existing || existing.phase !== expectedPhase) return false;
    const decision = expectedPhase === 'prepared' ? 'prepared-abandoned' : 'lease-abandoned';
    const value = Object.freeze({
      decision,
      failure_class: failureClass,
      request_id: existing.request_id,
    });
    const serialized = publicResult(value);
    return this.withAudit(
      {
        slot,
        sourceDigest: existing.source_digest,
        profileDigest: existing.profile_digest,
        phase: 'terminal',
        result: decision,
        publicValue: value,
      },
      () => {
        const current = rows(
          this.sql,
          `SELECT phase,source_digest,profile_digest,request_id,alert_emitted
           FROM slots WHERE slot=?`,
          slot,
        )[0];
        if (
          !current || current.phase !== expectedPhase
          || current.source_digest !== existing.source_digest
          || current.profile_digest !== existing.profile_digest
          || current.request_id !== existing.request_id
        ) return { skip: true, value: false };
        this.sql.exec(
          `UPDATE slots SET phase='terminal',version=version+1,public_json=?,updated_at_ms=?,
           alert_emitted=1 WHERE slot=?`,
          serialized,
          nowMs,
          slot,
        );
        if (!current.alert_emitted) {
          this.enqueueAlert(
            alertRecord,
            slot,
            existing.source_digest,
            existing.profile_digest,
            nowMs,
          );
        }
        return value;
      },
    );
  }

  async lease(slot, sourceDigest, profileDigest, nowMs) {
    exactNow(nowMs);
    return this.withAudit(
      { slot, sourceDigest, profileDigest, phase: 'leased', result: 'leased' },
      () => {
        if (rows(this.sql, 'SELECT 1 FROM slots WHERE slot=?', slot).length) {
          return { skip: true, value: false };
        }
        this.sql.exec(
          `INSERT OR IGNORE INTO generations(
            source_digest,profile_digest,created_at_ms,updated_at_ms
          ) VALUES(?,?,?,?)`,
          sourceDigest,
          profileDigest,
          nowMs,
          nowMs,
        );
        this.sql.exec(
          `INSERT INTO slots(
            slot,phase,version,source_digest,profile_digest,created_at_ms,updated_at_ms
          ) VALUES(?,'leased',1,?,?,?,?)`,
          slot,
          sourceDigest,
          profileDigest,
          nowMs,
          nowMs,
        );
        return true;
      },
    );
  }

  async prepareDispatch(slot, sourceDigest, profileDigest, prepared, nowMs) {
    exactNow(nowMs);
    if (
      !prepared || !/^[a-f0-9]{32}$/.test(String(prepared.request_id ?? ''))
      || !/^[a-f0-9]{40}$/.test(String(prepared.expected_sha ?? ''))
      || !Number.isSafeInteger(prepared.expires_at_epoch_second)
      || !prepared.envelope || typeof prepared.envelope !== 'object'
    ) throw new Error('Prepared dispatch is invalid.');
    const envelopeJson = JSON.stringify(prepared.envelope);
    if (!prepared.envelope || typeof prepared.envelope !== 'object' || envelopeJson.length > 8192) {
      throw new Error('Prepared dispatch is oversized.');
    }
    return this.withAudit(
      {
        slot,
        sourceDigest,
        profileDigest,
        phase: 'prepared',
        result: 'prepared',
        publicValue: { decision: 'prepared', request_id: prepared.request_id },
      },
      () => {
        const row = rows(
          this.sql,
          `SELECT phase FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        if (!row || row.phase !== 'leased') return { skip: true, value: false };
        this.sql.exec(
          `UPDATE slots SET
            phase='prepared',version=version+1,request_id=?,expected_sha=?,
            expires_at_epoch_second=?,envelope_json=?,updated_at_ms=?
           WHERE slot=?`,
          prepared.request_id,
          prepared.expected_sha,
          prepared.expires_at_epoch_second,
          envelopeJson,
          nowMs,
          slot,
        );
        return true;
      },
    );
  }

  async recordObserve(slot, sourceDigest, profileDigest, value, nowMs) {
    exactNow(nowMs);
    const baseResult = publicResult(value);
    return this.serialize(async () => {
      const priorHash = this.latestAuditHash();
      const generation = this.generation(sourceDigest, profileDigest);
      if (!generation) throw new Error('Controller generation is missing.');
      const existing = parseJson(generation.observe_json, []);
      const resultDigest = await sha256Hex('ssai-release-health-controller-result-v1', baseResult);
      const event = Object.freeze({
        controller_version: controllerStateVersion,
        phase: 'terminal',
        profile_digest: profileDigest,
        result: 'would-dispatch',
        result_digest: resultDigest,
        slot,
        source_digest: sourceDigest,
      });
      const eventJson = publicAuditEvent(event);
      const eventHash = await chainedAuditHash(priorHash, event);
      const observations = existing.at(-1)?.slot === slot - 15
        ? [existing.at(-1), { slot, audit_hash: eventHash }]
        : [{ slot, audit_hash: eventHash }];
      const proof = observations.length === 2
        ? await activationProof(sourceDigest, profileDigest, observations)
        : null;
      const result = Object.freeze({ ...value, activation_proof: proof });
      return this.state.storage.transactionSync(() => {
        if (this.latestAuditHash() !== priorHash) throw new Error('Audit predecessor changed.');
        const slotRow = rows(
          this.sql,
          `SELECT phase FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        const currentGeneration = this.generation(sourceDigest, profileDigest);
        if (
          !slotRow || slotRow.phase !== 'prepared' || !currentGeneration
          || currentGeneration.observe_json !== generation.observe_json
        ) throw new Error('Observe transition lost its durable precondition.');
        this.sql.exec(
          `UPDATE slots SET phase='terminal',version=version+1,public_json=?,updated_at_ms=?
           WHERE slot=?`,
          baseResult,
          nowMs,
          slot,
        );
        this.sql.exec(
          `UPDATE generations SET observe_json=?,activation_proof=?,updated_at_ms=?
           WHERE source_digest=? AND profile_digest=?`,
          JSON.stringify(observations),
          proof,
          nowMs,
          sourceDigest,
          profileDigest,
        );
        this.sql.exec(
          `INSERT INTO audit(
            slot,source_digest,profile_digest,controller_version,phase,result,result_digest,
            event_json,previous_hash,event_hash
          ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
          slot,
          sourceDigest,
          profileDigest,
          controllerStateVersion,
          'terminal',
          'would-dispatch',
          resultDigest,
          eventJson,
          priorHash,
          eventHash,
        );
        return result;
      });
    });
  }

  async recordNoDispatch(slot, sourceDigest, profileDigest, value, nowMs) {
    exactNow(nowMs);
    const serialized = publicResult(value);
    const resultName = String(value.decision ?? 'terminal');
    return this.withAudit(
      { slot, sourceDigest, profileDigest, phase: 'terminal', result: resultName, publicValue: value },
      () => {
        const row = rows(
          this.sql,
          `SELECT phase FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        if (!row || row.phase === 'terminal' || row.phase === 'post-attempted' || row.phase === 'unknown') {
          return { skip: true, value: false };
        }
        this.sql.exec(
          `UPDATE slots SET phase='terminal',version=version+1,public_json=?,updated_at_ms=?
           WHERE slot=?`,
          serialized,
          nowMs,
          slot,
        );
        return value;
      },
    );
  }

  async activationReady(sourceDigest, profileDigest, proof) {
    const row = this.generation(sourceDigest, profileDigest);
    return Boolean(
      row && /^[a-f0-9]{64}$/.test(String(proof ?? ''))
      && row.activation_proof === proof
      && parseJson(row.observe_json, []).length === 2
      && row.standby === 0,
    );
  }

  async updateStandby(sourceDigest, profileDigest, shouldStandby, slot, nowMs) {
    exactNow(nowMs);
    const row = this.generation(sourceDigest, profileDigest);
    if (!row) throw new Error('Controller generation is missing.');
    const next = shouldStandby ? 1 : 0;
    if (row.standby === next) {
      if (shouldStandby && row.last_canary_slot !== slot) {
        return this.withAudit(
          {
            slot,
            sourceDigest,
            profileDigest,
            phase: 'leased',
            result: 'standby-evidence',
            publicValue: { decision: 'standby-evidence', slot },
          },
          () => {
            this.sql.exec(
              `UPDATE generations SET canary_streak=2,last_canary_slot=?,updated_at_ms=?
               WHERE source_digest=? AND profile_digest=?`,
              slot,
              nowMs,
              sourceDigest,
              profileDigest,
            );
            return Object.freeze({ outcome: 'standby', changed: true });
          },
        );
      }
      return Object.freeze({ outcome: shouldStandby ? 'standby' : 'clear', changed: false });
    }
    const outcome = shouldStandby ? 'standby-entered' : 'standby-resumed';
    return this.withAudit(
      {
        slot,
        sourceDigest,
        profileDigest,
        phase: 'leased',
        result: outcome,
        publicValue: { decision: outcome, slot },
      },
      () => {
        this.sql.exec(
          `UPDATE generations SET standby=?,canary_streak=?,last_canary_slot=?,updated_at_ms=?
           WHERE source_digest=? AND profile_digest=?`,
          next,
          shouldStandby ? 2 : 0,
          shouldStandby ? slot : null,
          nowMs,
          sourceDigest,
          profileDigest,
        );
        return Object.freeze({ outcome, changed: true });
      },
    );
  }

  async consumePostPermit(slot, sourceDigest, profileDigest, proof, nowEpochSecond, nowMs) {
    exactNow(nowMs);
    if (!Number.isSafeInteger(nowEpochSecond) || nowEpochSecond < 0) throw new Error('Controller epoch is invalid.');
    const generation = this.generation(sourceDigest, profileDigest);
    const prepared = rows(
      this.sql,
      `SELECT phase,post_attempt_count,expires_at_epoch_second FROM slots
       WHERE slot=? AND source_digest=? AND profile_digest=?`,
      slot,
      sourceDigest,
      profileDigest,
    )[0];
    if (!generation || !prepared || prepared.phase !== 'prepared' || prepared.post_attempt_count !== 0) {
      return Object.freeze({ outcome: 'not-prepared', permit: false });
    }
    if (prepared.expires_at_epoch_second < nowEpochSecond) {
      return Object.freeze({ outcome: 'prepared-expired', permit: false });
    }
    if (
      generation.activation_proof !== proof || !/^[a-f0-9]{64}$/.test(String(proof ?? ''))
      || generation.standby !== 0
    ) return Object.freeze({ outcome: 'interlock-blocked', permit: false });
    if (generation.circuit_state === 'open' && slot < generation.circuit_open_until_slot) {
      return Object.freeze({
        outcome: 'circuit-open',
        permit: false,
        reopen_at_slot: generation.circuit_open_until_slot,
      });
    }
    if (generation.circuit_state === 'half-open') {
      return Object.freeze({ outcome: 'circuit-half-open-busy', permit: false });
    }
    const halfOpen = generation.circuit_state === 'open';
    const result = halfOpen ? 'circuit-half-open' : 'post-permit';
    return this.withAudit(
      { slot, sourceDigest, profileDigest, phase: 'post-attempted', result },
      () => {
        const current = rows(
          this.sql,
          `SELECT phase,post_attempt_count FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        const currentGeneration = this.generation(sourceDigest, profileDigest);
        if (
          !current || current.phase !== 'prepared' || current.post_attempt_count !== 0
          || !currentGeneration || currentGeneration.activation_proof !== proof
          || currentGeneration.standby !== 0
          || (halfOpen && currentGeneration.circuit_state !== 'open')
          || (!halfOpen && currentGeneration.circuit_state !== 'closed')
        ) return { skip: true, value: Object.freeze({ outcome: 'permit-lost', permit: false }) };
        this.sql.exec(
          `UPDATE slots SET phase='post-attempted',post_attempt_count=1,version=version+1,
           reconcile_after_ms=?,updated_at_ms=? WHERE slot=?`,
          nowMs,
          nowMs,
          slot,
        );
        if (halfOpen) {
          this.sql.exec(
            `UPDATE generations SET circuit_state='half-open',updated_at_ms=?
             WHERE source_digest=? AND profile_digest=?`,
            nowMs,
            sourceDigest,
            profileDigest,
          );
        }
        return Object.freeze({ outcome: result, permit: true, half_open: halfOpen });
      },
    );
  }

  enqueueAlert(record, slot, sourceDigest, profileDigest, nowMs) {
    validateAlertRecord(record);
    this.sql.exec(
      `INSERT OR IGNORE INTO alert_outbox(
        alert_id,slot,source_digest,profile_digest,body,state,
        next_attempt_ms,created_at_ms,updated_at_ms
      ) VALUES(?,?,?,?,?,'pending',?,?,?)`,
      record.alert_id,
      slot,
      sourceDigest,
      profileDigest,
      record.body,
      nowMs,
      nowMs,
      nowMs,
    );
  }

  async markUnknown(
    slot,
    sourceDigest,
    profileDigest,
    value,
    nowMs,
    unknownAlert = null,
    circuitAlert = null,
  ) {
    exactNow(nowMs);
    if (unknownAlert) validateAlertRecord(unknownAlert);
    if (circuitAlert) validateAlertRecord(circuitAlert);
    const row = await this.getSlot(slot, sourceDigest, profileDigest);
    if (!row || !['post-attempted', 'unknown'].includes(row.phase)) {
      return Object.freeze({ outcome: 'not-reconcileable', circuit: 'unchanged' });
    }
    const generation = this.generation(sourceDigest, profileDigest);
    const existingFailures = rows(
      this.sql,
      `SELECT COUNT(*) AS count FROM slots
       WHERE source_digest=? AND profile_digest=? AND phase='unknown' AND slot>=? AND slot<>?`,
      sourceDigest,
      profileDigest,
      slot - 60,
      slot,
    )[0].count;
    const opens = generation.circuit_state === 'half-open' || (
      row.phase === 'post-attempted' && Number(existingFailures) >= 3
    );
    const resultName = opens ? 'dispatch-unknown-circuit-open' : 'dispatch-unknown';
    const serialized = publicResult({ ...value, decision: 'dispatch-unknown', request_id: row.request_id });
    const nextCount = row.reconcile_count + 1;
    const delayMinutes = Math.min(5 * (2 ** Math.min(nextCount - 1, 3)), 60);
    return this.withAudit(
      {
        slot,
        sourceDigest,
        profileDigest,
        phase: 'unknown',
        result: resultName,
        publicValue: { ...value, decision: 'dispatch-unknown', request_id: row.request_id },
      },
      () => {
        const current = rows(
          this.sql,
          `SELECT phase,reconcile_count,alert_emitted FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        if (!current || !['post-attempted', 'unknown'].includes(current.phase)) {
          return { skip: true, value: Object.freeze({ outcome: 'transition-lost', circuit: 'unchanged' }) };
        }
        this.sql.exec(
          `UPDATE slots SET phase='unknown',version=version+1,public_json=?,
           reconcile_count=reconcile_count+1,reconcile_after_ms=?,updated_at_ms=?,alert_emitted=?
           WHERE slot=?`,
          serialized,
          nowMs + delayMinutes * 60_000,
          nowMs,
          current.alert_emitted || unknownAlert ? 1 : 0,
          slot,
        );
        if (!current.alert_emitted && unknownAlert) {
          this.enqueueAlert(unknownAlert, slot, sourceDigest, profileDigest, nowMs);
        }
        if (opens) {
          if (!circuitAlert) throw new Error('Circuit-open alert is required.');
          this.sql.exec(
            `UPDATE generations SET circuit_state='open',circuit_opened_slot=?,
             circuit_open_until_slot=?,circuit_episode=circuit_episode+1,updated_at_ms=?
             WHERE source_digest=? AND profile_digest=?`,
            slot,
            slot + 60,
            nowMs,
            sourceDigest,
            profileDigest,
          );
          this.enqueueAlert(circuitAlert, slot, sourceDigest, profileDigest, nowMs);
        }
        return Object.freeze({
          outcome: 'unknown',
          circuit: opens ? 'opened' : generation.circuit_state,
          reconcile_after_ms: nowMs + delayMinutes * 60_000,
        });
      },
    );
  }

  async confirmDispatch(slot, sourceDigest, profileDigest, receipt, terminalDecision, nowMs) {
    exactNow(nowMs);
    if (!['dispatched', 'dispatch-reconciled'].includes(terminalDecision)) {
      throw new Error('Confirmation terminal decision is invalid.');
    }
    const result = Object.freeze({
      decision: 'dispatch-confirmed',
      terminal_decision: terminalDecision,
      workflow_run_id: receipt.workflow_run_id,
      run_url: receipt.run_url,
      html_url: receipt.html_url,
    });
    const serialized = publicResult(result);
    const generation = this.generation(sourceDigest, profileDigest);
    return this.withAudit(
      {
        slot,
        sourceDigest,
        profileDigest,
        phase: 'confirmed',
        result: 'dispatch-confirmed',
        publicValue: result,
      },
      () => {
        const row = rows(
          this.sql,
          `SELECT phase,post_attempt_count FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        if (!row || !['post-attempted', 'unknown'].includes(row.phase) || row.post_attempt_count !== 1) {
          return { skip: true, value: false };
        }
        this.sql.exec(
          `UPDATE slots SET phase='confirmed',version=version+1,public_json=?,updated_at_ms=?
           WHERE slot=?`,
          serialized,
          nowMs,
          slot,
        );
        if (generation?.circuit_state === 'half-open') {
          this.sql.exec(
            `UPDATE generations SET circuit_state='closed',circuit_opened_slot=NULL,
             circuit_open_until_slot=NULL,updated_at_ms=?
             WHERE source_digest=? AND profile_digest=?`,
            nowMs,
            sourceDigest,
            profileDigest,
          );
        }
        return result;
      },
    );
  }

  async terminalizeConfirmed(slot, sourceDigest, profileDigest, decision, nowMs) {
    exactNow(nowMs);
    if (!['dispatched', 'dispatch-reconciled'].includes(decision)) throw new Error('Confirmation result is invalid.');
    const row = await this.getSlot(slot, sourceDigest, profileDigest);
    if (!row || row.phase !== 'confirmed') return false;
    const value = Object.freeze({ ...row.result, decision });
    const serialized = publicResult(value);
    return this.withAudit(
      { slot, sourceDigest, profileDigest, phase: 'terminal', result: decision, publicValue: value },
      () => {
        const current = rows(this.sql, 'SELECT phase FROM slots WHERE slot=?', slot)[0];
        if (!current || current.phase !== 'confirmed') return { skip: true, value: false };
        this.sql.exec(
          `UPDATE slots SET phase='terminal',version=version+1,public_json=?,updated_at_ms=?
           WHERE slot=?`,
          serialized,
          nowMs,
          slot,
        );
        return value;
      },
    );
  }

  async recordFailureTerminal(
    slot,
    sourceDigest,
    profileDigest,
    value,
    nowMs,
    alertRecord = null,
  ) {
    exactNow(nowMs);
    if (alertRecord) validateAlertRecord(alertRecord);
    const serialized = publicResult(value);
    const resultName = String(value.decision ?? 'failed-closed');
    return this.withAudit(
      { slot, sourceDigest, profileDigest, phase: 'terminal', result: resultName, publicValue: value },
      () => {
        const row = rows(
          this.sql,
          `SELECT phase,alert_emitted FROM slots
           WHERE slot=? AND source_digest=? AND profile_digest=?`,
          slot,
          sourceDigest,
          profileDigest,
        )[0];
        if (!row || ['terminal', 'confirmed', 'post-attempted', 'unknown'].includes(row.phase)) {
          return { skip: true, value: false };
        }
        this.sql.exec(
          `UPDATE slots SET phase='terminal',version=version+1,public_json=?,updated_at_ms=?,
           alert_emitted=? WHERE slot=?`,
          serialized,
          nowMs,
          row.alert_emitted || alertRecord ? 1 : 0,
          slot,
        );
        if (!row.alert_emitted && alertRecord) {
          this.enqueueAlert(alertRecord, slot, sourceDigest, profileDigest, nowMs);
        }
        return value;
      },
    );
  }

  async listReconcileable(nowMs, limit = 4) {
    exactNow(nowMs);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10) throw new Error('Reconciliation limit is invalid.');
    return rows(
      this.sql,
      `SELECT slot,phase,request_id,expected_sha,reconcile_count,source_digest,profile_digest
       FROM slots
       WHERE phase IN ('post-attempted','unknown') AND reconcile_after_ms<=?
       ORDER BY slot ASC LIMIT ?`,
      nowMs,
      limit,
    ).map((row) => Object.freeze({ ...row }));
  }

  async listUnattempted(limit = 4) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10) {
      throw new Error('Unattempted inventory limit is invalid.');
    }
    return rows(
      this.sql,
      `SELECT slot,phase,request_id,expected_sha,expires_at_epoch_second,source_digest,profile_digest
       FROM slots WHERE phase IN ('leased','prepared') ORDER BY slot ASC LIMIT ?`,
      limit,
    ).map((row) => Object.freeze({ ...row }));
  }

  async claimAlerts(nowMs, limit = 3, leaseMs = 30_000) {
    exactNow(nowMs);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5 || !Number.isSafeInteger(leaseMs)) {
      throw new Error('Alert outbox lease is invalid.');
    }
    return this.serialize(async () => this.state.storage.transactionSync(() => {
      const available = rows(
        this.sql,
        `SELECT * FROM alert_outbox
         WHERE (state='pending' AND next_attempt_ms<=?)
            OR (state='sending' AND lease_until_ms<=?)
         ORDER BY created_at_ms ASC LIMIT ?`,
        nowMs,
        nowMs,
        limit,
      );
      for (const record of available) {
        this.sql.exec(
          `UPDATE alert_outbox SET state='sending',attempts=attempts+1,lease_until_ms=?,updated_at_ms=?
           WHERE alert_id=?`,
          nowMs + leaseMs,
          nowMs,
          record.alert_id,
        );
      }
      return available.map((record) => Object.freeze({
        alert_id: record.alert_id,
        body: record.body,
        attempts: record.attempts + 1,
      }));
    }));
  }

  async acknowledgeAlert(alertId, status, nowMs) {
    exactNow(nowMs);
    if (!/^[a-f0-9]{64}$/.test(String(alertId ?? '')) || !Number.isSafeInteger(status)) {
      throw new Error('Alert acknowledgement is invalid.');
    }
    return this.serialize(async () => this.state.storage.transactionSync(() => {
      const row = rows(this.sql, "SELECT state FROM alert_outbox WHERE alert_id=?", alertId)[0];
      if (!row || row.state !== 'sending') return false;
      this.sql.exec(
        `UPDATE alert_outbox SET state='delivered',last_status=?,lease_until_ms=NULL,updated_at_ms=?
         WHERE alert_id=?`,
        status,
        nowMs,
        alertId,
      );
      return true;
    }));
  }

  async rejectAlert(alertId, status, errorClass, nowMs) {
    exactNow(nowMs);
    if (
      !/^[a-f0-9]{64}$/.test(String(alertId ?? ''))
      || !['transport', 'provider-evidence'].includes(errorClass)
      || (status !== null && !Number.isSafeInteger(status))
    ) throw new Error('Alert rejection is invalid.');
    return this.serialize(async () => this.state.storage.transactionSync(() => {
      const row = rows(this.sql, 'SELECT state,attempts FROM alert_outbox WHERE alert_id=?', alertId)[0];
      if (!row || row.state !== 'sending') return false;
      const dead = row.attempts >= 8;
      const delay = Math.min(60_000 * (2 ** Math.min(row.attempts - 1, 5)), 3_600_000);
      this.sql.exec(
        `UPDATE alert_outbox SET state=?,next_attempt_ms=?,lease_until_ms=NULL,
         last_status=?,error_class=?,updated_at_ms=? WHERE alert_id=?`,
        dead ? 'dead' : 'pending',
        nowMs + delay,
        status,
        errorClass,
        nowMs,
        alertId,
      );
      return !dead;
    }));
  }
}
