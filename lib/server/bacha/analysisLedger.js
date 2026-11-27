"use strict";

/**
 * Deep-analysis credit ledger (Phase 5, BUG-11).
 *
 * One document per (user, requestId) in the top-level `analysisRequests`
 * collection. The quota counter and the ledger record are always changed in
 * the SAME Firestore transaction, so a credit is charged at most once per
 * logical analysis, whatever the client resends.
 *
 * States:
 *   pending  – credit reserved, provider call in progress (or crashed)
 *   done     – credit charged, result stored (returned again on resend)
 *   failed   – credit refunded; the same requestId may be retried
 *   refunded – abandoned pending record refunded by the sweeper
 *
 * The requestId is bound to a fingerprint of the request content, so a client
 * bug that reuses an id for different content cannot fetch another result.
 * Deduplication is NOT permanent and NOT content-based: a new analysis with a
 * new requestId of the same text is a new, intentionally started analysis.
 */
const crypto = require("node:crypto");
const { fs } = require("./fsHelpers");
const { FREE_MONTHLY_LIMIT, PLUS_MONTHLY_LIMIT } = require("./config");
const { entitlementGrantsPlus } = require("./billing");

const COLLECTION = "analysisRequests";
/** Longer than the Vercel maxDuration (120 s): a pending record older than this
 * belongs to an invocation that cannot still be running. */
const PENDING_STALE_MS = 150 * 1000;
/** Abandoned pending records older than this are refunded by the sweeper. */
const SWEEP_AFTER_MS = 10 * 60 * 1000;
/** How long a finished result can be recovered without a new charge. */
const RECORD_TTL_MS = 24 * 60 * 60 * 1000;
const IN_PROGRESS_RETRY_AFTER_S = 5;

class LedgerConflictError extends Error {
  constructor(reason, message, retryAfterSeconds = null) {
    super(message);
    this.name = "LedgerConflictError";
    this.status = 409;
    this.code = "already-exists";
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function getCurrentPeriod(nowMillis = Date.now()) {
  const d = new Date(nowMillis);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

/** Content fingerprint: analysis type + text + image bytes. Never stored in clear. */
function requestFingerprint(input) {
  const imageHash = input.image && input.image.base64 ? sha256(input.image.base64) : "-";
  return sha256(`v1\0${input.analysisType || "TEXT_OR_URL"}\0${input.text || ""}\0${imageHash}`);
}

/** Opaque document id; the raw requestId and uid are not used as the key. */
function ledgerDocId(uid, requestId) {
  return sha256(`ledger:v1\0${uid}\0${requestId}`).slice(0, 40);
}

/** Short correlation id for logs (no uid, no content). */
function correlationId(uid, requestId) {
  return requestId ? sha256(`rid\0${uid}\0${requestId}`).slice(0, 12) : null;
}

function usageRefFor(db, uid, period) {
  return db.collection("users").doc(uid).collection("usage").doc(period);
}

async function monthlyLimitFor(db, uid, nowMillis) {
  const entSnap = await db.collection("users").doc(uid).collection("entitlement").doc("current").get();
  const isPlus = entitlementGrantsPlus(entSnap.exists ? entSnap.data() : null, nowMillis);
  return { isPlus, limit: isPlus ? PLUS_MONTHLY_LIMIT : FREE_MONTHLY_LIMIT };
}

/**
 * Atomic reservation.
 * Returns one of:
 *   { kind: "reserved", used, limit, usageRef, ledgerRef, takeover }
 *   { kind: "exhausted", used, limit }
 *   { kind: "duplicate_done", result, used, limit }
 * Throws LedgerConflictError for an in-flight duplicate or an id reused for other content.
 */
async function reserve(db, uid, input, nowMillis) {
  const { limit, isPlus } = await monthlyLimitFor(db, uid, nowMillis);
  const period = getCurrentPeriod(nowMillis);
  const usageRef = usageRefFor(db, uid, period);
  const requestId = input.requestId || null;
  const fingerprint = requestId ? requestFingerprint(input) : null;
  const ledgerRef = requestId ? db.collection(COLLECTION).doc(ledgerDocId(uid, requestId)) : null;

  let outcome = null;
  await db.runTransaction(async (tx) => {
    outcome = null;
    let existing = null;
    if (ledgerRef) {
      const snap = await tx.get(ledgerRef);
      existing = snap.exists ? snap.data() : null;
    }
    const usageSnap = await tx.get(usageRef);
    const used = usageSnap.exists ? usageSnap.data().deepAnalysisCount || 0 : 0;

    if (existing && Number(existing.createdAtMillis || 0) + RECORD_TTL_MS > nowMillis) {
      if (existing.fingerprint !== fingerprint) {
        throw new LedgerConflictError("request_id_reused", "Identifikátor požadavku byl použit pro jiný obsah.");
      }
      if (existing.status === "done" && existing.result) {
        outcome = { kind: "duplicate_done", result: existing.result, used, limit };
        return;
      }
      if (existing.status === "pending") {
        const fresh = Number(existing.updatedAtMillis || existing.createdAtMillis || 0) + PENDING_STALE_MS > nowMillis;
        if (fresh) {
          throw new LedgerConflictError("request_in_progress", "Tento požadavek se už zpracovává.", IN_PROGRESS_RETRY_AFTER_S);
        }
        // The invocation that reserved this credit crashed or timed out. Reuse its
        // reservation instead of charging again.
        tx.set(ledgerRef, { updatedAtMillis: nowMillis, attempts: Number(existing.attempts || 1) + 1 }, { merge: true });
        outcome = {
          kind: "reserved", takeover: true, used, limit, isPlus,
          usageRef: usageRefFor(db, uid, existing.period || period), ledgerRef,
        };
        return;
      }
      // failed / refunded: the previous attempt was not charged -> fall through to a new reservation.
    }

    if (used >= limit) {
      outcome = { kind: "exhausted", used, limit };
      return;
    }
    tx.set(usageRef, { deepAnalysisCount: used + 1, monthlyLimit: limit, updatedAt: fs().serverTimestamp() }, { merge: true });
    if (ledgerRef) {
      tx.set(ledgerRef, {
        uid,
        status: "pending",
        fingerprint,
        period,
        createdAtMillis: nowMillis,
        updatedAtMillis: nowMillis,
        attempts: existing ? Number(existing.attempts || 1) + 1 : 1,
        expiresAt: fs().fromMillis(nowMillis + RECORD_TTL_MS),
      });
    }
    outcome = { kind: "reserved", takeover: false, used: used + 1, limit, isPlus, usageRef, ledgerRef };
  });
  return outcome;
}

/** Marks a reservation as charged and stores the response for safe recovery. */
async function complete(reservation, response, nowMillis, logger = console) {
  if (!reservation.ledgerRef) return;
  try {
    await reservation.ledgerRef.set({ status: "done", result: response, updatedAtMillis: nowMillis }, { merge: true });
  } catch (e) {
    // The user got the result; the sweeper refunding this would only favour the user.
    logger.warn("ledger complete write failed:", e.message);
  }
}

/** Refunds a reservation exactly once (transactional state check). */
async function refund(db, reservation, nowMillis, reason, logger = console) {
  try {
    if (!reservation.ledgerRef) {
      await reservation.usageRef.update({ deepAnalysisCount: fs().increment(-1) });
      return true;
    }
    let refunded = false;
    await db.runTransaction(async (tx) => {
      refunded = false;
      const snap = await tx.get(reservation.ledgerRef);
      const rec = snap.exists ? snap.data() : null;
      if (!rec || rec.status !== "pending") return; // already completed/refunded elsewhere
      const usageRef = usageRefFor(db, rec.uid, rec.period);
      const usageSnap = await tx.get(usageRef);
      const used = usageSnap.exists ? usageSnap.data().deepAnalysisCount || 0 : 0;
      tx.set(usageRef, { deepAnalysisCount: Math.max(0, used - 1) }, { merge: true });
      tx.set(reservation.ledgerRef, { status: "failed", failureReason: reason, updatedAtMillis: nowMillis }, { merge: true });
      refunded = true;
    });
    return refunded;
  } catch (e) {
    logger.error("Failed to refund reservation:", e.message);
    return false;
  }
}

/**
 * Refunds pending reservations abandoned by crashed/killed invocations.
 * Equality-only query on `status` (automatic single-field index), bounded.
 */
async function sweepAbandoned(db, nowMillis, { limit = 200, logger = console } = {}) {
  const snap = await db.collection(COLLECTION).where("status", "==", "pending").limit(limit).get();
  let refunded = 0;
  for (const doc of snap.docs) {
    const rec = doc.data();
    if (Number(rec.updatedAtMillis || rec.createdAtMillis || 0) + SWEEP_AFTER_MS > nowMillis) continue;
    await db.runTransaction(async (tx) => {
      const fresh = await tx.get(doc.ref);
      const r = fresh.exists ? fresh.data() : null;
      if (!r || r.status !== "pending") return;
      const usageRef = usageRefFor(db, r.uid, r.period);
      const usageSnap = await tx.get(usageRef);
      const used = usageSnap.exists ? usageSnap.data().deepAnalysisCount || 0 : 0;
      tx.set(usageRef, { deepAnalysisCount: Math.max(0, used - 1) }, { merge: true });
      tx.set(doc.ref, { status: "refunded", failureReason: "abandoned", updatedAtMillis: nowMillis }, { merge: true });
      refunded++;
    });
  }
  if (refunded) logger.info(JSON.stringify({ evt: "ledger.sweep", refunded }));
  return { abandonedRefunded: refunded };
}

module.exports = {
  COLLECTION,
  PENDING_STALE_MS,
  SWEEP_AFTER_MS,
  RECORD_TTL_MS,
  LedgerConflictError,
  getCurrentPeriod,
  requestFingerprint,
  ledgerDocId,
  correlationId,
  reserve,
  complete,
  refund,
  sweepAbandoned,
};
