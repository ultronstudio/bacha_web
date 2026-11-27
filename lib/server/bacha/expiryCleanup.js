"use strict";
/**
 * Application-level expiry cleanup – a free alternative to Firestore TTL policies, so the project
 * can stay on the Firebase Spark plan. Runs from the existing daily Vercel cron.
 *
 * Every listed collection stores `expiresAt` (Firestore Timestamp). Expired documents are found
 * with a single-field range query (automatic index) and re-read and deleted in bounded transactions. Hard caps keep
 * one run to MAX_TOTAL queried documents and at most MAX_TOTAL deletes. Transactions add reads and retries; quota availability depends on all project traffic.
 * Pending credit-ledger records are never deleted here – sweepAbandoned() refunds them first.
 * Deletion is idempotent and safe to re-run; anything left over is deleted by the next run.
 */
const { fs } = require("./fsHelpers");

const TARGETS = [
  { collection: "analysisRequests", keep: (d) => d.status === "pending" },
  { collection: "authSessions" },
  { collection: "rateLimits" },
  { collection: "testingInterestVerifications" },
];
const PER_COLLECTION = 500;
const MAX_TOTAL = 2000;
const BATCH = 100;

async function purgeExpired(db, nowMillis, { logger = console, perCollection = PER_COLLECTION, maxTotal = MAX_TOTAL } = {}) {
  const now = fs().fromMillis(nowMillis);
  const report = {};
  let total = 0; let scanned = 0;
  for (const t of TARGETS) {
    if (scanned >= maxTotal) { report[t.collection] = { deleted: 0, skipped: "global cap reached" }; continue; }
    const cap = Math.min(perCollection, maxTotal - scanned);
    let deleted = 0; let kept = 0;
    try {
      const snap = await db.collection(t.collection).where("expiresAt", "<", now).limit(cap).get();
      scanned += snap.docs.length;
      for (let offset = 0; offset < snap.docs.length; offset += BATCH) {
        const refs = snap.docs.slice(offset, offset + BATCH).map((doc) => doc.ref);
        const counts = await db.runTransaction(async (tx) => {
          // All reads precede writes. Firestore retries if a document changes before commit.
          const current = await Promise.all(refs.map((ref) => tx.get(ref)));
          let removed = 0; let retained = 0;
          for (let i = 0; i < current.length; i++) {
            const doc = current[i];
            const data = doc.exists ? doc.data() : null;
            const expiry = data?.expiresAt;
            if (!data || typeof expiry?.toMillis !== "function" ||
                !Number.isFinite(expiry.toMillis()) || expiry.toMillis() >= nowMillis ||
                (t.keep && t.keep(data))) {
              retained++; continue;
            }
            tx.delete(refs[i]); removed++;
          }
          return { removed, retained };
        });
        // Only count committed deletions, never retry attempts.
        deleted += counts.removed; kept += counts.retained;
      }
      report[t.collection] = { deleted, kept, more: snap.docs.length === cap };
    } catch (e) {
      // e.g. a deployed TTL override with "indexes: []" makes the range query unavailable
      report[t.collection] = { deleted, error: e.code || e.message };
      logger.error(JSON.stringify({ evt: "expiry.cleanup_failed", collection: t.collection, error: String(e.code || e.message) }));
    }
    total += deleted;
  }
  logger.info(JSON.stringify({ evt: "expiry.cleanup", total }));
  return { expiryCleanup: { total, scanned, collections: report } };
}

module.exports = { purgeExpired, TARGETS, PER_COLLECTION, MAX_TOTAL };
