"use strict";
/**
 * Application-level expiry cleanup – a free alternative to Firestore TTL policies, so the project
 * can stay on the Firebase Spark plan. Runs from the existing daily Vercel cron.
 *
 * Every listed collection stores `expiresAt` (Firestore Timestamp). Expired documents are found
 * with a single-field range query (automatic index) and deleted in bounded batches. Hard caps keep
 * one run far below the Spark daily quotas (50k reads / 20k deletes): at most MAX_TOTAL deletes.
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
const BATCH = 250;

async function purgeExpired(db, nowMillis, { logger = console, perCollection = PER_COLLECTION, maxTotal = MAX_TOTAL } = {}) {
  const now = fs().fromMillis(nowMillis);
  const report = {};
  let total = 0;
  for (const t of TARGETS) {
    if (total >= maxTotal) { report[t.collection] = { deleted: 0, skipped: "global cap reached" }; continue; }
    const cap = Math.min(perCollection, maxTotal - total);
    let deleted = 0; let kept = 0;
    try {
      const snap = await db.collection(t.collection).where("expiresAt", "<", now).limit(cap).get();
      let batch = db.batch(); let inBatch = 0;
      for (const doc of snap.docs) {
        if (t.keep && t.keep(doc.data() || {})) { kept++; continue; }
        batch.delete(doc.ref); inBatch++; deleted++;
        if (inBatch === BATCH) { await batch.commit(); batch = db.batch(); inBatch = 0; }
      }
      if (inBatch) await batch.commit();
      report[t.collection] = { deleted, kept, more: snap.docs.length === cap };
    } catch (e) {
      // e.g. a deployed TTL override with "indexes: []" makes the range query unavailable
      report[t.collection] = { deleted, error: e.code || e.message };
      logger.error(JSON.stringify({ evt: "expiry.cleanup_failed", collection: t.collection, error: String(e.code || e.message) }));
    }
    total += deleted;
  }
  logger.info(JSON.stringify({ evt: "expiry.cleanup", total }));
  return { expiryCleanup: { total, collections: report } };
}

module.exports = { purgeExpired, TARGETS, PER_COLLECTION, MAX_TOTAL };
