#!/usr/bin/env node
// Auditable credit review for one account (Phase 5, BUG-11). READ-ONLY by default.
//
//   GOOGLE_APPLICATION_CREDENTIALS=sa.json node scripts/audit-analysis-credits.mjs --uid <uid> [--period 2026-11]
//
// Prints the usage counter and every deep-analysis record it can find (Phase 4
// users/{uid}/analysisRequests and the Phase 5 top-level ledger) WITHOUT any content.
// Charged-but-undelivered analyses are listed as refund candidates.
//
// A refund is applied only with an explicit, logged decision by the owner:
//   ... --refund <n> --reason "BUG-11 incident 2026-11-27, 3 charges for 1 analysis" --confirm
// It decrements the counter (never below 0) and writes an immutable record to
// creditAdjustments/{auto} in the same transaction. Nothing else is modified.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const admin = require("firebase-admin");

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => {
  if (a.startsWith("--")) acc.push([a.slice(2), arr[i + 1] && !arr[i + 1].startsWith("--") ? arr[i + 1] : true]);
  return acc;
}, []));
if (!args.uid) { console.error("--uid required"); process.exit(2); }
const now = new Date();
const period = args.period || `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;

admin.initializeApp();
const db = admin.firestore();
const usageRef = db.collection("users").doc(args.uid).collection("usage").doc(period);
const usage = (await usageRef.get()).data() || {};
console.log(`usage ${period}: deepAnalysisCount=${usage.deepAnalysisCount ?? 0} monthlyLimit=${usage.monthlyLimit ?? "?"}`);

const legacy = await db.collection("users").doc(args.uid).collection("analysisRequests").get();
const ledger = await db.collection("analysisRequests").where("uid", "==", args.uid).get();
const rows = [
  ...legacy.docs.map((d) => ({ src: "phase4", id: d.id.slice(0, 8), ...pick(d.data()) })),
  ...ledger.docs.map((d) => ({ src: "ledger", id: d.id.slice(0, 8), ...pick(d.data()) })),
].sort((a, b) => a.createdAtMillis - b.createdAtMillis);
for (const r of rows) console.log(JSON.stringify(r));
const candidates = rows.filter((r) => r.status === "pending");
console.log(`records=${rows.length} pending(charged, no stored result)=${candidates.length}`);
if (legacy.empty && ledger.empty) console.log("No request records found (TTL may have removed them); decide from other evidence.");

if (args.refund) {
  const n = Number(args.refund);
  if (!args.confirm || !args.reason || !Number.isInteger(n) || n < 1 || n > 10) {
    console.error("Refund requires --refund <1..10> --reason <text> --confirm"); process.exit(2);
  }
  await db.runTransaction(async (tx) => {
    const cur = (await tx.get(usageRef)).data()?.deepAnalysisCount || 0;
    const next = Math.max(0, cur - n);
    tx.set(usageRef, { deepAnalysisCount: next }, { merge: true });
    tx.set(db.collection("creditAdjustments").doc(), {
      uid: args.uid, period, before: cur, after: next, refunded: cur - next,
      reason: String(args.reason).slice(0, 300), appliedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });
  console.log("Refund applied and recorded in creditAdjustments.");
}

function pick(d) {
  return { status: d.status, createdAtMillis: d.createdAtMillis || 0, period: d.period || null, attempts: d.attempts || 1, hasResult: !!d.result };
}
