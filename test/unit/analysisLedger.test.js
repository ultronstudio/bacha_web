"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb, silentLogger } = require("../helpers/setup");
const svc = require("../../lib/server/bacha/analysisService");
const ledger = require("../../lib/server/bacha/analysisLedger");
const { errorResponse } = require("../../lib/server/bacha/authCore");

const NOW = Date.parse("2026-11-27T09:28:00Z");
const goodAi = JSON.stringify({
  riskLevel: "HIGH", confidence: "HIGH", summary: "Podvod s bezpečným účtem.", scamType: "BANK_PHISHING",
  detectedActions: ["TRANSFER_MONEY"], requiresFurtherVerification: false,
  signals: [{ id: "safe_account", title: "Bezpečný účet", description: "", severity: "HIGH", isPositive: false, evidenceGroup: "FINANCIAL_REQUEST" }],
  recommendedActions: [{ title: "Nic nepřevádějte", description: "", isCrucial: true }], limitations: [],
});
const usage = (db, uid) => (db.raw(`users/${uid}/usage/${svc.getCurrentPeriod(NOW)}`) || {}).deepAnalysisCount || 0;
const deps = (db, generate, extra = {}) => ({ db, generate, providers: [], logger: silentLogger, now: () => NOW, aiTimeoutMs: 200, ...extra });
const phoneInput = (requestId, text = "Telefonní číslo: +420777123456. Kontext: volal bankéř, převeďte úspory na bezpečný účet.") =>
  ({ text, analysisType: "PHONE_NUMBER", image: null, requestId });
async function seedUsage(db, uid, n) {
  await db.collection("users").doc(uid).collection("usage").doc(svc.getCurrentPeriod(NOW)).set({ deepAnalysisCount: n });
}

describe("BUG-11 credit ledger", () => {
  test("reproduction: Free 2/5, 20 rapid submissions of ONE logical analysis charge exactly one credit", async () => {
    const db = freshDb(() => NOW);
    await seedUsage(db, "u1", 2);
    let providerCalls = 0;
    let release;
    const gate = new Promise((r) => { release = r; });
    const gen = async () => { providerCalls++; await gate; return goodAi; };
    const rid = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const first = svc.analyzeContent(deps(db, gen, { aiTimeoutMs: 5000 }), "u1", phoneInput(rid));
    await new Promise((r) => setTimeout(r, 5));
    const dupes = await Promise.allSettled(Array.from({ length: 19 }, () => svc.analyzeContent(deps(db, gen), "u1", phoneInput(rid))));
    assert.ok(dupes.every((d) => d.status === "rejected" && d.reason.reason === "request_in_progress"));
    release();
    const r = await first;
    assert.equal(r.quotaCharged, true);
    assert.equal(providerCalls, 1);
    assert.equal(usage(db, "u1"), 3, "2 + exactly one credit");
    // A resend after completion (lost response) returns the stored result without a charge.
    const again = await svc.analyzeContent(deps(db, gen), "u1", phoneInput(rid));
    assert.deepEqual([again.quotaCharged, again.duplicateRequest, again.resultCategory], [false, true, r.resultCategory]);
    assert.equal(again.deepAnalysesUsed, 3);
    assert.equal(usage(db, "u1"), 3);
  });

  test("in-progress duplicate maps to 409 with reason and Retry-After", async () => {
    const e = new ledger.LedgerConflictError("request_in_progress", "x", 5);
    const res = errorResponse(e);
    assert.equal(res.status, 409);
    assert.equal(res.headers.get("retry-after"), "5");
    assert.equal((await res.json()).error.reason, "request_in_progress");
  });

  test("distinct requestIds are distinct intentional analyses (no permanent content dedup)", async () => {
    const db = freshDb(() => NOW);
    await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput("req-aaaaaaaaaaaaaaaa"));
    await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput("req-bbbbbbbbbbbbbbbb"));
    assert.equal(usage(db, "u1"), 2);
  });

  test("requestId bound to user and content: other user or other content cannot reuse it", async () => {
    const db = freshDb(() => NOW);
    const rid = "req-shared-0000000001";
    await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput(rid));
    // Different user, same id -> independent analysis, independently charged.
    const other = await svc.analyzeContent(deps(db, async () => goodAi), "u2", phoneInput(rid));
    assert.equal(other.quotaCharged, true);
    assert.equal(usage(db, "u2"), 1);
    // Same user, same id, different content -> conflict, no charge, no foreign result.
    await assert.rejects(svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput(rid, "úplně jiný text")),
      (e) => e.reason === "request_id_reused");
    assert.equal(usage(db, "u1"), 1);
  });

  test("provider timeout refunds exactly once and the same id can be retried (one charge in total)", async () => {
    const db = freshDb(() => NOW);
    const rid = "req-timeout-000000001";
    await assert.rejects(svc.analyzeContent(deps(db, () => new Promise(() => {})), "u1", phoneInput(rid)),
      (e) => e.name === "AnalysisUnavailableError" && e.reason === "provider_timeout");
    assert.equal(usage(db, "u1"), 0);
    const ok = await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput(rid));
    assert.equal(ok.quotaCharged, true);
    assert.equal(usage(db, "u1"), 1);
  });

  test("provider 429 is a provider limit (not the user's), refunded, with Retry-After", async () => {
    const db = freshDb(() => NOW);
    const gen = async () => { throw Object.assign(new Error("OpenAI API failed (HTTP 429)"), { providerStatus: 429, retryAfterSeconds: 20 }); };
    let err;
    await svc.analyzeContent(deps(db, gen), "u1", phoneInput("req-provider-429-0001")).catch((e) => { err = e; });
    assert.equal(err.reason, "provider_rate_limited");
    assert.equal(usage(db, "u1"), 0);
    const res = errorResponse(err);
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "20");
    assert.equal((await res.json()).error.reason, "provider_rate_limited");
  });

  test("crash between reservation and completion: a resend takes over the reservation without a second charge", async () => {
    const db = freshDb(() => NOW);
    const rid = "req-crash-00000000001";
    const input = phoneInput(rid);
    // Simulate a killed invocation: reservation written, nothing else.
    const r = await ledger.reserve(db, "u1", input, NOW);
    assert.equal(r.kind, "reserved");
    assert.equal(usage(db, "u1"), 1);
    // Before the stale window the resend is told to wait.
    await assert.rejects(svc.analyzeContent(deps(db, async () => goodAi, { now: () => NOW + 10_000 }), "u1", input), (e) => e.reason === "request_in_progress");
    // After it, the reservation is reused.
    const later = NOW + ledger.PENDING_STALE_MS + 1000;
    const ok = await svc.analyzeContent(deps(db, async () => goodAi, { now: () => later }), "u1", input);
    assert.equal(ok.quotaCharged, true);
    assert.equal(usage(db, "u1"), 1, "still one credit");
  });

  test("sweeper refunds abandoned reservations once and leaves fresh/completed ones alone", async () => {
    const db = freshDb(() => NOW);
    await ledger.reserve(db, "u1", phoneInput("req-abandoned-0000001"), NOW);
    await ledger.reserve(db, "u1", phoneInput("req-fresh-00000000001"), NOW + ledger.SWEEP_AFTER_MS);
    await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput("req-done-000000000001"));
    assert.equal(usage(db, "u1"), 3);
    const t = NOW + ledger.SWEEP_AFTER_MS + 1000;
    assert.deepEqual(await ledger.sweepAbandoned(db, t, { logger: silentLogger }), { abandonedRefunded: 1 });
    assert.equal(usage(db, "u1"), 2);
    assert.deepEqual(await ledger.sweepAbandoned(db, t, { logger: silentLogger }), { abandonedRefunded: 0 }, "idempotent");
    assert.equal(usage(db, "u1"), 2);
  });

  test("refund never double-refunds a record that completed meanwhile (cancel/complete race)", async () => {
    const db = freshDb(() => NOW);
    const input = phoneInput("req-race-000000000001");
    const res = await ledger.reserve(db, "u1", input, NOW);
    await ledger.complete(res, { resultCategory: "HIGH_RISK" }, NOW, silentLogger);
    assert.equal(await ledger.refund(db, res, NOW, "cancelled", silentLogger), false);
    assert.equal(usage(db, "u1"), 1);
  });

  test("quota exhaustion is reported with the authoritative counter and never charges", async () => {
    const db = freshDb(() => NOW);
    await seedUsage(db, "u1", 5);
    const r = await svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput("req-exhausted-000001"));
    assert.deepEqual([r.quotaExhausted, r.quotaCharged, r.deepAnalysesUsed, r.monthlyLimit], [true, false, 5, 5]);
    assert.equal(usage(db, "u1"), 5);
  });

  test("20 concurrent DIFFERENT intentional analyses never exceed the free limit", async () => {
    const db = freshDb(() => NOW);
    const results = await Promise.allSettled(Array.from({ length: 20 }, (_, i) =>
      svc.analyzeContent(deps(db, async () => goodAi), "u1", phoneInput(`req-concurrent-${String(i).padStart(6, "0")}`))));
    assert.equal(results.filter((r) => r.status === "fulfilled" && r.value.quotaCharged).length, 5);
    assert.equal(usage(db, "u1"), 5);
  });

  test("lifecycle events are structured and contain no content, uid or requestId", async () => {
    const db = freshDb(() => NOW);
    const lines = [];
    const logger = { ...silentLogger, info: (l) => lines.push(l) };
    const text = "Tajný obsah +420777123456";
    await svc.analyzeContent(deps(db, async () => goodAi, { logger }), "user-secret-uid", phoneInput("req-log-0000000000001", text));
    const evts = lines.map((l) => JSON.parse(l).evt);
    assert.deepEqual(evts, ["analyze.start", "analyze.reserved", "analyze.provider_call", "analyze.completed"]);
    const all = lines.join("\n");
    for (const secret of ["Tajný", "777123456", "user-secret-uid", "req-log-0000000000001"]) assert.ok(!all.includes(secret), secret);
  });
});
