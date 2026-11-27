"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb, silentLogger } = require("../helpers/setup");
const { fs } = require("../../lib/server/bacha/fsHelpers");
const { purgeExpired } = require("../../lib/server/bacha/expiryCleanup");

const NOW = Date.parse("2026-11-27T18:00:00Z");
const ts = (ms) => fs().fromMillis(ms);

test("deletes only expired documents and never pending ledger records", async () => {
  const db = freshDb();
  await db.collection("analysisRequests").doc("old-done").set({ status: "done", expiresAt: ts(NOW - 1000) });
  await db.collection("analysisRequests").doc("old-pending").set({ status: "pending", expiresAt: ts(NOW - 1000) });
  await db.collection("analysisRequests").doc("fresh").set({ status: "done", expiresAt: ts(NOW + 3600e3) });
  await db.collection("authSessions").doc("s-old").set({ expiresAt: ts(NOW - 1) });
  await db.collection("authSessions").doc("s-new").set({ expiresAt: ts(NOW + 1) });
  await db.collection("rateLimits").doc("r-old").set({ expiresAt: ts(NOW - 5) });
  await db.collection("testingInterestVerifications").doc("i-old").set({ expiresAt: ts(NOW - 5) });
  const r = await purgeExpired(db, NOW, { logger: silentLogger });
  assert.equal(r.expiryCleanup.total, 4);
  assert.equal(db.raw("analysisRequests/old-done"), undefined);
  assert.ok(db.raw("analysisRequests/old-pending"), "pending reservations are left to the refund sweeper");
  assert.ok(db.raw("analysisRequests/fresh"));
  assert.equal(db.raw("authSessions/s-old"), undefined);
  assert.ok(db.raw("authSessions/s-new"));
  assert.equal(db.raw("rateLimits/r-old"), undefined);
  assert.equal(db.raw("testingInterestVerifications/i-old"), undefined);
});

test("respects the per-run caps (Spark quotas) and reports remaining work", async () => {
  const db = freshDb();
  for (let i = 0; i < 30; i++) await db.collection("rateLimits").doc("r" + i).set({ expiresAt: ts(NOW - 10) });
  const r = await purgeExpired(db, NOW, { logger: silentLogger, perCollection: 10, maxTotal: 12 });
  assert.equal(r.expiryCleanup.collections.rateLimits.deleted, 10);
  assert.equal(r.expiryCleanup.collections.rateLimits.more, true);
  assert.ok(r.expiryCleanup.total <= 12);
  const again = await purgeExpired(db, NOW, { logger: silentLogger, perCollection: 10, maxTotal: 12 });
  assert.equal(again.expiryCleanup.collections.rateLimits.deleted, 10, "idempotent: next run continues");
});

test("a failing collection does not stop the others", async () => {
  const db = freshDb();
  await db.collection("authSessions").doc("s").set({ expiresAt: ts(NOW - 1) });
  const orig = db.collection.bind(db);
  db.collection = (name) => (name === "analysisRequests" ? { where() { throw Object.assign(new Error("index"), { code: "failed-precondition" }); } } : orig(name));
  const r = await purgeExpired(db, NOW, { logger: silentLogger });
  assert.equal(r.expiryCleanup.collections.analysisRequests.error, "failed-precondition");
  assert.equal(r.expiryCleanup.collections.authSessions.deleted, 1);
});

test("preserves records refreshed after the expiry query and pending reservations", async () => {
  const db = freshDb();
  const session = db.collection("authSessions").doc("refresh");
  const ledger = db.collection("analysisRequests").doc("reserve");
  await session.set({ expiresAt: ts(NOW - 1000) });
  await ledger.set({ status: "done", expiresAt: ts(NOW - 1000) });
  const original = db.runTransaction.bind(db);
  let first = true;
  db.runTransaction = async (fn) => {
    if (first) {
      first = false;
      await session.set({ expiresAt: ts(NOW + 1000) });
      await ledger.set({ status: "pending", expiresAt: ts(NOW - 1000) });
    }
    return original(fn);
  };
  const r = await purgeExpired(db, NOW, { logger: silentLogger });
  assert.equal(r.expiryCleanup.total, 0);
  assert.ok(db.raw("authSessions/refresh"));
  assert.equal(db.raw("analysisRequests/reserve").status, "pending");
});

test("rechecks a session renewed between its query and transaction", async () => {
  const db = freshDb();
  const session = db.collection("authSessions").doc("refresh");
  await session.set({ expiresAt: ts(NOW - 1000) });
  const original = db.runTransaction.bind(db);
  db.runTransaction = async (fn) => {
    await session.set({ expiresAt: ts(NOW + 1000) });
    return original(fn);
  };
  const r = await purgeExpired(db, NOW, { logger: silentLogger });
  assert.equal(r.expiryCleanup.total, 0);
  assert.ok(db.raw("authSessions/refresh"));
});
