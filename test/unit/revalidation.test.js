"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb, FakeTimestamp, silentLogger } = require("../helpers/setup");
const ti = require("../../lib/server/bacha/threatIntel");
const indexes = require("../../firestore/firestore.indexes.json");

const NOW = Date.parse("2026-11-27T02:17:00Z");

async function seed(db, id, data) {
  await db.collection("threatIndicators").doc(id).set({ active: true, ...data });
}

test("composite index for the daily revalidation stays versioned", () => {
  const idx = indexes.indexes.find((i) => i.collectionGroup === "threatIndicators");
  assert.deepEqual(idx.fields.map((f) => [f.fieldPath, f.order]), [["active", "ASCENDING"], ["expiresAt", "ASCENDING"]]);
  assert.equal(idx.queryScope, "COLLECTION");
});

test("expired indicators become INACTIVE; KNOWN_SAFE and fresh ones untouched", async () => {
  const db = freshDb(() => NOW);
  await seed(db, "a", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW - 1000) });
  await seed(db, "b", { verdict: "KNOWN_SAFE", expiresAt: new FakeTimestamp(NOW - 1000) });
  await seed(db, "c", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW + 86400000) });
  const r = await ti.revalidateExpiredIndicators(db, { logger: silentLogger });
  assert.equal(r.expiredCount, 1);
  assert.equal(r.usedIndexFallback, false);
  assert.equal(db.raw("threatIndicators/a").verdict, "INACTIVE");
  assert.equal(db.raw("threatIndicators/b").verdict, "KNOWN_SAFE");
  assert.equal(db.raw("threatIndicators/c").active, true);
});

test("many expired KNOWN_SAFE records no longer starve other expired indicators", async () => {
  const db = freshDb(() => NOW);
  for (let i = 0; i < 250; i++) await seed(db, `a_safe_${String(i).padStart(3, "0")}`, { verdict: "KNOWN_SAFE", expiresAt: new FakeTimestamp(NOW - 1000) });
  await seed(db, "z_bad", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW - 1000) });
  const r = await ti.revalidateExpiredIndicators(db, { logger: silentLogger });
  assert.equal(r.expiredCount, 1);
  assert.equal(db.raw("threatIndicators/z_bad").verdict, "INACTIVE");
});

test("missing composite index (FAILED_PRECONDITION) falls back instead of failing the cron", async () => {
  const db = freshDb(() => NOW);
  await seed(db, "a", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW - 1000) });
  await seed(db, "c", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW + 1000) });
  db.queryHook = (q) => {
    if (q.path === "threatIndicators" && q.filters.length > 1) {
      const e = new Error("9 FAILED_PRECONDITION: The query requires an index."); e.code = 9; throw e;
    }
  };
  const warnings = [];
  const r = await ti.revalidateExpiredIndicators(db, { logger: { ...silentLogger, warn: (m) => warnings.push(m) } });
  assert.equal(r.usedIndexFallback, true);
  assert.equal(r.expiredCount, 1);
  assert.equal(db.raw("threatIndicators/a").verdict, "INACTIVE");
  assert.equal(db.raw("threatIndicators/c").active, true);
  assert.match(warnings[0], /index missing/);
});

test("other Firestore errors are not swallowed", async () => {
  const db = freshDb(() => NOW);
  await seed(db, "a", { verdict: "SUSPICIOUS", expiresAt: new FakeTimestamp(NOW - 1000) });
  db.queryHook = () => { const e = new Error("14 UNAVAILABLE"); e.code = 14; throw e; };
  await assert.rejects(ti.revalidateExpiredIndicators(db, { logger: silentLogger }), /UNAVAILABLE/);
});
