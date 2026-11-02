"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb } = require("../helpers/setup");
const { deleteAllUserData } = require("../../lib/server/bacha/accountDeletion");

async function seed(db, uid) {
  const u = db.collection("users").doc(uid);
  await u.set({ email: "a@b.cz", displayName: "A" });
  await u.collection("devices").doc("d1").set({ fcmToken: "t" });
  await u.collection("usage").doc("2026-11").set({ deepAnalysisCount: 3 });
  await u.collection("entitlement").doc("current").set({ tier: "PLUS" });
  await db.collection("purchases").doc("h1").set({ userId: uid });
  await db.collection("threatWatches").doc(`${uid}_k`).set({ uid, lookupKey: "k" });
  await db.collection("userReports").doc(`${uid}_k`).set({ uid, lookupKey: "k" });
  await db.collection("rateLimits").doc(`${uid}_x_1`).set({ uid });
  await db.collection("threatDisputes").doc(`${uid}_p`).set({ submittedByUid: uid, status: "PENDING", reason: "secret" });
  await db.collection("threatDisputes").doc(`${uid}_r`).set({ submittedByUid: uid, status: "REJECTED", reason: "secret" });
}

describe("deleteAllUserData", () => {
  test("removes every UID-linked record and the auth user", async () => {
    const db = freshDb();
    await seed(db, "victim");
    await seed(db, "other");
    const deleted = [];
    const res = await deleteAllUserData({ db, auth: { deleteUser: async (uid) => deleted.push(uid) } }, "victim");
    assert.equal(res.success, true);
    assert.equal(res.authDeleted, true);
    assert.deepEqual(deleted, ["victim"]);
    const remaining = [...db.store.entries()].filter(([path, data]) => path.includes("victim") || JSON.stringify(data).includes("victim"));
    // only anonymised resolved dispute remains (doc id keeps the hash-free prefix, data no longer has uid)
    assert.deepEqual(remaining.map(([p]) => p), ["threatDisputes/victim_r"]);
    const anon = db.raw("threatDisputes/victim_r");
    assert.equal(anon.submittedByUid, null);
    assert.equal(anon.reason.includes("secret"), false);
    // other user untouched
    assert.ok(db.raw("users/other"));
    assert.ok(db.raw("purchases/h1"));
  });

  test("failure in any step propagates (no false success)", async () => {
    const db = freshDb();
    await seed(db, "victim");
    db.failOn = (op, path) => (op === "delete" && path.startsWith("threatWatches") ? new Error("boom") : null);
    await assert.rejects(deleteAllUserData({ db, auth: { deleteUser: async () => {} } }, "victim"), /boom/);
  });

  test("auth deletion failure propagates", async () => {
    const db = freshDb();
    await assert.rejects(deleteAllUserData({ db, auth: { deleteUser: async () => { throw Object.assign(new Error("x"), { code: "auth/internal-error" }); } } }, "u"));
  });

  test("already deleted auth user is treated as deleted", async () => {
    const db = freshDb();
    const r = await deleteAllUserData({ db, auth: { deleteUser: async () => { throw Object.assign(new Error("x"), { code: "auth/user-not-found" }); } } }, "u");
    assert.equal(r.authDeleted, true);
  });
});
