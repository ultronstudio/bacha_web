"use strict";
const { test, before, after } = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { initializeTestEnvironment, assertFails } = require("@firebase/rules-unit-testing");
const {
  doc, getDoc, setDoc, deleteDoc, collection, getDocs,
} = require("firebase/firestore");

let env;
before(async () => {
  env = await initializeTestEnvironment({
    projectId: "demo-bacha-backend-only",
    firestore: {
      rules: fs.readFileSync(path.resolve(__dirname, "../../firestore/backend-only.rules"), "utf8"),
    },
  });
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, "users/owner"), { accountKind: "google" });
    await setDoc(doc(db, "users/owner/entitlement/current"), { tier: "PLUS" });
    await setDoc(doc(db, "users/owner/devices/d1"), { fcmToken: "fake" });
    await setDoc(doc(db, "authSessions/session"), { uid: "owner" });
  });
});
after(async () => { if (env) await env.cleanup(); });

test("post-migration policy rejects ALL Firebase SDK client reads and writes, even owner", async () => {
  const authenticated = env.authenticatedContext("owner").firestore();
  const paths = [
    "users/owner", "users/owner/entitlement/current",
    "users/owner/usage/2026-11", "users/owner/devices/d1",
    "authSessions/session", "authIdentities/mapping",
    "rateLimits/window", "purchases/token", "threatIndicators/any",
  ];
  for (const id of paths) {
    await assertFails(getDoc(doc(authenticated, id)));
    await assertFails(setDoc(doc(authenticated, id), { tampered: true }));
    await assertFails(deleteDoc(doc(authenticated, id)));
  }
  await assertFails(getDocs(collection(authenticated, "users")));
  await assertFails(getDocs(collection(authenticated, "authSessions")));
  await assertFails(getDoc(doc(env.unauthenticatedContext().firestore(), "users/owner")));
  assert.equal(paths.length, 9);
});
