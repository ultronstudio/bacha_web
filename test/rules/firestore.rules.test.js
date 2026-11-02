"use strict";
/**
 * Firestore security rules tests – run against the Firestore emulator:
 *   npm run test:rules   (wraps `firebase emulators:exec`)
 */
const { test, describe, before, after, beforeEach } = require("node:test");
const fs = require("fs");
const path = require("path");
const { initializeTestEnvironment, assertFails, assertSucceeds } = require("@firebase/rules-unit-testing");
const { doc, getDoc, setDoc, updateDoc, deleteDoc, collection, getDocs, query, where } = require("firebase/firestore");

let env;

before(async () => {
  env = await initializeTestEnvironment({
    projectId: "demo-bacha",
    firestore: { rules: fs.readFileSync(path.join(__dirname, "../../firestore/firestore.rules"), "utf8") },
  });
});

after(async () => {
  if (env) await env.cleanup();
});

beforeEach(async () => {
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, "users/alice"), { accountKind: "anonymous" });
    await setDoc(doc(db, "users/alice/entitlement/current"), { tier: "FREE", status: "FREE" });
    await setDoc(doc(db, "users/alice/usage/2026-11"), { deepAnalysisCount: 2 });
    await setDoc(doc(db, "threatIndicators/" + "a".repeat(64)), { verdict: "SUSPICIOUS" });
    await setDoc(doc(db, "threatWatches/alice_k"), { uid: "alice", lookupKey: "k" });
    await setDoc(doc(db, "threatWatches/bob_k"), { uid: "bob", lookupKey: "k" });
    await setDoc(doc(db, "purchases/h"), { userId: "alice" });
  });
});

const alice = () => env.authenticatedContext("alice").firestore();
const bob = () => env.authenticatedContext("bob").firestore();
const anon = () => env.unauthenticatedContext().firestore();

describe("user profile", () => {
  test("owner can create/update allowed profile fields", async () => {
    await assertSucceeds(setDoc(doc(alice(), "users/alice"), { accountKind: "google", email: "a@b.cz", displayName: "A" }, { merge: true }));
  });
  test("new user can create own profile", async () => {
    await assertSucceeds(setDoc(doc(bob(), "users/bob"), { accountKind: "anonymous" }));
  });
  test("cannot forge entitlement fields on profile", async () => {
    await assertFails(setDoc(doc(alice(), "users/alice"), { tier: "PLUS" }, { merge: true }));
    await assertFails(updateDoc(doc(alice(), "users/alice"), { isPlusActive: true }));
  });
  test("other users cannot read or write", async () => {
    await assertFails(getDoc(doc(bob(), "users/alice")));
    await assertFails(setDoc(doc(bob(), "users/alice"), { accountKind: "google" }, { merge: true }));
  });
  test("client cannot delete profile directly (server deletion flow)", async () => {
    await assertFails(deleteDoc(doc(alice(), "users/alice")));
  });
});

describe("server-authoritative entitlement & usage", () => {
  test("owner can read", async () => {
    await assertSucceeds(getDoc(doc(alice(), "users/alice/entitlement/current")));
    await assertSucceeds(getDoc(doc(alice(), "users/alice/usage/2026-11")));
  });
  test("owner cannot write entitlement", async () => {
    await assertFails(setDoc(doc(alice(), "users/alice/entitlement/current"), { tier: "PLUS", status: "PLUS_ACTIVE" }));
    await assertFails(deleteDoc(doc(alice(), "users/alice/entitlement/current")));
  });
  test("owner cannot reset usage", async () => {
    await assertFails(setDoc(doc(alice(), "users/alice/usage/2026-11"), { deepAnalysisCount: 0 }));
    await assertFails(deleteDoc(doc(alice(), "users/alice/usage/2026-11")));
  });
  test("others cannot read", async () => {
    await assertFails(getDoc(doc(bob(), "users/alice/entitlement/current")));
  });
});

describe("devices", () => {
  test("owner can read devices but writes are server-only", async () => {
    await env.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc("users/alice/devices/d1").set({ fcmToken: "t", notificationsEnabled: true, permissionGranted: true });
    });
    await assertSucceeds(getDoc(doc(alice(), "users/alice/devices/d1")));
    await assertFails(setDoc(doc(alice(), "users/alice/devices/d2"), { fcmToken: "t" }));
    await assertFails(updateDoc(doc(alice(), "users/alice/devices/d1"), { notificationsEnabled: false }));
    await assertFails(deleteDoc(doc(alice(), "users/alice/devices/d1")));
  });
});

describe("threat intelligence & reports", () => {
  test("threat indicators not readable directly (no enumeration)", async () => {
    await assertFails(getDoc(doc(alice(), "threatIndicators/" + "a".repeat(64))));
    await assertFails(getDocs(collection(anon(), "threatIndicators")));
  });
  test("clients cannot write verdicts, reports or disputes", async () => {
    await assertFails(setDoc(doc(alice(), "threatIndicators/" + "b".repeat(64)), { verdict: "CONFIRMED_MALICIOUS" }));
    await assertFails(setDoc(doc(alice(), "userReports/x"), { uid: "alice" }));
    await assertFails(setDoc(doc(alice(), "threatDisputes/x"), { status: "UPHELD" }));
    await assertFails(setDoc(doc(alice(), "indicatorHistory/x"), {}));
  });
  test("user reads only own watches", async () => {
    await assertSucceeds(getDocs(query(collection(alice(), "threatWatches"), where("uid", "==", "alice"))));
    await assertFails(getDoc(doc(alice(), "threatWatches/bob_k")));
    await assertFails(getDocs(collection(alice(), "threatWatches")));
  });
  test("purchases & rate limits are server-only", async () => {
    await assertFails(getDoc(doc(alice(), "purchases/h")));
    await assertFails(setDoc(doc(alice(), "rateLimits/alice_x"), { count: 0 }));
  });
});
