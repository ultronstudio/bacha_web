"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb } = require("../helpers/setup");
const {
  ACCESS_MS, REFRESH_MS, allowedEmail, findOrCreateUser, createSession,
  verifySession, rotateSession, revokeSession, parseCredential,
} = require("../../lib/server/bacha/serverSessions");
const { handleAuthHttp } = require("../../lib/server/bacha/authHttp");
const { limitAuthIp } = require("../../lib/server/bacha/authIpGuard");

const now = Date.parse("2026-11-19T12:00:00Z");
const env = {
  THREAT_INTEL_HMAC_SECRET: "unit-test-only-secret-0123456789abc-0123456789abc",
  BACHA_AUTH_MODE: "closed",
  BACHA_AUTH_ALLOWED_GOOGLE_EMAILS: "owner@gmail.com,tester@gmail.com",
  NODE_ENV: "test",
};
const good = {
  sub: "109876543210123456789",
  email: "owner@gmail.com",
  email_verified: true,
  name: "Owner",
  picture: "https://example.test/avatar.png",
};
const fakeAuth = (legacyUid = null) => ({
  async getUserByProviderUid(provider, sub) {
    assert.equal(provider, "google.com");
    assert.equal(sub, good.sub);
    if (legacyUid) return { uid: legacyUid };
    throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
  },
});

test("closed beta accepts only exact Google emails; no fuzzy-domain bypass", () => {
  assert.equal(allowedEmail("owner@gmail.com", env), true);
  assert.equal(allowedEmail("OWNER@GMAIL.COM", env), true);
  assert.equal(allowedEmail("owner@gmail.com.evil.net", env), false);
  assert.equal(allowedEmail("stranger@gmail.com", env), false);
  assert.equal(allowedEmail("owner@gmail.com", { BACHA_AUTH_MODE: "closed" }), false);
  assert.equal(allowedEmail("stranger@gmail.com", { BACHA_AUTH_MODE: "open" }), true);
  assert.equal(allowedEmail("owner@gmail.com", { BACHA_AUTH_MODE: "typo" }), false);
});

test("login creates server-only user, not Firebase Auth account; re-login stable UID", async () => {
  const db = freshDb(() => now);
  const user = await findOrCreateUser(db, fakeAuth(), good, env, now);
  assert.match(user.uid, /^b_[0-9a-f]{48}$/);
  assert.equal(db.raw(`users/${user.uid}`).email, good.email);
  assert.equal(user.isAnonymous, false);
  const same = await findOrCreateUser(db, fakeAuth(), good, env, now + 5000);
  assert.equal(same.uid, user.uid);
  assert.equal([...db.store.keys()].filter(k => k.startsWith("authIdentities/")).length, 1);
});

test("legacy Google provider UID maps to existing Firebase UID and preserves data", async () => {
  const db = freshDb(() => now);
  await db.collection("users").doc("legacy-firebase-uid").collection("entitlement").doc("current").set({ tier: "PLUS", status: "PLUS_ACTIVE" });
  const user = await findOrCreateUser(db, fakeAuth("legacy-firebase-uid"), good, env, now);
  assert.equal(user.uid, "legacy-firebase-uid");
  assert.equal(db.raw("users/legacy-firebase-uid/entitlement/current").tier, "PLUS");
});

test("unapproved identity never writes profile/session even with valid Google claims", async () => {
  const db = freshDb(() => now);
  await assert.rejects(
    findOrCreateUser(db, fakeAuth(), { ...good, email: "unapproved@gmail.com" }, env, now),
    (err) => err.status === 403
  );
  for (const claim of [{ ...good, email_verified: false }, { ...good, sub: "attacker/123" }]) {
    await assert.rejects(findOrCreateUser(db, fakeAuth(), claim, env, now), (err) => err.status === 401);
  }
  assert.equal(db.store.size, 0);
});

test("opaque access/refresh credentials rotate atomically and reject replay", async () => {
  const db = freshDb(() => now);
  const pair = await createSession(db, { uid: "legacy-uid", email: "owner@gmail.com" }, "app/123", now);
  assert.match(pair.accessToken, /^ba_a_/);
  assert.match(pair.refreshToken, /^ba_r_/);
  assert.equal(parseCredential(pair.accessToken, "r"), null);
  assert.equal((await verifySession(db, pair.accessToken, "app/123", env, now)).uid, "legacy-uid");
  assert.equal(await verifySession(db, pair.accessToken, "other-app", env, now), null);
  assert.equal(await verifySession(db, pair.accessToken, "app/123", env, now + ACCESS_MS + 1), null);
  const next = await rotateSession(db, pair.refreshToken, "app/123", env, now + ACCESS_MS + 2);
  assert.equal(await verifySession(db, pair.accessToken, "app/123", env, now + ACCESS_MS + 3), null);
  assert.equal((await verifySession(db, next.accessToken, "app/123", env, now + ACCESS_MS + 3)).uid, "legacy-uid");
  await assert.rejects(rotateSession(db, pair.refreshToken, "app/123", env, now + ACCESS_MS + 4), (err) => err.status === 401);
  assert.equal(next.refreshExpiresAtMillis, now + REFRESH_MS);
  assert.equal(await revokeSession(db, next.accessToken, "app/123"), true);
  assert.equal(await verifySession(db, next.accessToken, "app/123", env, now + ACCESS_MS + 4), null);
});

test("concurrent refresh requests are single use", async () => {
  const db = freshDb(() => now);
  const pair = await createSession(db, { uid: "uid", email: "owner@gmail.com" }, "app", now);
  const attempts = await Promise.allSettled([
    rotateSession(db, pair.refreshToken, "app", env, now + 1),
    rotateSession(db, pair.refreshToken, "app", env, now + 1),
  ]);
  assert.equal(attempts.filter(x => x.status === "fulfilled").length, 1);
  assert.equal(attempts.filter(x => x.status === "rejected").length, 1);
});

test("auth endpoint enforces App Check, Google validation and disallows outsiders", async () => {
  const db = freshDb(() => now);
  let checks = 0;
  const deps = {
    db, env, now: () => now, auth: fakeAuth(),
    appCheck: { verifyToken: async t => { checks++; if(t !== "good-check") throw Error("bad"); return { appId: "app/123" }; } },
    verifyGoogleToken: async token => { if(token.startsWith("bad")) throw Error("invalid"); return good; },
  };
  const request = (token, check = "good-check") => new Request("https://example.invalid/api/v1/auth/google", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Firebase-AppCheck": check },
    body: JSON.stringify({ idToken: token }),
  });
  await assert.rejects(handleAuthHttp(request("some-id-token".repeat(10), "bad-check"), "auth/google", deps), (err) => err.status === 401);
  await assert.rejects(handleAuthHttp(request("bad".repeat(50)), "auth/google", deps), (err) => err.status === 401);
  const ok = await handleAuthHttp(request("good".repeat(50)), "auth/google", deps);
  assert.equal(ok.status, 200);
  const payload = await ok.json();
  assert.equal(payload.user.uid.startsWith("b_"), true);
  assert.equal(typeof payload.accessToken, "string");
  assert.equal(typeof payload.refreshToken, "string");
  assert.equal(checks, 3);
});

test("IP quotas are shared between clients and store no raw address", async () => {
  const db = freshDb(() => now);
  const ipEnv = { ...env, VERCEL: "1", NODE_ENV: "production" };
  const request = new Request("https://example.invalid", { headers: { "x-forwarded-for": "198.51.100.20" } });
  for (let n = 0; n < 20; n++) await limitAuthIp(db, request, "google", ipEnv, now);
  await assert.rejects(limitAuthIp(db, request, "google", ipEnv, now), (err) => err.name === "RateLimitError");
  assert.equal([...db.store.keys()].some(k => k.includes("198.51.100.20")), false);
});
