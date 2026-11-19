"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb } = require("../helpers/setup");
const { enforceBetaAccess, trustedVercelIp, ipRateLimitConfig, enforceApiIpRateLimit } = require("../../lib/server/bacha/apiAccessGuard");

const SECRET = "integration-test-hmac-secret-strong-01234567890123456";
const env = {
  VERCEL: "1",
  API_IP_RATE_LIMIT_ENABLED: "1",
  API_IP_RATE_LIMIT_PER_15M: "10",
  THREAT_INTEL_HMAC_SECRET: SECRET
};
const req = (ip) => ({ headers: new Headers(ip ? { "x-forwarded-for": ip } : {}) });

test("closed beta denies unknown authenticated users and fails closed without allowed UIDs", () => {
  assert.doesNotThrow(() => enforceBetaAccess({ uid: "owner" }, { BETA_ACCESS_MODE: "open" }));
  assert.doesNotThrow(() => enforceBetaAccess({ uid: "owner" }, { BETA_ACCESS_MODE: "closed", BETA_ALLOWED_UIDS: "owner,tester" }));
  assert.throws(() => enforceBetaAccess({ uid: "stranger" }, { BETA_ACCESS_MODE: "closed", BETA_ALLOWED_UIDS: "owner,tester" }), (err) => err.status === 403);
  assert.throws(() => enforceBetaAccess({ uid: "owner" }, { BETA_ACCESS_MODE: "closed", BETA_ALLOWED_UIDS: "" }), (err) => err.status === 503);
  assert.throws(() => enforceBetaAccess({ uid: "owner" }, { BETA_ACCESS_MODE: "typo" }), (err) => err.status === 503);
});

test("cannot trust caller-provided IP unless on Vercel", () => {
  assert.equal(trustedVercelIp(req("203.0.113.40"), { VERCEL: "1" }), "203.0.113.40");
  assert.equal(trustedVercelIp(req("203.0.113.40"), {}), null);
  assert.equal(trustedVercelIp(req("not-ip"), { VERCEL: "1" }), null);
  assert.equal(trustedVercelIp(req("203.0.113.40, 10.0.0.2"), { VERCEL: "1" }), "203.0.113.40");
});

test("per-IP transaction enforces 10 requests per window across UIDs and never stores plain IP", async () => {
  const db = freshDb();
  const t = Date.parse("2026-11-19T20:00:00.000Z");
  for (let i = 0; i < 10; i++) {
    await enforceApiIpRateLimit(db, req("198.51.100.5"), env, t);
  }
  await assert.rejects(
    enforceApiIpRateLimit(db, req("198.51.100.5"), env, t),
    (err) => err.name === "RateLimitError"
  );
  await enforceApiIpRateLimit(db, req("198.51.100.6"), env, t);
  await enforceApiIpRateLimit(db, req("198.51.100.5"), env, t + 15 * 60 * 1000);
  for (const [path, data] of db.store.entries()) {
    assert.equal(path.includes("198.51.100."), false);
    assert.equal(JSON.stringify(data).includes("198.51.100."), false);
  }
});

test("invalid IP or secret fails safely, and disabled guard does nothing", async () => {
  const db = freshDb();
  await enforceApiIpRateLimit(db, req(), { API_IP_RATE_LIMIT_ENABLED: "0" });
  await assert.rejects(enforceApiIpRateLimit(db, req(), env), (err) => err.status === 503);
  assert.throws(() => ipRateLimitConfig({ API_IP_RATE_LIMIT_ENABLED: "1", API_IP_RATE_LIMIT_PER_15M: "abc" }), (err) => err.status === 503);
});
