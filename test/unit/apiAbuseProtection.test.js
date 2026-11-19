"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb } = require("../helpers/setup");
const {
  IP_RATE_POLICIES, apiIpPolicy, trustedVercelClientIp, betaAccessAllowed,
  enforceBetaAccess, ipRateKey, enforceApiIpRateLimit
} = require("../../lib/server/bacha/apiAbuseProtection");

const SECRET = "offline-ip-quota-secret-0123456789abcdef";
const PROD = { NODE_ENV: "production", VERCEL: "1", THREAT_INTEL_HMAC_SECRET: SECRET };
const NOW = Date.parse("2026-11-19T22:00:00Z");

function request(ip = "203.0.113.7", spoofedIp = "192.0.2.1") {
  const headers = new Headers();
  if (ip !== null) headers.set("x-forwarded-for", ip);
  headers.set("x-real-ip", spoofedIp);
  headers.set("client-ip", spoofedIp);
  return { headers };
}

test("only a known, authenticated route gets an IP quota; Auth signups bypass this backend", () => {
  assert.equal(apiIpPolicy("PUT", "devices/install-1"), "deviceWrite");
  assert.equal(apiIpPolicy("PATCH", "devices/install-1"), "deviceWrite");
  assert.equal(apiIpPolicy("DELETE", "devices/install-1"), "deviceDelete");
  assert.equal(apiIpPolicy("POST", "analyze"), "analyze");
  assert.equal(apiIpPolicy("GET", "threats/watches"), "watchRead");
  assert.equal(apiIpPolicy("POST", "billing/verify"), "billingVerify");
  assert.equal(apiIpPolicy("DELETE", "account"), null);
  assert.equal(apiIpPolicy("PUT", "devices/../escape"), null);
  assert.equal(apiIpPolicy("POST", "auth/signup"), null);
});

test("accept only validated Vercel-controlled client address, ignore spoofable alternatives", () => {
  assert.equal(trustedVercelClientIp(request().headers, PROD), "203.0.113.7");
  assert.equal(trustedVercelClientIp(request("2001:db8::abcd").headers, PROD), "2001:db8::abcd");
  assert.equal(trustedVercelClientIp(request("203.0.113.7, 10.0.0.1").headers, PROD), "203.0.113.7");
  assert.equal(trustedVercelClientIp(request("not-an-ip").headers, PROD), null);
  assert.equal(trustedVercelClientIp(request(null).headers, PROD), null);
  assert.equal(trustedVercelClientIp(request().headers, { VERCEL: "0" }), null);
});

test("rate-limit document IDs never contain raw IPs and differ by action and IP", () => {
  const a = ipRateKey(SECRET, "203.0.113.7", "deviceWrite", 1);
  const b = ipRateKey(SECRET, "203.0.113.7", "deviceWrite", 2);
  const c = ipRateKey(SECRET, "203.0.113.8", "deviceWrite", 1);
  assert.notEqual(a, b);
  assert.notEqual(a, c);
  assert.equal(a.includes("203.0.113"), false);
  assert.match(a, /^ip_v1_deviceWrite_[0-9a-f]{64}_1$/);
});

test("shared IP quota blocks many distinct UIDs, isolates other IPs and resets next window", async () => {
  const db = freshDb(() => NOW);
  const userA = request("198.51.100.11");
  const userB = request("198.51.100.12");
  const limit = IP_RATE_POLICIES.deviceWrite.limit;
  for (let n = 0; n < limit; n++) {
    await enforceApiIpRateLimit(db, userA, "PUT", "devices/device-" + n, PROD, NOW);
  }
  await assert.rejects(
    enforceApiIpRateLimit(db, userA, "PUT", "devices/device-x", PROD, NOW),
    (err) => err.name === "RateLimitError"
  );
  await enforceApiIpRateLimit(db, userB, "PUT", "devices/device-x", PROD, NOW);
  await enforceApiIpRateLimit(
    db, userA, "PUT", "devices/device-x", PROD,
    NOW + IP_RATE_POLICIES.deviceWrite.windowSeconds * 1000
  );
  for (const [key, value] of db.store) {
    assert.equal(key.includes("198.51."), false);
    assert.equal(JSON.stringify(value).includes("198.51."), false);
    assert.ok(value.expiresAt, "TTL field is required");
  }
});

test("fail closed when trusted source IP or HMAC secret is missing", async () => {
  const db = freshDb();
  await assert.rejects(
    enforceApiIpRateLimit(db, request(null), "PUT", "devices/device-1", PROD, NOW),
    (err) => err.status === 503
  );
  await assert.rejects(
    enforceApiIpRateLimit(db, request(), "PUT", "devices/device-1", { NODE_ENV: "production", VERCEL: "1" }, NOW),
    /THREAT_INTEL_HMAC_SECRET/
  );
  await assert.rejects(
    enforceApiIpRateLimit(db, request(), "PUT", "devices/device-1", { NODE_ENV: "production", VERCEL: "0" }, NOW),
    (err) => err.status === 503
  );
});

test("closed beta optional allowlist permits known users but always permits deletion", () => {
  const env = { BACHA_BETA_ALLOWED_UIDS: "owner-uid, tester-2" };
  assert.equal(betaAccessAllowed("owner-uid", env), true);
  assert.equal(betaAccessAllowed("random-uid", env), false);
  assert.equal(betaAccessAllowed("random-uid", {}), true);
  assert.throws(
    () => enforceBetaAccess("random-uid", "POST", "analyze", env),
    (err) => err.status === 403 && err.code === "permission-denied"
  );
  assert.doesNotThrow(() => enforceBetaAccess("owner-uid", "POST", "analyze", env));
  assert.doesNotThrow(() => enforceBetaAccess("random-uid", "DELETE", "account", env));
  assert.doesNotThrow(() => enforceBetaAccess("random-uid", "DELETE", "devices/device-1", env));
});
