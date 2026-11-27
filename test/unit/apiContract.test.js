"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { errorResponse } = require("../../lib/server/bacha/authCore");

test("versioned HTTP contract exposes every migrated operation", () => {
  const source = fs.readFileSync(path.join(__dirname, "../../lib/server/bacha/httpApi.ts"), "utf8");
  for (const route of [
    'path === "analyze"', 'path === "threats/lookup"', 'path === "threats/report"',
    'path === "threats/dispute"', 'path === "threats/watch"', 'path === "threats/watches"',
    'path === "billing/verify"', 'path === "account"', 'path === "admin/threats/moderate"',
    'path === "admin/disputes/resolve"', 'devices\\/',
  ]) assert.ok(source.includes(route), `missing API route ${route}`);
  assert.match(source, /handleRtdn/);
  assert.match(source, /handleCron/);
});

test("sensitive route responses set no-store and REST errors are consistent", () => {
  const source = fs.readFileSync(path.join(__dirname, "../../lib/server/bacha/authCore.js"), "utf8");
  assert.match(source, /Cache-Control.*no-store/);
  // Behavioural contract (was a source regex): every error body has ok=false and
  // error.code + error.message; Phase 5 only ADDS optional reason / retryAfterSeconds.
  assert.match(source, /ok: false, error: \{ code, message/);
});

test("error reasons and Retry-After are optional, machine-readable extensions (Phase 5)", async () => {
  const { RateLimitError } = require("../../lib/server/bacha/rateLimit");
  const r = errorResponse(new RateLimitError("analyzeContent", { scope: "user", retryAfterSeconds: 42 }));
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), "42");
  const b = await r.json();
  assert.deepEqual([b.error.code, b.error.reason, b.error.retryAfterSeconds], ["resource-exhausted", "user_rate_limited", 42]);
  assert.equal(typeof b.error.message, "string");
  const ip = await errorResponse(new RateLimitError("analyze", { scope: "ip", retryAfterSeconds: 5 })).json();
  assert.equal(ip.error.reason, "ip_rate_limited");
  const plain = errorResponse(Object.assign(new Error("x"), { code: "unauthenticated" }));
  assert.equal(plain.headers.get("retry-after"), null);
  assert.deepEqual(Object.keys((await plain.json()).error), ["code", "message"]);
});

test("maps legacy backend error codes to the REST status contract", async () => {
  for (const [code, status] of [
    ["unauthenticated", 401], ["permission-denied", 403], ["invalid-argument", 400],
    ["resource-exhausted", 429], ["already-exists", 409], ["failed-precondition", 412],
    ["unavailable", 503], ["internal", 500],
  ]) {
    const response = errorResponse(Object.assign(new Error("safe message"), { code }));
    assert.equal(response.status, status);
    assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
    const body = await response.json();
    assert.deepEqual(Object.keys(body), ["ok", "error"]);
    assert.equal(body.ok, false);
    assert.equal(body.error.code, code);
  }
});
