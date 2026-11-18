"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
require("../helpers/setup");
const { requireIdentityWith, requireAdmin, requireRegisteredForAnalysis, ApiError } = require("../../lib/server/bacha/authCore");
const { enforceRateLimit, RateLimitError, RATE_LIMITS } = require("../../lib/server/bacha/rateLimit");
const { freshDb } = require("../helpers/setup");

const validIdentity = { uid: "user-1", admin: false };

describe("REST request security", () => {
  test("requires both Firebase ID token and App Check token", async () => {
    const request = new Request("https://bacha.petrvurm.cz/api/v1/analyze");
    await assert.rejects(requireIdentityWith(request, { verifyIdToken: async () => validIdentity }, { verifyToken: async () => ({}) }), (e) => e instanceof ApiError && e.status === 401);
  });

  test("verifies the bearer ID token and App Check token", async () => {
    const seen = [];
    const request = new Request("https://bacha.petrvurm.cz/api/v1/analyze", {
      headers: { Authorization: "Bearer id-token", "X-Firebase-AppCheck": "app-token" },
    });
    const result = await requireIdentityWith(request, {
      verifyIdToken: async (token, revoked) => { seen.push([token, revoked]); return validIdentity; },
    }, { verifyToken: async (token) => { seen.push(token); return {}; } });
    assert.equal(result.uid, "user-1");
    assert.deepEqual(seen, [["id-token", true], "app-token"]);
  });

  test("rejects invalid Auth or App Check tokens", async () => {
    const request = new Request("https://bacha.petrvurm.cz/api/v1/analyze", {
      headers: { Authorization: "Bearer id-token", "X-Firebase-AppCheck": "app-token" },
    });
    await assert.rejects(requireIdentityWith(request, { verifyIdToken: async () => { throw new Error("invalid"); } }, { verifyToken: async () => ({}) }), (e) => e.status === 401);
    await assert.rejects(requireIdentityWith(request, { verifyIdToken: async () => validIdentity }, { verifyToken: async () => { throw new Error("invalid"); } }), (e) => e.status === 401);
  });

  test("anonymous Firebase user cannot invoke advanced analysis", () => {
    for (const identity of [null, {}, { uid: "u", firebase: { sign_in_provider: "anonymous" } }]) {
      assert.throws(() => requireRegisteredForAnalysis(identity), e => e instanceof ApiError && e.status === 403);
    }
    for (const provider of ["google.com", "password", "apple.com"]) {
      assert.equal(requireRegisteredForAnalysis({ uid: "u", firebase: { sign_in_provider: provider } }).uid, "u");
    }
  });

  test("analyze route checks registered sign-in before quota", () => {
    const src = require("node:fs").readFileSync(require("node:path").join(__dirname, "../../lib/server/bacha/httpApi.ts"), "utf8");
    const route = src.slice(src.indexOf('if (path === "analyze"'));
    assert.ok(route.indexOf("requireRegisteredForAnalysis(identity)") < route.indexOf('enforceRateLimit(firestore, uid, "analyzeContent")'));
  });

  test("admin operations require the verified admin custom claim", () => {
    assert.throws(() => requireAdmin(validIdentity), (e) => e.status === 403);
    assert.doesNotThrow(() => requireAdmin({ ...validIdentity, admin: true }));
  });
});

describe("rate limiting", () => {
  test("uses transaction-backed per-user limits", async () => {
    const db = freshDb();
    const lim = RATE_LIMITS.reportThreat.limit;
    for (let i = 0; i < lim; i++) await enforceRateLimit(db, "u", "reportThreat", 1000);
    await assert.rejects(enforceRateLimit(db, "u", "reportThreat", 1000), RateLimitError);
    await enforceRateLimit(db, "other", "reportThreat", 1000);
  });
});
