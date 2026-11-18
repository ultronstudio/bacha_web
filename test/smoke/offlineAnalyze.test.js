"use strict";

/**
 * No network requests, credentials, production databases or paid API usage.
 * Request -> mocked Firebase ID/App Check -> actual HTTP analysis orchestration
 * -> fake Firestore + actual quotas -> actual OpenAI request builder + fake HTTP
 * -> validated analysis result -> HTTP Response.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb, silentLogger } = require("../helpers/setup");
const { requireIdentityWith, errorResponse } = require("../../lib/server/bacha/authCore");
const { handleAnalyzeHttp } = require("../../lib/server/bacha/analyzeHttp");
const { generateOpenAi } = require("../../lib/server/bacha/openaiClient");
const { getCurrentPeriod } = require("../../lib/server/bacha/analysisService");

const NOW = Date.parse("2026-11-18T12:00:00.000Z");
const FAKE_KEY = "offline-smoke-test-key-NOT-REAL";
const JPG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 1, 2, 3]).toString("base64");
const AI_RESULT = {
  riskLevel: "CAUTION",
  confidence: "MEDIUM",
  summary: "Tento text obsahuje podezřelou výzvu.",
  signals: [
    { id: "urgency", title: "Časový nátlak", description: "Požaduje rychlou reakci.", severity: "CAUTION", isPositive: false },
  ],
  recommendedActions: [
    { title: "Ověřte odesílatele", description: "Kontaktujte organizaci z oficiálních stránek.", isCrucial: true },
  ],
  limitations: [],
};

// Explicit network tripwire: a test must never reach the real OpenAI API.
globalThis.fetch = async () => { throw new Error("REAL NETWORK ACCESS IS FORBIDDEN IN OFFLINE SMOKE TEST"); };

function makeHarness({ now = NOW, provider = "google.com", uid = "free-1", responseStatus = 200 } = {}) {
  const db = freshDb(() => now);
  const sent = [];
  const verifications = [];

  const firebaseAuth = {
    verifyIdToken: async (token, checkRevoked) => {
      verifications.push(["firebase", token, checkRevoked]);
      if (token !== "fake-id-token") throw new Error("invalid Firebase token");
      return { uid, firebase: { sign_in_provider: provider } };
    },
  };
  const appCheck = {
    verifyToken: async (token) => {
      verifications.push(["app-check", token]);
      if (token !== "fake-app-check") throw new Error("invalid App Check token");
      return { appId: "offline-smoke-app" };
    },
  };
  async function mockHttp(url, options) {
    assert.equal(url, "https://api.openai.com/v1/responses");
    assert.equal(options.headers.Authorization, `Bearer ${FAKE_KEY}`);
    const body = JSON.parse(options.body);
    assert.equal(body.store, false);
    assert.equal(body.text.format.strict, true);
    sent.push(body);
    return {
      ok: responseStatus === 200,
      status: responseStatus,
      json: async () => ({
        status: "completed",
        output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify(AI_RESULT) }] }],
      }),
    };
  }
  async function dispatch(payload, { authToken = "fake-id-token", appToken = "fake-app-check" } = {}) {
    const headers = { "Content-Type": "application/json" };
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    if (appToken) headers["X-Firebase-AppCheck"] = appToken;
    const request = new Request("https://localhost.invalid/api/v1/analyze", {
      method: "POST", headers, body: JSON.stringify(payload),
    });
    try {
      const identity = await requireIdentityWith(request, firebaseAuth, appCheck);
      return await handleAnalyzeHttp({
        request,
        identity,
        db,
        providers: [],
        logger: silentLogger,
        now: () => now,
        generate: (params) => generateOpenAi(params, {
          env: { OPENAI_API_KEY: FAKE_KEY },
          fetchImpl: mockHttp,
        }),
      });
    } catch (error) {
      return errorResponse(error);
    }
  }
  function usage() {
    return db.raw(`users/${uid}/usage/${getCurrentPeriod(now)}`)?.deepAnalysisCount || 0;
  }
  return { db, sent, verifications, dispatch, usage };
}

test("unauthenticated, invalid Firebase ID and invalid App Check -> HTTP 401, no AI/quota", async () => {
  const h = makeHarness();
  for (const headers of [
    { authToken: null },
    { appToken: null },
    { authToken: "bad-id-token" },
    { appToken: "bad-app-check" },
  ]) {
    const r = await h.dispatch({ text: "Test", analysisType: "TEXT_OR_URL" }, headers);
    assert.equal(r.status, 401);
    assert.equal((await r.json()).error.code, "unauthenticated");
  }
  assert.equal(h.usage(), 0);
  assert.equal(h.sent.length, 0);
  assert.ok(h.verifications.some(x => x[0] === "firebase" && x[2] === true));
});

test("anonymous Firebase account -> HTTP 403, 0 advanced analyses, no OpenAI", async () => {
  const h = makeHarness({ provider: "anonymous", uid: "anon" });
  const r = await h.dispatch({ text: "Pochybná SMS", analysisType: "TEXT_OR_URL" });
  assert.equal(r.status, 403);
  assert.equal((await r.json()).error.code, "permission-denied");
  assert.equal(h.sent.length, 0);
  assert.equal(h.usage(), 0);
});

test("registered Free -> exactly 5 charged successful analyses per UTC calendar month", async () => {
  const h = makeHarness();
  for (let i = 1; i <= 5; i++) {
    const r = await h.dispatch({ text: `Zaplaťte ihned ${i}`, analysisType: "TEXT_OR_URL" });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("cache-control"), "no-store, max-age=0");
    const data = await r.json();
    assert.equal(data.ok, true);
    assert.equal(data.quotaCharged, true);
    assert.equal(data.quotaExhausted, false);
    assert.equal(data.deepAnalysesUsed, i);
    assert.equal(data.monthlyLimit, 5);
    assert.equal(data.riskLevel, "CAUTION");
    assert.equal(data.signals[0].source, "AI");
  }
  const sixth = await h.dispatch({ text: "Šestý test", analysisType: "TEXT_OR_URL" });
  assert.equal(sixth.status, 200);
  const body = await sixth.json();
  assert.equal(body.quotaExhausted, true);
  assert.equal(body.quotaCharged, false);
  assert.equal(body.monthlyLimit, 5);
  assert.equal(h.usage(), 5);
  assert.equal(h.sent.length, 5);
});

test("registered Plus -> 100 monthly quota, 101st is not sent to OpenAI", async () => {
  const h = makeHarness({ uid: "plus-1" });
  await h.db.collection("users").doc("plus-1").collection("entitlement").doc("current")
    .set({ tier: "PLUS", status: "PLUS_ACTIVE", expiryTimeMillis: NOW + 86400000 });
  await h.db.collection("users").doc("plus-1").collection("usage").doc(getCurrentPeriod(NOW))
    .set({ deepAnalysisCount: 99 });
  const r100 = await h.dispatch({ text: "Poslední Plus analýza", analysisType: "TEXT_OR_URL" });
  assert.equal(r100.status, 200);
  const data100 = await r100.json();
  assert.equal(data100.monthlyLimit, 100);
  assert.equal(data100.deepAnalysesUsed, 100);
  assert.equal(data100.quotaCharged, true);
  const r101 = await h.dispatch({ text: "Nad limit", analysisType: "TEXT_OR_URL" });
  assert.equal((await r101.json()).quotaExhausted, true);
  assert.equal(h.sent.length, 1);
  assert.equal(h.usage(), 100);
});

test("screenshot and QR image+decoded URL are passed to the mocked multimodal OpenAI request", async () => {
  const h = makeHarness({ uid: "images" });
  const screenshot = await h.dispatch({ imageBase64: JPG, analysisType: "SCREENSHOT" });
  assert.equal(screenshot.status, 200);
  const qr = await h.dispatch({ analysisType: "QR_CODE", text: "https://example.invalid/payment", imageBase64: JPG });
  assert.equal(qr.status, 200);
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[0].input[0].content[1].type, "input_image");
  assert.equal(h.sent[0].input[0].content[1].image_url, `data:image/jpeg;base64,${JPG}`);
  assert.match(h.sent[1].input[0].content[0].text, /QR kód/);
  assert.match(h.sent[1].input[0].content[0].text, /https:\/\/example.invalid\/payment/);
  assert.equal(h.sent[1].input[0].content[1].type, "input_image");
  assert.equal(h.usage(), 2);
});

test("invalid image payload -> HTTP 400, no AI invocation and no quota", async () => {
  const h = makeHarness({ uid: "bad-image" });
  const res = await h.dispatch({ analysisType: "SCREENSHOT", imageBase64: Buffer.from("<script>").toString("base64") });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, "invalid-argument");
  assert.equal(h.usage(), 0);
  assert.equal(h.sent.length, 0);
});

test("OpenAI mock HTTP 429 -> API HTTP 503, no quota charge or request-body leak", async () => {
  const h = makeHarness({ uid: "provider-fail", responseStatus: 429 });
  // Expected server error is deliberately logged generically; mute output in this test.
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    const res = await h.dispatch({ text: "Pochybný e-mail", analysisType: "TEXT_OR_URL" });
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.error.code, "unavailable");
    assert.equal(JSON.stringify(body).includes("Pochybný e-mail"), false);
    assert.equal(h.usage(), 0);
    assert.equal(h.sent.length, 1);
  } finally {
    console.error = originalConsoleError;
  }
});
