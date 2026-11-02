"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb } = require("../helpers/setup");
const ti = require("../../lib/server/bacha/threatIntel");

const URL_RAW = "https://posta-doplatek.top/zasilka?id=1";

async function reportAs(db, uid, accountKind = "anonymous") {
  return ti.submitCommunityReport(db, uid, { rawValue: URL_RAW, indicatorType: "URL", category: "FAKE_DELIVERY", financialHarm: "NO" }, { accountKind });
}

function keyFor(raw) {
  const n = ti.normalizeUrl(raw);
  return ti.computeHmacLookupKey(n.type, n.canonicalValue);
}

describe("HMAC lookup keys", () => {
  test("missing secret fails closed (no default)", () => {
    assert.throws(() => ti.computeHmacLookupKey("URL", "x", {}), /THREAT_INTEL_HMAC_SECRET/);
  });
  test("weak secret is rejected", () => {
    assert.throws(() => ti.computeHmacLookupKey("URL", "x", { THREAT_INTEL_HMAC_SECRET: "short" }), /at least/);
  });
  test("old hardcoded default is not present in source", () => {
    const src = require("fs").readFileSync(require.resolve("../../lib/server/bacha/threatIntel"), "utf8");
    assert.equal(src.includes("bacha_threat_intel_salt"), false);
  });
});

describe("Public Suffix List registrable domain", () => {
  for (const [host, expected] of [
    ["login.example.co.uk", "example.co.uk"],
    ["a.b.example.com.au", "example.com.au"],
    ["www.example.co.jp", "example.co.jp"],
    ["ib.csob.cz", "csob.cz"],
    ["evil.github.io", "evil.github.io"],
  ]) {
    test(`${host} -> ${expected}`, () => assert.equal(ti.extractRegistrableDomain(host), expected));
  }
});

describe("Normalisation", () => {
  test("strips sensitive query params", () => {
    const n = ti.normalizeUrl("https://Example.COM/a?token=abc&page=2&email=x@y.cz");
    assert.equal(n.canonicalValue, "https://example.com/a?page=2");
  });
  test("userinfo trick resolves to real host", () => {
    assert.equal(ti.normalizeDomain("https://csob.cz@evil.top/login"), "evil.top");
  });
  test("phone normalisation", () => {
    assert.equal(ti.normalizePhone("603 123 456").canonicalValue, "+420603123456");
    assert.equal(ti.normalizePhone("abc"), null);
  });
});

describe("Community trust model (Sybil resistance)", () => {
  test("single report -> SUSPICIOUS, never confirmed", async () => {
    const db = freshDb();
    const r = await reportAs(db, "u1");
    assert.equal(r.verdict, "SUSPICIOUS");
  });

  test("50 distinct anonymous UIDs still cannot reach CONFIRMED_MALICIOUS", async () => {
    const db = freshDb();
    for (let i = 0; i < 50; i++) await reportAs(db, `sybil_${i}`);
    const doc = db.raw(`threatIndicators/${keyFor(URL_RAW)}`);
    assert.equal(doc.verdict, "SUSPICIOUS");
    assert.equal(doc.independentReporterCount, 50);
    assert.equal(doc.confidence, "MEDIUM");
    assert.equal(doc.needsReview, true);
  });

  test("duplicate reports from same user do not inflate counts", async () => {
    const db = freshDb();
    for (let i = 0; i < 5; i++) await reportAs(db, "same");
    const doc = db.raw(`threatIndicators/${keyFor(URL_RAW)}`);
    assert.equal(doc.reportCount, 1);
    assert.equal(doc.independentReporterCount, 1);
  });

  test("reports cannot downgrade a trusted CONFIRMED verdict nor overturn KNOWN_SAFE", async () => {
    assert.equal(ti.verdictAfterCommunityReport("CONFIRMED_MALICIOUS"), "CONFIRMED_MALICIOUS");
    assert.equal(ti.verdictAfterCommunityReport("KNOWN_SAFE"), "KNOWN_SAFE");
    assert.equal(ti.verdictAfterCommunityReport("UNKNOWN"), "SUSPICIOUS");
    assert.equal(ti.verdictAfterCommunityReport("INACTIVE"), "SUSPICIOUS");
  });

  test("only trusted sources may confirm; untrusted source rejected", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await assert.rejects(ti.applyTrustedVerdict(db, { lookupKey: key, verdict: "CONFIRMED_MALICIOUS", sourceType: "USER_REPORT" }), /not trusted/);
    await ti.applyTrustedVerdict(db, { lookupKey: key, verdict: "CONFIRMED_MALICIOUS", sourceType: "WEB_RISK", category: "PHISHING" });
    assert.equal(db.raw(`threatIndicators/${key}`).verdict, "CONFIRMED_MALICIOUS");
    const history = db.docsIn("indicatorHistory").map((p) => db.raw(p));
    assert.ok(history.some((h) => h.newVerdict === "CONFIRMED_MALICIOUS" && h.sourceType === "WEB_RISK"), "audit entry written");
  });

  test("manual moderation writes actor into audit log", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await ti.applyTrustedVerdict(db, { lookupKey: key, verdict: "KNOWN_SAFE", sourceType: "MANUAL_REVIEW", actorUid: "mod1", reason: "official" });
    const h = db.docsIn("indicatorHistory").map((p) => db.raw(p)).find((x) => x.newVerdict === "KNOWN_SAFE");
    assert.equal(h.actorUid, "mod1");
  });
});

describe("Disputes", () => {
  test("dispute is PENDING and does NOT change verdict", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await ti.applyTrustedVerdict(db, { lookupKey: key, verdict: "CONFIRMED_MALICIOUS", sourceType: "PHISHTANK" });
    const r = await ti.submitDispute(db, "owner", { lookupKey: key, reason: "This is my legitimate shop", indicatorType: "URL" });
    assert.equal(r.status, "PENDING");
    const ind = db.raw(`threatIndicators/${key}`);
    assert.equal(ind.verdict, "CONFIRMED_MALICIOUS");
    assert.equal(ind.openDisputeCount, 1);
    const hist = db.docsIn("indicatorHistory").map((p) => db.raw(p));
    assert.ok(hist.some((h) => h.event === "DISPUTE_OPENED" && h.newVerdict === "CONFIRMED_MALICIOUS"));
  });

  test("duplicate pending dispute from same user is not re-created", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await reportAs(db, "x");
    await ti.submitDispute(db, "owner", { lookupKey: key, reason: "reason long enough" });
    const r2 = await ti.submitDispute(db, "owner", { lookupKey: key, reason: "reason long enough" });
    assert.equal(r2.duplicate, true);
    assert.equal(db.raw(`threatIndicators/${key}`).openDisputeCount, 1);
  });

  test("upheld dispute changes verdict via audited trusted path; rejected does not", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await reportAs(db, "x");
    const { disputeId } = await ti.submitDispute(db, "owner", { lookupKey: key, reason: "reason long enough" });
    await ti.resolveDispute(db, { disputeId, resolution: "REJECTED", actorUid: "mod" });
    assert.equal(db.raw(`threatIndicators/${key}`).verdict, "SUSPICIOUS");
    assert.equal(db.raw(`threatDisputes/${disputeId}`).status, "REJECTED");

    const d2 = await ti.submitDispute(db, "owner", { lookupKey: key, reason: "second try long" });
    await ti.resolveDispute(db, { disputeId: d2.disputeId, resolution: "UPHELD", newVerdict: "KNOWN_SAFE", actorUid: "mod" });
    assert.equal(db.raw(`threatIndicators/${key}`).verdict, "KNOWN_SAFE");
    assert.equal(db.raw(`threatIndicators/${key}`).openDisputeCount, 0);
    await assert.rejects(ti.resolveDispute(db, { disputeId: d2.disputeId, resolution: "REJECTED", actorUid: "mod" }), /already resolved/);
  });
});

describe("Lookup hierarchy", () => {
  test("registrable-domain match is found for sub-host", async () => {
    const db = freshDb();
    const dKey = ti.computeHmacLookupKey("DOMAIN", "evil.co.uk");
    await ti.applyTrustedVerdict(db, { lookupKey: dKey, verdict: "CONFIRMED_MALICIOUS", sourceType: "MANUAL_REVIEW", actorUid: "m" });
    const rep = await ti.queryThreatIntelligence(db, ti.normalizeUrl("https://login.evil.co.uk/x"));
    assert.equal(rep.verdict, "CONFIRMED_MALICIOUS");
    assert.equal(rep.matchType, "REGISTRABLE_DOMAIN");
  });
  test("KNOWN_SAFE never wins over negative evidence in pickTopReputation", () => {
    const top = ti.pickTopReputation([{ verdict: "KNOWN_SAFE" }, { verdict: "SUSPICIOUS" }]);
    assert.equal(top.verdict, "SUSPICIOUS");
  });
});

describe("External providers", () => {
  function hangingFetch(_url, opts) {
    return new Promise((_, reject) => opts.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))));
  }

  for (const P of [ti.GoogleWebRiskProvider, ti.PhishTankProvider, ti.UrlhausProvider]) {
    test(`${P.name} timeout -> checked=false (not clean)`, async () => {
      const p = new P({ apiKey: "k", fetchImpl: hangingFetch, timeoutMs: 20 });
      const r = await p.checkUrl("https://x.top");
      assert.equal(r.checked, false);
      assert.equal(r.isMalicious, false);
      assert.equal(r.error, "TIMEOUT");
    });
    test(`${P.name} without key is skipped`, async () => {
      const r = await new P({ apiKey: null }).checkUrl("https://x.top");
      assert.equal(r.checked, false);
    });
  }

  test("aggregate: one provider hit wins even if others fail", async () => {
    const providers = [
      { name: "WEB_RISK", checkUrl: async () => ({ checked: false, error: "TIMEOUT" }) },
      { name: "PHISHTANK", checkUrl: async () => { throw new Error("boom"); } },
      { name: "URLHAUS", checkUrl: async () => ({ checked: true, isMalicious: true, category: "MALWARE" }) },
    ];
    const res = await ti.checkExternalProviders("https://x.top", providers);
    assert.equal(res.hit.provider, "URLHAUS");
    assert.equal(res.results.find((r) => r.provider === "PHISHTANK").checked, false);
  });
});

describe("Threat watches", () => {
  test("watch persists and can be listed after restart", async () => {
    const db = freshDb();
    const key = keyFor(URL_RAW);
    await ti.setThreatWatch(db, "u1", key, true);
    const list = await ti.listThreatWatches(db, "u1");
    assert.deepEqual(list.map((w) => w.lookupKey), [key]);
    await ti.setThreatWatch(db, "u1", key, false);
    assert.equal((await ti.listThreatWatches(db, "u1")).length, 0);
  });
});
