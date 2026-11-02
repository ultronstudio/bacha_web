"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const L = require("../../lib/server/bacha/limits");

const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]).toString("base64");

describe("analyze request limits", () => {
  test("accepts normal text", () => {
    assert.equal(L.validateAnalyzeRequest({ text: "ahoj", analysisType: "TEXT_OR_URL" }).text, "ahoj");
  });
  test("rejects oversized text", () => {
    assert.throws(() => L.validateAnalyzeRequest({ text: "a".repeat(L.LIMITS.MAX_TEXT_CHARS + 1) }), L.ValidationError);
  });
  test("rejects empty input", () => {
    assert.throws(() => L.validateAnalyzeRequest({ text: "   " }), L.ValidationError);
  });
  test("rejects unknown analysis type", () => {
    assert.throws(() => L.validateAnalyzeRequest({ text: "x", analysisType: "SYSTEM_PROMPT" }), L.ValidationError);
  });
  test("rejects non-string text", () => {
    assert.throws(() => L.validateAnalyzeRequest({ text: { $gt: 1 } }), L.ValidationError);
  });
  test("accepts small jpeg and detects mime", () => {
    const r = L.validateAnalyzeRequest({ imageBase64: JPEG });
    assert.equal(r.image.mimeType, "image/jpeg");
  });
  test("rejects oversized image", () => {
    assert.throws(() => L.validateAnalyzeRequest({ imageBase64: "A".repeat(L.LIMITS.MAX_IMAGE_BASE64_CHARS + 4) }), L.ValidationError);
    const big = Buffer.alloc(L.LIMITS.MAX_IMAGE_BYTES + 10, 0);
    big[0] = 0xff; big[1] = 0xd8; big[2] = 0xff;
    assert.throws(() => L.validateAnalyzeRequest({ imageBase64: big.toString("base64") }), L.ValidationError);
  });
  test("rejects non-image payload", () => {
    assert.throws(() => L.validateAnalyzeRequest({ imageBase64: Buffer.from("<script>").toString("base64") }), /formát/);
  });
});

describe("other limits", () => {
  test("lookup max indicators", () => {
    const many = Array.from({ length: L.LIMITS.MAX_LOOKUP_INDICATORS + 1 }, () => ({ type: "URL", value: "a.cz" }));
    assert.throws(() => L.validateLookupRequest({ indicators: many }), L.ValidationError);
    assert.equal(L.validateLookupRequest({ indicators: [{ type: "URL", value: "a.cz" }] }).length, 1);
  });
  test("report note limit and enums", () => {
    assert.throws(() => L.validateReportRequest({ rawValue: "a.cz", note: "x".repeat(501) }), L.ValidationError);
    assert.throws(() => L.validateReportRequest({ rawValue: "a.cz", category: "HACK" }), L.ValidationError);
    assert.equal(L.validateReportRequest({ rawValue: "a.cz", category: "PHISHING", financialHarm: "YES" }).category, "PHISHING");
  });
  test("dispute reason bounds & lookupKey format", () => {
    const key = "a".repeat(64);
    assert.throws(() => L.validateDisputeRequest({ lookupKey: key, reason: "short" }), L.ValidationError);
    assert.throws(() => L.validateDisputeRequest({ lookupKey: "../etc", reason: "long enough reason" }), L.ValidationError);
    assert.equal(L.validateDisputeRequest({ lookupKey: key, reason: "long enough reason" }).lookupKey, key);
  });
});
