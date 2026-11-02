"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const R = require("../../lib/server/bacha/riskEngine");

describe("server evidence model", () => {
  test("KNOWN_SAFE cannot downgrade strong AI evidence", () => {
    const r = R.combineServerVerdict({
      threatReputation: { verdict: "KNOWN_SAFE" },
      ai: { riskLevel: "HIGH", confidence: "HIGH", signals: [{ id: "cred", severity: "HIGH" }] },
    });
    assert.equal(r.category, "HIGH_RISK");
  });
  test("no evidence -> NO_KNOWN_RED_FLAGS (not SAFE)", () => {
    const r = R.combineServerVerdict({ threatReputation: null, ai: { riskLevel: "LOW", confidence: "HIGH", signals: [] } });
    assert.equal(r.category, "NO_KNOWN_RED_FLAGS");
    assert.notEqual(r.category, "SAFE");
  });
  test("UNKNOWN ai without evidence -> INCONCLUSIVE", () => {
    assert.equal(R.combineServerVerdict({ ai: { riskLevel: "UNKNOWN", confidence: "LOW", signals: [] } }).category, "INCONCLUSIVE");
  });
  test("confirmed threat feed -> KNOWN_MALICIOUS", () => {
    assert.equal(R.combineServerVerdict({ threatReputation: { verdict: "CONFIRMED_MALICIOUS" }, ai: null }).category, "KNOWN_MALICIOUS");
  });
});
