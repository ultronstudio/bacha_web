"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const df = require("../../lib/server/bacha/domainFacts");
const { buildUserPrompt } = require("../../lib/server/bacha/aiOutput");
const { combineServerVerdict } = require("../../lib/server/bacha/riskEngine");

test("BUG-08: reserved TLD is recognised without any DNS lookup", async () => {
  let called = 0;
  const r = await df.assessUrlDomains("https://bankovni-overeni.example.invalid/login", { enabled: true, resolve: async () => { called++; return { status: "EXISTS", addresses: ["1.1.1.1"] }; } });
  assert.equal(called, 0);
  assert.equal(r.signals[0].id, "url_reserved_domain");
  assert.match(r.promptFacts[0], /\.invalid/);
  for (const h of ["a.test", "x.example", "localhost", "printer.local", "router.home.arpa", "www.example.com", "a.example.org"]) {
    assert.ok(df.reservedReason(h), h);
  }
  for (const h of ["seznam.cz", "csob.cz", "example-bank.cz", "invalidni.cz", "testovani.cz"]) assert.equal(df.reservedReason(h), null, h);
});

test("reserved/NXDOMAIN facts are not counted as phishing evidence", () => {
  const facts = [{ id: "url_reserved_domain", severity: "LOW", source: "URL_FACT", isPositive: false, evidenceGroup: "URL_STRUCTURE" }];
  const v = combineServerVerdict({ threatReputation: null, ai: { riskLevel: "LOW", signals: [] }, metadataSignals: facts });
  assert.equal(v.category, "NO_KNOWN_RED_FLAGS");
});

test("DNS states are distinguished: verified, NXDOMAIN, failed, not checked", async () => {
  const nx = await df.assessUrlDomains("https://neexistuje-xyz.cz/login", { enabled: true, resolve: async () => ({ status: "NXDOMAIN" }) });
  assert.equal(nx.signals[0].id, "url_domain_not_found");
  const failed = await df.assessUrlDomains("https://banka.cz/", { enabled: true, resolve: async () => ({ status: "FAILED" }) });
  assert.equal(failed.signals.length, 0);
  assert.match(failed.limitations[0], /nepodařilo ověřit/);
  const thrown = await df.assessUrlDomains("https://banka.cz/", { enabled: true, resolve: async () => { throw new Error("boom"); } });
  assert.equal(thrown.facts[0].dns, "FAILED");
  const off = await df.assessUrlDomains("https://banka.cz/", { enabled: false, resolve: async () => { throw new Error("must not run"); } });
  assert.equal(off.facts[0].dns, "NOT_CHECKED");
  const ok = await df.assessUrlDomains("https://www.csob.cz/login", { enabled: true, resolve: async () => ({ status: "EXISTS", addresses: ["193.85.1.1"] }) });
  assert.equal(ok.signals.length, 0, "a legitimate login URL on a resolving public domain yields no signal");
});

test("private/loopback DNS answers are reported (rebinding indicator) but never contacted", async () => {
  const r = await df.assessUrlDomains("https://evil.cz/x", { enabled: true, resolve: async () => ({ status: "EXISTS", addresses: ["127.0.0.1"] }) });
  assert.equal(r.signals[0].id, "url_domain_private_address");
  for (const ip of ["10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1"]) assert.ok(df.isNonPublicAddress(ip), ip);
  for (const ip of ["8.8.8.8", "172.32.0.1", "193.85.1.1"]) assert.equal(df.isNonPublicAddress(ip), false, ip);
});

test("domain facts reach the AI prompt as server facts, escaped, bounded", () => {
  const p = buildUserPrompt({ text: "x", analysisType: "TEXT_OR_URL", threatContext: null, hasImage: false, domainFacts: ["a", "b", "c", "d"] });
  assert.match(p, /<domain_facts>\n- a\n- b\n- c\n<\/domain_facts>/);
  const none = buildUserPrompt({ text: "x", analysisType: "TEXT_OR_URL", threatContext: null, hasImage: false });
  assert.doesNotMatch(none, /domain_facts/);
});
