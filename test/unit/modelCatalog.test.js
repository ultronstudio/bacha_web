"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const {
  assertValidCatalog, resolveSovaCatalogEntry, toClientCatalog, ModelCatalogError, APPROVED_SOVA_CATALOG,
} = require("../../lib/server/bacha/modelCatalog");

const base = {
  model_id: "sova", channel: "stable", generation: 1, version: "1.0.0-alpha.3",
  release_tag: "sova-v1.0.0-alpha.3",
  files: { "sova-int8.onnx": { sha256: "a".repeat(64), bytes: 1024 } },
  manifest_sha256: "b".repeat(64),
  compatible_sdk: { min: "0.1.0", maxExclusive: "0.2.0" },
  minAppVersion: "0.3.0",
  approval: "approved",
};

describe("real shipped catalog", () => {
  test("is empty until the owner reviews real evidence (fail closed by construction)", () => {
    assert.deepEqual(APPROVED_SOVA_CATALOG, []);
  });
});

describe("assertValidCatalog", () => {
  test("accepts a well-formed catalog", () => {
    assert.deepEqual(assertValidCatalog([base]), [base]);
  });
  test("rejects anything not exactly approved", () => {
    assert.throws(() => assertValidCatalog([{ ...base, approval: "candidate" }]), ModelCatalogError);
    assert.throws(() => assertValidCatalog([{ ...base, approval: "experimental" }]));
  });
  test("rejects a release_tag that does not match the version (no arbitrary pointer)", () => {
    assert.throws(() => assertValidCatalog([{ ...base, release_tag: "sova-v9.9.9" }]));
  });
  test("rejects non-increasing or non-integer generations", () => {
    const b = { ...base, generation: 2, version: "1.0.0-alpha.4", release_tag: "sova-v1.0.0-alpha.4" };
    assert.throws(() => assertValidCatalog([b, { ...base }])); // second generation (1) <= first (2)
    assert.throws(() => assertValidCatalog([{ ...base, generation: 1.5 }]));
  });
  test("rejects duplicate versions", () => {
    assert.throws(() => assertValidCatalog([base, { ...base, generation: 2 }]));
  });
  test("rejects unsafe or path-traversal file names", () => {
    assert.throws(() => assertValidCatalog([{ ...base, files: { "../evil": { sha256: "a".repeat(64), bytes: 1 } } }]));
    assert.throws(() => assertValidCatalog([{ ...base, files: { "ok.bin": { sha256: "nothex", bytes: 1 } } }]));
  });
  test("rejects an unbounded or non-positive declared file size", () => {
    assert.throws(() => assertValidCatalog([{ ...base, files: { "x.onnx": { sha256: "a".repeat(64), bytes: 0 } } }]));
    assert.throws(() => assertValidCatalog([{ ...base, files: { "x.onnx": { sha256: "a".repeat(64), bytes: 500 * 1024 * 1024 } } }]));
  });
  test("rejects an invalid channel", () => {
    assert.throws(() => assertValidCatalog([{ ...base, channel: "beta" }]));
  });
});

describe("resolveSovaCatalogEntry (fail-closed selection)", () => {
  test("returns null for a completely empty catalog", () => {
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "9.9.9", sdkVersion: "0.1.0", catalog: [] }), null);
  });
  test("returns null for an invalid/unknown channel", () => {
    assert.equal(resolveSovaCatalogEntry({ channel: "hacker", appVersion: "9.9.9", sdkVersion: "0.1.0", catalog: [base] }), null);
  });
  test("matches a compatible entry on the right channel", () => {
    const got = resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", catalog: [base] });
    assert.equal(got, base);
  });
  test("never offers a stable entry on the owner-test channel or vice versa", () => {
    assert.equal(resolveSovaCatalogEntry({ channel: "owner-test", appVersion: "0.5.0", sdkVersion: "0.1.5", catalog: [base] }), null);
  });
  test("rejects an app version below minAppVersion", () => {
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.2.9", sdkVersion: "0.1.5", catalog: [base] }), null);
  });
  test("rejects an SDK version outside compatible_sdk range (min and maxExclusive)", () => {
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.0.9", catalog: [base] }), null);
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.2.0", catalog: [base] }), null);
  });
  test("ignores an expired entry", () => {
    const expired = { ...base, expiresAtMillis: 1000 };
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", now: 2000, catalog: [expired] }), null);
  });
  test("ignores a revoked entry even if otherwise compatible", () => {
    const revoked = { ...base, revoked: true };
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", catalog: [revoked] }), null);
  });
  test("never selects a downgrade: picks the highest compatible generation", () => {
    const g1 = { ...base, generation: 1, version: "1.0.0-alpha.3", release_tag: "sova-v1.0.0-alpha.3" };
    const g2 = { ...base, generation: 2, version: "1.0.0-alpha.4", release_tag: "sova-v1.0.0-alpha.4" };
    const got = resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", catalog: [g2, g1] });
    assert.equal(got.generation, 2);
  });
  test("tampered/garbage appVersion or sdkVersion from a client fails closed, never throws", () => {
    assert.doesNotThrow(() => resolveSovaCatalogEntry({ channel: "stable", appVersion: "'; DROP", sdkVersion: "../../x", catalog: [base] }));
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "'; DROP", sdkVersion: "../../x", catalog: [base] }), null);
  });
});

describe("toClientCatalog", () => {
  test("never includes the private HF repo, approval reasoning, or anything beyond the wire shape", () => {
    const wire = toClientCatalog(base);
    assert.deepEqual(Object.keys(wire).sort(), [
      "channel", "compatibleSdk", "files", "generation", "manifestSha256",
      "minAppVersion", "modelId", "releaseBaseUrl", "releaseTag", "schema", "version",
    ].sort());
    assert.equal(wire.releaseBaseUrl, "https://github.com/ultronstudio/sova/releases/download/sova-v1.0.0-alpha.3");
  });
  test("returns null for a null entry", () => {
    assert.equal(toClientCatalog(null), null);
  });
});
