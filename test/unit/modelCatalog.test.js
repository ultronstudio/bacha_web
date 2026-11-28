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
  test("accepts optional expires_at and revoked fields", () => {
    assert.deepEqual(assertValidCatalog([{ ...base, expires_at: "2027-01-01T00:00:00Z", revoked: false }]),
      [{ ...base, expires_at: "2027-01-01T00:00:00Z", revoked: false }]);
  });
  test("rejects an unknown model_id", () => {
    assert.throws(() => assertValidCatalog([{ ...base, model_id: "ml1" }]), ModelCatalogError);
  });
  test("rejects anything not exactly approved", () => {
    assert.throws(() => assertValidCatalog([{ ...base, approval: "candidate" }]), ModelCatalogError);
    assert.throws(() => assertValidCatalog([{ ...base, approval: "experimental" }]));
  });
  test("rejects a release_tag that does not match the version (no arbitrary pointer)", () => {
    assert.throws(() => assertValidCatalog([{ ...base, release_tag: "sova-v9.9.9" }]));
  });
  test("rejects non-increasing, non-positive, or non-integer generations", () => {
    const b = { ...base, generation: 2, version: "1.0.0-alpha.4", release_tag: "sova-v1.0.0-alpha.4" };
    assert.throws(() => assertValidCatalog([b, { ...base }])); // second generation (1) <= first (2) on the same channel
    assert.throws(() => assertValidCatalog([{ ...base, generation: 1.5 }]));
    assert.throws(() => assertValidCatalog([{ ...base, generation: 0 }]));
    assert.throws(() => assertValidCatalog([{ ...base, generation: -1 }]));
  });
  test("generation sequences are independent per channel", () => {
    const stable1 = { ...base, channel: "stable", generation: 1 };
    const ownerTest1 = { ...base, channel: "owner-test", generation: 1, version: "1.0.0-alpha.9", release_tag: "sova-v1.0.0-alpha.9" };
    assert.deepEqual(assertValidCatalog([stable1, ownerTest1]), [stable1, ownerTest1]);
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
  test("rejects too many files on one entry", () => {
    const files = {};
    for (let i = 0; i < 17; i += 1) files[`f${i}.bin`] = { sha256: "a".repeat(64), bytes: 1 };
    assert.throws(() => assertValidCatalog([{ ...base, files }]));
  });
  test("rejects an invalid channel", () => {
    assert.throws(() => assertValidCatalog([{ ...base, channel: "beta" }]));
  });
  test("rejects a malformed expires_at", () => {
    assert.throws(() => assertValidCatalog([{ ...base, expires_at: "not-a-date" }]));
  });
  test("rejects a non-boolean revoked", () => {
    assert.throws(() => assertValidCatalog([{ ...base, revoked: "yes" }]));
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
    const expired = { ...base, expires_at: "1970-01-01T00:00:01Z" };
    assert.equal(resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", now: 2000, catalog: [expired] }), null);
  });
  test("keeps a not-yet-expired entry", () => {
    const notExpired = { ...base, expires_at: "2099-01-01T00:00:00Z" };
    const got = resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", now: Date.now(), catalog: [notExpired] });
    assert.equal(got, notExpired);
  });
  test("a malformed expires_at on an entry fails that entry closed, never throws", () => {
    const malformed = { ...base, expires_at: "not-a-date" };
    assert.throws(() => resolveSovaCatalogEntry({ channel: "stable", appVersion: "0.5.0", sdkVersion: "0.1.5", catalog: [malformed] }));
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
      "channel", "compatibleSdk", "expiresAt", "files", "generation", "manifestSha256",
      "minAppVersion", "modelId", "releaseBaseUrl", "releaseTag", "revoked", "schema", "version",
    ].sort());
    assert.equal(wire.releaseBaseUrl, "https://github.com/ultronstudio/sova/releases/download/sova-v1.0.0-alpha.3");
    assert.equal(wire.expiresAt, null);
    assert.equal(wire.revoked, false);
  });
  test("passes through expiresAt/revoked when present", () => {
    const wire = toClientCatalog({ ...base, expires_at: "2027-01-01T00:00:00Z", revoked: true });
    assert.equal(wire.expiresAt, "2027-01-01T00:00:00Z");
    assert.equal(wire.revoked, true);
  });
  test("returns null for a null entry", () => {
    assert.equal(toClientCatalog(null), null);
  });
});
