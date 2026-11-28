"use strict";
const { test, describe, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { handleModelCatalogLatest, parseQuery, devFixtureCatalog } = require("../../lib/server/bacha/modelCatalogHttp");

function req(qs) {
  return new Request(`https://bacha.petrvurm.cz/api/v1/models/sova/latest${qs}`, { method: "GET" });
}

describe("parseQuery", () => {
  test("defaults to the stable channel and 0.0.0 versions", () => {
    assert.deepEqual(parseQuery(req("")), { channel: "stable", appVersion: "0.0.0", sdkVersion: "0.0.0" });
  });
  test("accepts well-formed overrides", () => {
    assert.deepEqual(parseQuery(req("?channel=owner-test&appVersion=0.5.1&sdkVersion=0.1.0")),
      { channel: "owner-test", appVersion: "0.5.1", sdkVersion: "0.1.0" });
  });
  test("rejects an unknown channel", () => {
    assert.throws(() => parseQuery(req("?channel=beta")), { name: "ValidationError" });
  });
  test("rejects malformed or oversized version strings", () => {
    assert.throws(() => parseQuery(req("?appVersion=" + "1".repeat(60))), { name: "ValidationError" });
    assert.throws(() => parseQuery(req("?sdkVersion=not-a-version!!")), { name: "ValidationError" });
    assert.throws(() => parseQuery(req("?appVersion=../../etc/passwd")), { name: "ValidationError" });
  });
});

describe("handleModelCatalogLatest (no Firestore access - metadata only)", () => {
  test("returns available:false by default (the real catalog is empty)", async () => {
    const body = await handleModelCatalogLatest(req(""));
    assert.deepEqual(body, { ok: true, available: false, reason: "no_approved_version" });
  });
  test("never 500s or throws on a malformed query - validation errors surface as ValidationError for the caller to map", async () => {
    await assert.rejects(() => handleModelCatalogLatest(req("?channel=not-real")), { name: "ValidationError" });
  });
});

describe("dev fixture (never active in production, never the default)", () => {
  const prevEnv = process.env.NODE_ENV;
  const prevFixture = process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE;
  const fixtureEntry = {
    model_id: "sova", channel: "stable", generation: 1, version: "1.0.0-alpha.3",
    release_tag: "sova-v1.0.0-alpha.3", files: { "sova-int8.onnx": { sha256: "a".repeat(64), bytes: 10 } },
    manifest_sha256: "b".repeat(64), compatible_sdk: { min: "0.1.0", maxExclusive: "0.2.0" },
    minAppVersion: "0.0.0", approval: "approved",
  };

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevFixture === undefined) delete process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE; else process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE = prevFixture;
  });

  test("is ignored entirely in production even if set", () => {
    process.env.NODE_ENV = "production";
    process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE = JSON.stringify([fixtureEntry]);
    assert.equal(devFixtureCatalog(), null);
  });
  test("activates outside production and lets the endpoint report an available update", async () => {
    process.env.NODE_ENV = "test";
    process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE = JSON.stringify([fixtureEntry]);
    const body = await handleModelCatalogLatest(req("?sdkVersion=0.1.0"));
    assert.equal(body.available, true);
    assert.equal(body.catalog.version, "1.0.0-alpha.3");
  });
  test("a malformed fixture never crashes the request - falls back to the real (empty) catalog", async () => {
    process.env.NODE_ENV = "test";
    process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE = "{not json";
    const body = await handleModelCatalogLatest(req(""));
    assert.deepEqual(body, { ok: true, available: false, reason: "no_approved_version" });
  });
  test("is inactive when the env var is simply unset", () => {
    delete process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE;
    process.env.NODE_ENV = "test";
    assert.equal(devFixtureCatalog(), null);
  });
});
