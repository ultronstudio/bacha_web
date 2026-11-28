"use strict";
const { test, describe, beforeEach, after } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const SCRIPT = path.join(ROOT, "scripts", "propose-sova-catalog-entry.mjs");
// Isolated tmp file for every test - never touches the real committed sovaCatalogEntries.json.
const ENTRIES_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sova-catalog-test-")), "sovaCatalogEntries.json");

const validPayload = {
  version: "1.0.0-alpha.9", generation: 1, manifest_sha256: "a".repeat(64),
  compatible_sdk: { min: "0.1.0", maxExclusive: "0.2.0" },
  files: { "sova-int8.onnx": { sha256: "b".repeat(64), bytes: 1024 } },
  min_app_version: "0.3.0",
};

function run(payload) {
  const env = { ...process.env, SOVA_CATALOG_ENTRIES_PATH_FOR_TEST: ENTRIES_PATH };
  try {
    const stdout = execFileSync("node", [SCRIPT, JSON.stringify(payload)], { encoding: "utf8", env });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout ? e.stdout.toString() : "", stderr: e.stderr ? e.stderr.toString() : "" };
  }
}

describe("propose-sova-catalog-entry.mjs (review-only staging, never a direct publish)", () => {
  beforeEach(() => { fs.writeFileSync(ENTRIES_PATH, "[]\n"); });
  after(() => { fs.rmSync(path.dirname(ENTRIES_PATH), { recursive: true, force: true }); });

  test("stages a well-formed candidate entry on the owner-test channel", () => {
    const r = run(validPayload);
    assert.equal(r.code, 0, r.stderr);
    const entries = JSON.parse(fs.readFileSync(ENTRIES_PATH, "utf8"));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].channel, "owner-test"); // never proposed as stable
    assert.equal(entries[0].approval, "approved");
    assert.equal(entries[0].version, "1.0.0-alpha.9");
  });

  test("forces channel to owner-test even if the payload tried to request stable", () => {
    run({ ...validPayload, channel: "stable" });
    const entries = JSON.parse(fs.readFileSync(ENTRIES_PATH, "utf8"));
    assert.equal(entries[0].channel, "owner-test");
  });

  test("is idempotent: re-proposing the same version is a no-op, not a duplicate or an error", () => {
    run(validPayload);
    const after1 = fs.readFileSync(ENTRIES_PATH, "utf8");
    const r2 = run(validPayload);
    assert.equal(r2.code, 0);
    assert.equal(fs.readFileSync(ENTRIES_PATH, "utf8"), after1);
    assert.equal(JSON.parse(after1).length, 1);
  });

  test("rejects a missing required field without writing anything", () => {
    const r = run({ version: "1.0.0-alpha.9" });
    assert.equal(r.code, 1);
    assert.equal(fs.readFileSync(ENTRIES_PATH, "utf8"), "[]\n");
  });

  test("rejects a malformed generation via assertValidCatalog and writes nothing", () => {
    const r = run({ ...validPayload, generation: 0 });
    assert.notEqual(r.code, 0);
    assert.equal(fs.readFileSync(ENTRIES_PATH, "utf8"), "[]\n");
  });

  test("rejects a second proposal whose generation does not strictly increase", () => {
    run(validPayload);
    const r = run({ ...validPayload, version: "1.0.0-alpha.10", generation: 1 });
    assert.notEqual(r.code, 0);
    assert.equal(JSON.parse(fs.readFileSync(ENTRIES_PATH, "utf8")).length, 1);
  });

  test("rejects malformed JSON input without writing anything", () => {
    const envRun = { ...process.env, SOVA_CATALOG_ENTRIES_PATH_FOR_TEST: ENTRIES_PATH };
    let failed = false;
    try {
      execFileSync("node", [SCRIPT, "not json"], { encoding: "utf8", env: envRun });
    } catch {
      failed = true;
    }
    assert.ok(failed);
    assert.equal(fs.readFileSync(ENTRIES_PATH, "utf8"), "[]\n");
  });
});
