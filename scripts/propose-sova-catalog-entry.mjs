#!/usr/bin/env node
/**
 * Review-only SOVA catalog entry proposal (issue #39 follow-up). Invoked by
 * .github/workflows/sova-catalog-proposal.yml after bacha's own sova-update.yml has
 * INDEPENDENTLY verified a SOVA release's dual signatures and opened its own review-only
 * model-lock PR; this script never re-verifies signatures itself (bacha_web has no pinned SOVA
 * keys) - it only stages a candidate catalog entry from already-verified fields for a human to
 * review. It NEVER writes directly to a protected branch and never sets channel to "stable":
 * promoting a model to "stable" remains a separate, manual, independently reviewed code change.
 *
 * Usage: node scripts/propose-sova-catalog-entry.mjs '<json payload>'
 * Payload fields (all required unless noted): version, generation, manifest_sha256,
 * compatible_sdk {min, maxExclusive}, files {name: {sha256, bytes}}, min_app_version,
 * expires_at (optional), revoked (optional, default false).
 */
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
// Overridable for tests only; the real workflow never sets this, so it always targets the
// actual committed catalog file that the resulting PR diff is reviewed against.
const ENTRIES_PATH = process.env.SOVA_CATALOG_ENTRIES_PATH_FOR_TEST
  || path.join(ROOT, "lib", "server", "bacha", "sovaCatalogEntries.json");
const { assertValidCatalog } = require("../lib/server/bacha/modelCatalog.js");

function fail(message) {
  process.stderr.write(`propose-sova-catalog-entry: ${message}\n`);
  process.exit(1);
}

function main() {
  const raw = process.argv[2];
  if (!raw) fail("missing JSON payload argument");
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (e) {
    fail(`payload is not valid JSON: ${e.message}`);
  }
  const required = ["version", "generation", "manifest_sha256", "compatible_sdk", "files", "min_app_version"];
  for (const key of required) {
    if (payload[key] === undefined || payload[key] === null) fail(`payload missing required field: ${key}`);
  }
  const entries = JSON.parse(readFileSync(ENTRIES_PATH, "utf8"));
  const candidate = {
    model_id: "sova",
    channel: "owner-test", // never proposed as "stable" - that promotion is a separate, manual change
    generation: payload.generation,
    version: payload.version,
    release_tag: `sova-v${payload.version}`,
    files: payload.files,
    manifest_sha256: payload.manifest_sha256,
    compatible_sdk: payload.compatible_sdk,
    minAppVersion: payload.min_app_version,
    approval: "approved",
    expires_at: payload.expires_at ?? null,
    revoked: payload.revoked === true,
  };
  if (entries.some((e) => e.version === candidate.version)) {
    process.stdout.write(`version ${candidate.version} is already proposed/present; nothing to do\n`);
    process.exit(0);
  }
  const next = [...entries, candidate];
  assertValidCatalog(next); // throws (and exits non-zero via the uncaught rejection below) on anything malformed
  writeFileSync(ENTRIES_PATH, `${JSON.stringify(next, null, 2)}\n`, "utf8");
  process.stdout.write(`staged candidate entry for ${candidate.version} (generation ${candidate.generation})\n`);
}

main();
