"use strict";

/**
 * Versioned, signed model catalog contract shared with the Android app. See the canonical schema
 * doc in the Android repo: ultronstudio/bacha docs/model-catalog-schema.md (also: ml/sova.lock.json
 * for the existing build-time pinning this complements).
 *
 * This module is the ONLY place that lists which SOVA model generations this backend will ever
 * point an app at. It is a POINTER, not a trust anchor: every entry names an exact SOVA GitHub
 * release that is already independently signed twice - an offline author Ed25519 signature over
 * manifest.json, and a separate CI-receipt Ed25519 signature over provenance.json (see
 * sova/scripts/verify_release.py and bacha/scripts/ml/verify_sova_release.py). The Android app
 * verifies both signatures itself with public keys baked into the APK at build time; it must
 * NEVER trust this HTTP response, HTTPS alone, or any server-provided checksum as sufficient
 * proof of authenticity. Catalog entries only narrow which already-approved release an app may
 * be pointed at (allowlist), fail-closed and reviewed, never a second way to approve a model.
 *
 * Entries are added ONLY by a reviewed code change + manual owner deploy - never from a
 * database, admin API, or request body - so "approved" stays an explicit, auditable decision
 * and there is exactly one trust/approval path (the same one ml/sova.lock.json already uses).
 */

const SCHEMA = 1;
const RELEASE_BASE_URL = "https://github.com/ultronstudio/sova/releases/download/";
const CHANNELS = Object.freeze(["owner-test", "stable"]);
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]{1,32})?$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const MAX_FILE_BYTES = 200 * 1024 * 1024; // bounded payload; real SOVA bundles are a few tens of MB

/**
 * One entry per approved, released SOVA generation.
 *
 *  model_id        logical model family ("sova" today; future ML1/ML2 OTA would reuse this shape).
 *  channel         "owner-test" | "stable". Only "stable" is ever offered outside explicit owner testing.
 *  generation      monotonic integer; strictly increasing across entries (enforced by assertValidCatalog).
 *  version         exact SOVA semver - never "latest".
 *  release_tag     exact GitHub release tag; files are fetched from RELEASE_BASE_URL + this tag.
 *  files           exact inventory: { name: { sha256, bytes } }; re-verified client-side against
 *                  the downloaded, author-signed manifest.json - these hashes are a convenience
 *                  cross-check, not the trust anchor.
 *  manifest_sha256 pins manifest.json's own hash (defense in depth alongside the Ed25519 signature).
 *  compatible_sdk  { min, maxExclusive } Android SOVA SDK range (mirrors ml/sova.lock.json).
 *  minAppVersion   minimum Bacha app semver allowed to receive this generation.
 *  approval        must be exactly "approved"; anything else can never be served (fail-closed).
 *  expiresAtMillis optional; the entry is ignored once Date.now() reaches this.
 *  revoked         optional kill switch; true removes the entry from consideration immediately.
 */
const APPROVED_SOVA_CATALOG = Object.freeze([
  // Intentionally empty. Per the current evaluation state (experimental 6L/12L, "candidate"
  // alpha.1 - see bacha/ml/sova.lock.json and SOVA issues #30/#31), nothing is approved for
  // distribution yet. The catalog endpoint must fail closed until the owner reviews real
  // evaluation evidence and adds a reviewed entry here.
]);

class ModelCatalogError extends Error {
  constructor(message) {
    super(message);
    this.name = "ModelCatalogError";
  }
}

function parseSemver(version) {
  const m = /^([0-9]+)\.([0-9]+)\.([0-9]+)/.exec(typeof version === "string" ? version : "");
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compareSemver(a, b) {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function versionAtLeast(version, min) {
  const v = parseSemver(version);
  const m = parseSemver(min);
  return Boolean(v && m) && compareSemver(v, m) >= 0;
}

function sdkInRange(sdkVersion, range) {
  const v = parseSemver(sdkVersion);
  const lo = parseSemver(range && range.min);
  const hi = parseSemver(range && range.maxExclusive);
  if (!v || !lo || !hi) return false;
  return compareSemver(v, lo) >= 0 && compareSemver(v, hi) < 0;
}

/** Throws ModelCatalogError on any malformed/unsafe entry. Run once at module load (below) so a
 * mistake in a reviewed catalog change fails the build/boot instead of being served silently. */
function assertValidCatalog(entries) {
  if (!Array.isArray(entries)) throw new ModelCatalogError("catalog must be an array");
  let lastGeneration = -Infinity;
  const seenVersions = new Set();
  for (const e of entries) {
    if (e.approval !== "approved") throw new ModelCatalogError(`entry ${e.version}: approval must be "approved"`);
    if (!VERSION_RE.test(e.version)) throw new ModelCatalogError(`entry ${e.version}: invalid version`);
    if (e.release_tag !== `sova-v${e.version}`) throw new ModelCatalogError(`entry ${e.version}: release_tag must match version`);
    if (!Number.isInteger(e.generation) || e.generation <= lastGeneration) {
      throw new ModelCatalogError(`entry ${e.version}: generation must be a strictly increasing integer`);
    }
    lastGeneration = e.generation;
    if (seenVersions.has(e.version)) throw new ModelCatalogError(`entry ${e.version}: duplicate version`);
    seenVersions.add(e.version);
    if (!CHANNELS.includes(e.channel)) throw new ModelCatalogError(`entry ${e.version}: invalid channel`);
    if (!e.files || typeof e.files !== "object" || Array.isArray(e.files) || Object.keys(e.files).length === 0) {
      throw new ModelCatalogError(`entry ${e.version}: files must be a non-empty object`);
    }
    for (const [name, meta] of Object.entries(e.files)) {
      if (!FILE_NAME_RE.test(name)) throw new ModelCatalogError(`entry ${e.version}: unsafe file name ${name}`);
      if (!meta || !SHA256_RE.test(meta.sha256)) throw new ModelCatalogError(`entry ${e.version}: invalid sha256 for ${name}`);
      if (!Number.isInteger(meta.bytes) || meta.bytes <= 0 || meta.bytes > MAX_FILE_BYTES) {
        throw new ModelCatalogError(`entry ${e.version}: invalid size for ${name}`);
      }
    }
    if (!SHA256_RE.test(e.manifest_sha256)) throw new ModelCatalogError(`entry ${e.version}: invalid manifest_sha256`);
    if (!parseSemver(e.compatible_sdk && e.compatible_sdk.min) || !parseSemver(e.compatible_sdk && e.compatible_sdk.maxExclusive)) {
      throw new ModelCatalogError(`entry ${e.version}: invalid compatible_sdk range`);
    }
    if (!parseSemver(e.minAppVersion)) throw new ModelCatalogError(`entry ${e.version}: invalid minAppVersion`);
    if (e.expiresAtMillis !== undefined && !Number.isFinite(e.expiresAtMillis)) {
      throw new ModelCatalogError(`entry ${e.version}: invalid expiresAtMillis`);
    }
    if (e.revoked !== undefined && typeof e.revoked !== "boolean") throw new ModelCatalogError(`entry ${e.version}: revoked must be boolean`);
  }
  return entries;
}

assertValidCatalog(APPROVED_SOVA_CATALOG);

/**
 * Fail-closed selection: returns null (never throws, never guesses, never falls back to an
 * incompatible or expired/revoked entry) unless a currently-approved entry on the requested
 * channel is compatible with the caller's app and SDK version. Among compatible candidates the
 * highest `generation` wins - this can never select a downgrade.
 */
function resolveSovaCatalogEntry({ channel, appVersion, sdkVersion, now = Date.now(), catalog = APPROVED_SOVA_CATALOG }) {
  if (!CHANNELS.includes(channel)) return null;
  let best = null;
  for (const entry of catalog) {
    if (entry.approval !== "approved") continue;
    if (entry.channel !== channel) continue;
    if (entry.revoked) continue;
    if (typeof entry.expiresAtMillis === "number" && now >= entry.expiresAtMillis) continue;
    if (!versionAtLeast(appVersion, entry.minAppVersion)) continue;
    if (!sdkInRange(sdkVersion, entry.compatible_sdk)) continue;
    if (!best || entry.generation > best.generation) best = entry;
  }
  return best;
}

/** Shapes a resolved entry into the exact wire format the Android client parses. */
function toClientCatalog(entry) {
  if (!entry) return null;
  return {
    schema: SCHEMA,
    modelId: entry.model_id,
    channel: entry.channel,
    generation: entry.generation,
    version: entry.version,
    releaseTag: entry.release_tag,
    releaseBaseUrl: RELEASE_BASE_URL + entry.release_tag,
    files: entry.files,
    manifestSha256: entry.manifest_sha256,
    compatibleSdk: entry.compatible_sdk,
    minAppVersion: entry.minAppVersion,
  };
}

module.exports = {
  SCHEMA, RELEASE_BASE_URL, CHANNELS, APPROVED_SOVA_CATALOG,
  ModelCatalogError, assertValidCatalog, resolveSovaCatalogEntry, toClientCatalog,
};
