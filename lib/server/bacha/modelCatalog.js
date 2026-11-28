"use strict";

/**
 * Versioned, signed model catalog contract shared with the Android app and with SOVA's own
 * signed release manifest. See the canonical schema doc in the Android repo:
 * ultronstudio/bacha docs/model-catalog-schema.md (also: ml/sova.lock.json for the existing
 * build-time pinning this complements).
 *
 * This module is the ONLY place that lists which SOVA model generations this backend will ever
 * point an app at. It is a POINTER, not a trust anchor: every entry names an exact SOVA GitHub
 * release that is already independently signed twice - an offline author Ed25519 signature over
 * manifest.json, and a separate CI-receipt Ed25519 signature over provenance.json (see
 * sova/scripts/verify_release.py and bacha/scripts/ml/verify_sova_release.py). The Android app
 * verifies both signatures itself with public keys baked into the APK at build time; it must
 * NEVER trust this HTTP response, HTTPS alone, or any server-provided checksum as sufficient
 * proof of authenticity. `generation`/`channel`/`expires_at`/`revoked` here are a CONVENIENCE
 * mirror of the same-named fields SOVA now signs directly inside manifest.json (see
 * sova/scripts/package_release.py) - the Android client re-derives the authoritative values
 * from the signed manifest it downloads and must never trust this entry's copy of them alone
 * (see SovaReleaseVerifier in the Android repo).
 *
 * Entries live in sovaCatalogEntries.json and are added ONLY by a reviewed code change + manual
 * owner deploy - never from a database, admin API, or request body - so "approved" stays an
 * explicit, auditable decision and there is exactly one trust/approval path (the same one
 * ml/sova.lock.json already uses). The JSON-file split (rather than inlining the array in this
 * module) exists so SOVA's review-only catalog-proposal automation
 * (.github/workflows/sova-catalog-proposal.yml) can safely append a candidate entry with a
 * trivial, non-fragile read-modify-write - it still only ever produces a PR for a human to
 * review and merge, never a direct write to this repository's default branch.
 *
 * Free vs. private distribution: `releaseBaseUrl` always points at a GitHub release tag in
 * ultronstudio/sova. Only a release that is ALSO made public (or otherwise made fetchable
 * without a private token) may ever be the target of an entry here - this catalog must never be
 * the mechanism that makes a still-private experimental release reachable. Promoting a release
 * from private/experimental to the kind of "approved" entry this file accepts is therefore two
 * separate owner decisions: (1) SOVA repository/release visibility (an explicit SOVA-side
 * action, never automated by this bridge or by Android), and (2) adding the reviewed entry here.
 * Neither this module nor the proposal automation ever flips a SOVA release's visibility.
 */

const SCHEMA = 1;
const RELEASE_BASE_URL = "https://github.com/ultronstudio/sova/releases/download/";
const CHANNELS = Object.freeze(["owner-test", "stable"]);
const MODEL_IDS = Object.freeze(["sova"]);
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]{1,32})?$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const MAX_FILE_BYTES = 200 * 1024 * 1024; // bounded payload; real SOVA bundles are a few tens of MB
const MAX_FILES_PER_ENTRY = 16;

/**
 * One entry per approved, released SOVA generation. Field names/shapes below intentionally
 * mirror what sova/scripts/package_release.py now signs inside manifest.json; see the file-level
 * comment above for why that is a convenience mirror, not a second trust path.
 *
 *  model_id        allowlisted logical model family (MODEL_IDS).
 *  channel         "owner-test" | "stable". Only "stable" is ever offered outside explicit owner testing.
 *  generation      positive integer; strictly increasing per channel (enforced by assertValidCatalog).
 *  version         exact SOVA semver - never "latest".
 *  release_tag     exact GitHub release tag; files are fetched from RELEASE_BASE_URL + this tag.
 *  files           exact inventory: { name: { sha256, bytes } }; re-verified client-side against
 *                  the downloaded, author-signed manifest.json - these hashes are a convenience
 *                  cross-check, not the trust anchor.
 *  manifest_sha256 pins manifest.json's own hash (defense in depth alongside the Ed25519 signature).
 *  compatible_sdk  { min, maxExclusive } Android SOVA SDK range (mirrors ml/sova.lock.json).
 *  minAppVersion   minimum Bacha app semver allowed to receive this generation.
 *  approval        must be exactly "approved"; anything else can never be served (fail-closed).
 *  expires_at      optional ISO-8601 UTC string; the entry is ignored once now() reaches it.
 *  revoked         optional kill switch; true removes the entry from consideration immediately.
 */
const APPROVED_SOVA_CATALOG = Object.freeze(require("./sovaCatalogEntries.json"));

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

function parseExpiresAtMillis(expiresAt) {
  if (expiresAt === undefined || expiresAt === null) return null;
  const ms = Date.parse(expiresAt);
  if (Number.isNaN(ms)) throw new ModelCatalogError(`invalid expires_at: ${expiresAt}`);
  return ms;
}

/** Throws ModelCatalogError on any malformed/unsafe entry. Run once at module load (below) so a
 * mistake in a reviewed catalog change fails the build/boot instead of being served silently. */
function assertValidCatalog(entries) {
  if (!Array.isArray(entries)) throw new ModelCatalogError("catalog must be an array");
  const lastGenerationByChannel = new Map();
  const seenVersions = new Set();
  for (const e of entries) {
    if (!MODEL_IDS.includes(e.model_id)) throw new ModelCatalogError(`entry ${e.version}: model_id must be one of ${MODEL_IDS}`);
    if (e.approval !== "approved") throw new ModelCatalogError(`entry ${e.version}: approval must be "approved"`);
    if (!VERSION_RE.test(e.version)) throw new ModelCatalogError(`entry ${e.version}: invalid version`);
    if (e.release_tag !== `sova-v${e.version}`) throw new ModelCatalogError(`entry ${e.version}: release_tag must match version`);
    if (!CHANNELS.includes(e.channel)) throw new ModelCatalogError(`entry ${e.version}: invalid channel`);
    if (!Number.isInteger(e.generation) || e.generation < 1) {
      throw new ModelCatalogError(`entry ${e.version}: generation must be a positive integer`);
    }
    const lastGeneration = lastGenerationByChannel.get(e.channel) ?? -Infinity;
    if (e.generation <= lastGeneration) {
      throw new ModelCatalogError(`entry ${e.version}: generation must be strictly increasing within channel ${e.channel}`);
    }
    lastGenerationByChannel.set(e.channel, e.generation);
    if (seenVersions.has(e.version)) throw new ModelCatalogError(`entry ${e.version}: duplicate version`);
    seenVersions.add(e.version);
    if (!e.files || typeof e.files !== "object" || Array.isArray(e.files)) {
      throw new ModelCatalogError(`entry ${e.version}: files must be an object`);
    }
    const fileNames = Object.keys(e.files);
    if (fileNames.length === 0 || fileNames.length > MAX_FILES_PER_ENTRY) {
      throw new ModelCatalogError(`entry ${e.version}: files must have between 1 and ${MAX_FILES_PER_ENTRY} entries`);
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
    parseExpiresAtMillis(e.expires_at); // throws on malformed; null/undefined is fine
    if (e.revoked !== undefined && typeof e.revoked !== "boolean") throw new ModelCatalogError(`entry ${e.version}: revoked must be boolean`);
  }
  return entries;
}

assertValidCatalog(APPROVED_SOVA_CATALOG);

/**
 * Fail-closed selection: returns null (never throws, never guesses, never falls back to an
 * incompatible or expired/revoked entry) unless a currently-approved entry on the requested
 * channel is compatible with the caller's app and SDK version. Among compatible candidates the
 * highest `generation` wins - this can never select a downgrade. [channel] authorization (who
 * may even ask for "owner-test") is enforced by the HTTP layer (modelCatalogHttp.js), not here -
 * this function is pure selection logic over an already-authorized request.
 */
function resolveSovaCatalogEntry({ channel, appVersion, sdkVersion, now = Date.now(), catalog = APPROVED_SOVA_CATALOG }) {
  if (!CHANNELS.includes(channel)) return null;
  let best = null;
  for (const entry of catalog) {
    if (entry.approval !== "approved") continue;
    if (entry.channel !== channel) continue;
    if (entry.revoked) continue;
    const expiresAtMillis = parseExpiresAtMillis(entry.expires_at);
    if (expiresAtMillis !== null && now >= expiresAtMillis) continue;
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
    expiresAt: entry.expires_at ?? null,
    revoked: entry.revoked === true,
  };
}

module.exports = {
  SCHEMA, RELEASE_BASE_URL, CHANNELS, MODEL_IDS, APPROVED_SOVA_CATALOG,
  ModelCatalogError, assertValidCatalog, resolveSovaCatalogEntry, toClientCatalog, parseExpiresAtMillis,
};
