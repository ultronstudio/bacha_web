"use strict";

const { CHANNELS, resolveSovaCatalogEntry, toClientCatalog, assertValidCatalog, APPROVED_SOVA_CATALOG } = require("./modelCatalog");
const { requireOwnerTestChannelAccess } = require("./sovaOwnerTestAuth");
const { ValidationError } = require("./limits");

const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]{1,32})?$/;

function parseQuery(request) {
  const params = new URL(request.url).searchParams;
  const channel = params.get("channel") || "stable";
  const appVersion = params.get("appVersion") || "0.0.0";
  const sdkVersion = params.get("sdkVersion") || "0.0.0";
  if (!CHANNELS.includes(channel)) throw new ValidationError("Neplatný kanál modelu.");
  if (!VERSION_RE.test(appVersion) || appVersion.length > 48) throw new ValidationError("Neplatná verze aplikace.");
  if (!VERSION_RE.test(sdkVersion) || sdkVersion.length > 48) throw new ValidationError("Neplatná verze SDK.");
  return { channel, appVersion, sdkVersion };
}

/**
 * No-cost dev/test fixture: only ever active outside production, and only when explicitly
 * requested, so the real (currently empty) catalog can never be bypassed in a deployed app.
 * CI/local tests call resolveSovaCatalogEntry directly with their own fixture catalog instead of
 * relying on this env var; it exists for manual/preview smoke testing without touching Firestore
 * or committing a fake "approved" entry to modelCatalog.js.
 */
function devFixtureCatalog() {
  if (process.env.NODE_ENV === "production") return null;
  const raw = process.env.BACHA_MODEL_CATALOG_DEV_FIXTURE;
  if (!raw) return null;
  try {
    return assertValidCatalog(JSON.parse(raw));
  } catch {
    return null; // malformed fixture must never crash the request; falls back to the real catalog
  }
}

/** GET /api/v1/models/sova/latest - metadata only; see modelCatalog.js for the trust model.
 * No Firestore read or write on this path: the catalog is static, reviewed code, not per-user
 * data. [identity] is the already-authenticated caller (App Check + session, enforced upstream
 * in httpApi.ts); it is ONLY used here for the separate owner-test channel authorization check -
 * never persisted, never logged. */
async function handleModelCatalogLatest(request, identity) {
  const { channel, appVersion, sdkVersion } = parseQuery(request);
  if (channel === "owner-test") requireOwnerTestChannelAccess(identity);
  const catalog = devFixtureCatalog() || APPROVED_SOVA_CATALOG;
  const entry = resolveSovaCatalogEntry({ channel, appVersion, sdkVersion, catalog });
  if (!entry) return { ok: true, available: false, reason: "no_approved_version" };
  return { ok: true, available: true, catalog: toClientCatalog(entry) };
}

module.exports = { handleModelCatalogLatest, parseQuery, devFixtureCatalog };
