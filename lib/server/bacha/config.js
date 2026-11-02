"use strict";

/**
 * Central backend configuration & secret management.
 *
 * All secrets are declared with `defineSecret`, which means they live in
 * Google Cloud Secret Manager and are bound to each function at deploy time.
 * A missing secret makes `firebase deploy` fail – there is intentionally
 * NO hardcoded fallback value for any secret (spec P0.10).
 */
const REGION = "europe-west1";
const PACKAGE_NAME = "cz.petrvurm.bacha";
const PRODUCT_ID = "bacha_plus";
const ALLOWED_BASE_PLANS = ["monthly", "yearly"];

/** Server is the only authority for quotas (spec P1.10). */
const FREE_MONTHLY_LIMIT = 5;
const PLUS_MONTHLY_LIMIT = 100;

const GEMINI_MODEL = "gemini-2.5-flash";

/** Minimum acceptable HMAC secret length (bytes of entropy encoded as chars). */
const MIN_HMAC_SECRET_LENGTH = 32;

/**
 * Reads a secret value. Throws when it is not configured so that callers
 * fail closed instead of silently degrading to an insecure default.
 * `env` is injectable for tests.
 */
function requireSecret(name, env = process.env) {
  const value = env[name];
  if (!value || typeof value !== "string" || value.trim() === "") {
    throw new Error(`Required server secret ${name} is not configured.`);
  }
  return value;
}

/** Optional secrets (external providers) – absence disables that provider. */
function optionalSecret(name, env = process.env) {
  const value = env[name];
  return value && typeof value === "string" && value.trim() !== "" ? value : null;
}

function getHmacSecret(env = process.env) {
  const secret = requireSecret("THREAT_INTEL_HMAC_SECRET", env);
  if (secret.length < MIN_HMAC_SECRET_LENGTH) {
    throw new Error(
      `THREAT_INTEL_HMAC_SECRET must be at least ${MIN_HMAC_SECRET_LENGTH} characters long.`
    );
  }
  return secret;
}

module.exports = {
  REGION,
  PACKAGE_NAME,
  PRODUCT_ID,
  ALLOWED_BASE_PLANS,
  FREE_MONTHLY_LIMIT,
  PLUS_MONTHLY_LIMIT,
  GEMINI_MODEL,
  MIN_HMAC_SECRET_LENGTH,
  requireSecret,
  optionalSecret,
  getHmacSecret,
};
