"use strict";

const { createHmac } = require("node:crypto");
const { isIP } = require("node:net");
const { fs } = require("./fsHelpers");
const { getHmacSecret } = require("./config");
const { ApiError } = require("./authCore");
const { RateLimitError } = require("./rateLimit");

/**
 * Per-source quotas supplement existing per-UID Firestore quotas.
 * These never govern Firebase Auth account creation: Auth SDK talks to Google
 * directly and never passes through /api/v1 on Vercel.
 *
 * Keep limits generous enough for multiple legitimate users behind one NAT.
 */
const IP_RATE_POLICIES = Object.freeze({
  analyze: { limit: 30, windowSeconds: 900 },
  threatLookup: { limit: 120, windowSeconds: 3600 },
  threatReport: { limit: 30, windowSeconds: 3600 },
  threatDispute: { limit: 20, windowSeconds: 3600 },
  threatWatchWrite: { limit: 60, windowSeconds: 3600 },
  watchRead: { limit: 180, windowSeconds: 3600 },
  accountRead: { limit: 240, windowSeconds: 3600 },
  billingVerify: { limit: 30, windowSeconds: 3600 },
  deviceWrite: { limit: 30, windowSeconds: 900 },
  deviceDelete: { limit: 60, windowSeconds: 3600 },
});

/**
 * Limit only recognized authenticated client routes. Cron jobs and Play RTDN
 * enter through independent authenticated handlers, never via this function.
 */
function apiIpPolicy(method, path) {
  const verb = String(method).toUpperCase();
  if (path === "analyze" && verb === "POST") return "analyze";
  if (path === "threats/lookup" && verb === "POST") return "threatLookup";
  if (path === "threats/report" && verb === "POST") return "threatReport";
  if (path === "threats/dispute" && verb === "POST") return "threatDispute";
  if (path === "threats/watch" && verb === "PUT") return "threatWatchWrite";
  if (path === "threats/watches" && verb === "GET") return "watchRead";
  if (path === "me" && verb === "GET") return "accountRead";
  if (path === "billing/verify" && verb === "POST") return "billingVerify";
  if (/^devices\/[A-Za-z0-9_-]{1,128}$/.test(path)) {
    if (verb === "PUT" || verb === "PATCH") return "deviceWrite";
    if (verb === "DELETE") return "deviceDelete";
  }
  // Account deletion remains usable even for blocked/revoked beta users.
  // Admin endpoints remain limited by requireAdmin and their own validation.
  return null;
}

/**
 * Only Vercel's overwritten X-Forwarded-For is trusted. Never use arbitrary
 * X-Real-IP/Client-IP headers, and do not accept unvalidated IP strings.
 * If Vercel's trusted header is absent, fail closed for protected routes.
 */
function trustedVercelClientIp(headers, env = process.env) {
  if (env.VERCEL !== "1") return null;
  const value = headers.get("x-forwarded-for");
  if (!value) return null;
  // Vercel overwrites this header at the edge; the left-most address is
  // the visitor (never trust forwarded headers on non-Vercel deployments).
  const candidate = value.split(",")[0].trim();
  return isIP(candidate) ? candidate.toLowerCase() : null;
}

function betaAccessAllowed(uid, env = process.env) {
  const setting = env.BACHA_BETA_ALLOWED_UIDS;
  if (!setting) return true; // Optional: allow public launch without a code change.
  const allowed = setting.split(",").map((id) => id.trim()).filter(Boolean);
  return allowed.includes(uid);
}

function enforceBetaAccess(uid, method, path, env = process.env) {
  // Do not prevent account deletion or signed-out cleanup.
  if ((path === "account" && method === "DELETE") ||
      (/^devices\/[A-Za-z0-9_-]{1,128}$/.test(path) && method === "DELETE")) return;
  if (!betaAccessAllowed(uid, env)) {
    throw new ApiError(403, "permission-denied", "Tento účet nemá přístup ke cloudovým funkcím uzavřeného testování.");
  }
}

function ipRateKey(secret, ip, action, windowIndex) {
  const digest = createHmac("sha256", secret)
    .update("bacha-api-ip-limit:v1\0" + ip)
    .digest("hex");
  return "ip_v1_" + action + "_" + digest + "_" + windowIndex;
}

async function enforceApiIpRateLimit(db, request, method, path, env = process.env, nowMillis = Date.now()) {
  const action = apiIpPolicy(method, path);
  if (!action) return;
  if (env.VERCEL !== "1") {
    if (env.NODE_ENV === "production") {
      throw new ApiError(503, "unavailable", "Ochranu požadavků se nepodařilo ověřit.");
    }
    return; // Local emulator and offline tests use per-UID protection only.
  }
  const ip = trustedVercelClientIp(request.headers, env);
  if (!ip) throw new ApiError(503, "unavailable", "Ochranu požadavků se nepodařilo ověřit.");

  // Reuse an existing 32+ character server secret, domain-separated from
  // threat indicator HMAC keys. No raw IP or token is persisted or logged.
  const secret = getHmacSecret(env);
  const policy = IP_RATE_POLICIES[action];
  const windowIndex = Math.floor(nowMillis / 1000 / policy.windowSeconds);
  const ref = db.collection("rateLimits").doc(ipRateKey(secret, ip, action, windowIndex));

  await db.runTransaction(async (tx) => {
    const snapshot = await tx.get(ref);
    const count = snapshot.exists ? snapshot.data().count || 0 : 0;
    if (count >= policy.limit) {
      const windowEndMillis = (windowIndex + 1) * policy.windowSeconds * 1000;
      throw new RateLimitError(action, { scope: "ip", retryAfterSeconds: Math.max(1, Math.ceil((windowEndMillis - nowMillis) / 1000)) });
    }
    tx.set(ref, {
      action: "ip:" + action,
      scope: "ip",
      count: count + 1,
      windowIndex,
      expiresAt: fs().fromMillis((windowIndex + 2) * policy.windowSeconds * 1000),
    });
  });
}

module.exports = {
  IP_RATE_POLICIES, apiIpPolicy, trustedVercelClientIp, betaAccessAllowed,
  enforceBetaAccess, ipRateKey, enforceApiIpRateLimit
};
