"use strict";

const { isIP } = require("node:net");
const { createHmac } = require("node:crypto");
const { ApiError } = require("./authCore");
const { RateLimitError } = require("./rateLimit");
const { getHmacSecret } = require("./config");
const { fs } = require("./fsHelpers");

const IP_WINDOW_SECONDS = 15 * 60;
const DEFAULT_IP_LIMIT = 100;

/**
 * This is an API-access gate, NOT a Firebase Auth sign-up block.
 *
 * Explicit configuration is required to enable closed beta. An empty allowlist
 * in closed mode fails closed, rather than accidentally granting access.
 */
function enforceBetaAccess(identity, env = process.env) {
  const mode = (env.BETA_ACCESS_MODE || "open").trim();
  if (mode === "open") return;
  if (mode !== "closed") throw new ApiError(503, "unavailable", "Režim přístupu není nastaven.");
  const uids = (env.BETA_ALLOWED_UIDS || "").split(",").map(x => x.trim()).filter(Boolean);
  if (!uids.length || uids.some(uid => !/^[A-Za-z0-9_-]{1,128}$/.test(uid))) {
    throw new ApiError(503, "unavailable", "Přístup k uzavřenému testování není nakonfigurovaný.");
  }
  if (!identity?.uid || !uids.includes(identity.uid)) {
    throw new ApiError(403, "permission-denied", "Tento účet není schválen pro uzavřené testování Bacha!.");
  }
}

/**
 * Vercel overwrites X-Forwarded-For at the trusted platform ingress.
 * Do NOT trust this header outside Vercel: a client could forge it there.
 * See https://vercel.com/docs/headers/request-headers
 */
function trustedVercelIp(request, env = process.env) {
  if (env.VERCEL !== "1") return null;
  const forwarded = request.headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim() || "";
  return isIP(first) ? first : null;
}

function ipRateLimitConfig(env = process.env) {
  if (env.API_IP_RATE_LIMIT_ENABLED !== "1") return null;
  const raw = env.API_IP_RATE_LIMIT_PER_15M;
  const limit = raw === undefined || raw.trim() === "" ? DEFAULT_IP_LIMIT : Number(raw);
  if (!Number.isSafeInteger(limit) || limit < 10 || limit > 10_000) {
    throw new ApiError(503, "unavailable", "Neplatné nastavení API IP rate limitu.");
  }
  return { limit, windowSeconds: IP_WINDOW_SECONDS };
}

/**
 * HMAC IP (not raw IP) into a Firestore document ID. A transaction ensures
 * different serverless instances share the same count and cannot race a bypass.
 * Reads+writes are bounded by existing Firestore TTL on rateLimits.expiresAt.
 */
async function enforceApiIpRateLimit(db, request, env = process.env, nowMillis = Date.now()) {
  const cfg = ipRateLimitConfig(env);
  if (!cfg) return;
  const ip = trustedVercelIp(request, env);
  if (!ip) {
    throw new ApiError(503, "unavailable", "Bezpečné určení IP adresy není dostupné.");
  }
  const secret = getHmacSecret(env);
  const digest = createHmac("sha256", secret).update("bacha-api-ip-v1:" + ip).digest("hex");
  const windowIndex = Math.floor(nowMillis / 1000 / cfg.windowSeconds);
  const ref = db.collection("rateLimits").doc(`api_ip_${digest}_${windowIndex}`);
  await db.runTransaction(async tx => {
    const snapshot = await tx.get(ref);
    const count = snapshot.exists ? snapshot.data().count || 0 : 0;
    if (count >= cfg.limit) throw new RateLimitError("apiIp");
    tx.set(ref, {
      action: "apiIp",
      count: count + 1,
      windowIndex,
      expiresAt: fs().fromMillis((windowIndex + 2) * cfg.windowSeconds * 1000),
    });
  });
}

module.exports = {
  IP_WINDOW_SECONDS, DEFAULT_IP_LIMIT, enforceBetaAccess,
  trustedVercelIp, ipRateLimitConfig, enforceApiIpRateLimit
};
