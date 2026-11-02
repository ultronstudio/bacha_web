"use strict";

const { fs } = require("./fsHelpers");

/**
 * Fixed-window, transactional per-user rate limits (spec P0.9).
 * Docs live in the server-only `rateLimits` collection and carry `uid`
 * so account deletion can remove them.
 */
const RATE_LIMITS = Object.freeze({
  analyzeContent: { limit: 10, windowSeconds: 60 },
  lookupThreatIndicators: { limit: 60, windowSeconds: 3600 },
  reportThreat: { limit: 20, windowSeconds: 86400 },
  submitThreatDispute: { limit: 5, windowSeconds: 86400 },
  subscribeThreatWatch: { limit: 50, windowSeconds: 3600 },
  verifyPlayPurchase: { limit: 20, windowSeconds: 3600 },
  deleteUserData: { limit: 5, windowSeconds: 3600 },
  deviceRegistration: { limit: 60, windowSeconds: 3600 },
});

class RateLimitError extends Error {
  constructor(action) {
    super(`Rate limit exceeded for ${action}`);
    this.name = "RateLimitError";
    this.action = action;
  }
}

async function enforceRateLimit(db, uid, action, nowMillis = Date.now()) {
  const cfg = RATE_LIMITS[action];
  if (!cfg) throw new Error(`Unknown rate-limited action ${action}`);
  const windowIndex = Math.floor(nowMillis / 1000 / cfg.windowSeconds);
  const ref = db.collection("rateLimits").doc(`${uid}_${action}_${windowIndex}`);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const count = snap.exists ? snap.data().count || 0 : 0;
    if (count >= cfg.limit) throw new RateLimitError(action);
    tx.set(ref, {
      uid,
      action,
      windowIndex,
      count: count + 1,
      // used by a Firestore TTL policy to clean up old windows
      expiresAt: fs().fromMillis((windowIndex + 2) * cfg.windowSeconds * 1000),
    });
  });
}

module.exports = { RATE_LIMITS, RateLimitError, enforceRateLimit };
