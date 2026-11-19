"use strict";
const crypto = require("node:crypto");
const { isIP } = require("node:net");
const { ApiError } = require("./authCore");
const { getHmacSecret } = require("./config");
const { fs } = require("./fsHelpers");

const LIMITS = Object.freeze({
  google: { limit: 20, seconds: 3600 },
  refresh: { limit: 120, seconds: 3600 },
});
function trustedIp(request, env = process.env) {
  // Platform overwrites X-Forwarded-For. Never trust arbitrary client headers.
  if (env.VERCEL !== "1") return null;
  const value = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return value && isIP(value) ? value.toLowerCase() : null;
}
async function limitAuthIp(db, request, kind, env = process.env, nowMillis = Date.now()) {
  const policy = LIMITS[kind];
  if (!policy) throw new Error("Unknown authentication rate policy");
  const ip = trustedIp(request, env);
  if (!ip) {
    // Local emulator only: skip Vercel-specific IP requirement.
    if (env.NODE_ENV !== "production" && env.VERCEL !== "1") return;
    throw new ApiError(503, "unavailable", "Ochrana přihlášení není dostupná.");
  }
  const secret = getHmacSecret(env);
  const hmac = crypto.createHmac("sha256", secret).update("bacha-auth-ip:v1:" + ip).digest("hex");
  const window = Math.floor(nowMillis / 1000 / policy.seconds);
  const ref = db.collection("rateLimits").doc(`auth_ip_${kind}_${hmac}_${window}`);
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if ((snap.exists ? snap.data().count || 0 : 0) >= policy.limit) {
      const e = new Error("Too many auth attempts");
      e.name = "RateLimitError";
      throw e;
    }
    tx.set(ref, {
      action: "auth_ip_" + kind, count: (snap.exists ? snap.data().count || 0 : 0) + 1,
      windowIndex: window, expiresAt: fs().fromMillis((window + 2) * policy.seconds * 1000),
    });
  });
}
module.exports = { LIMITS, trustedIp, limitAuthIp };
