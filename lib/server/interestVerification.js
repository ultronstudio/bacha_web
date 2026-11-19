"use strict";

const { createHash, createHmac, randomBytes } = require("node:crypto");
const { domainToASCII } = require("node:url");
const { fs } = require("./bacha/fsHelpers");

const HOUR = 60 * 60 * 1000;
const PENDING_MS = 24 * HOUR;
const RETAIN_MS = 7 * 24 * HOUR;
const CLAIM_MS = 2 * 60 * 1000;

// Deliberately conservative: block well-known disposable inboxes, not all
// privacy-oriented providers. Extend without a deploy with the env variable.
const DISPOSABLE_DOMAINS = new Set([
  "anonmart.com", "10minutemail.com", "10minutemail.net", "20minutemail.com",
  "dispostable.com", "emailondeck.com", "fakeinbox.com", "getnada.com",
  "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "guerrillamailblock.com", "grr.la", "maildrop.cc", "mailinator.com",
  "mailinator.net", "mailnesia.com", "mintemail.com", "mohmal.com",
  "mytemp.email", "sharklasers.com", "temp-mail.org", "temp-mail.io",
  "tempail.com", "tempmail.com", "tempmail.net", "tempmail.org",
  "throwawaymail.com", "trashmail.com", "trashmail.net", "trash-mail.com",
  "yopmail.com", "yopmail.fr", "yopmail.net"
]);

function isDisposableDomain(domain, extra = "") {
  const blocked = new Set([
    ...DISPOSABLE_DOMAINS,
    ...extra.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean)
  ]);
  const normalized = String(domain).trim().toLowerCase();
  return [...blocked].some((candidate) => normalized === candidate || normalized.endsWith("." + candidate));
}

function normalizeTesterEmail(input, extraBlocked = "") {
  if (typeof input !== "string") return { error: "invalid" };
  const email = input.trim();
  if (Buffer.byteLength(email, "utf8") > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) return { error: "invalid" };
  const [local, rawDomain] = email.split("@");
  const domain = domainToASCII(rawDomain).toLowerCase();
  if (!local || local.length > 64 || !domain || domain.length > 253 ||
      !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(domain) || domain.split(".").some((part) => part.startsWith("-") || part.endsWith("-"))) {
    return { error: "invalid" };
  }
  if (isDisposableDomain(domain, extraBlocked)) return { error: "disposable" };
  return { email: local + "@" + domain };
}

function createToken() { return randomBytes(32).toString("base64url"); }
function tokenId(token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return createHash("sha256").update(token).digest("hex");
}

function hmac(secret, value) { return createHmac("sha256", secret).update(value).digest("hex"); }

/** Distributed, transactional protection; reuses rateLimits' existing Firestore TTL. */
async function enforceInterestLimits(db, secret, ip, email, now = Date.now()) {
  if (!secret) throw new Error("Missing interest rate-limit secret");
  const specs = [
    { name: "ip", value: ip, period: 15 * 60 * 1000, limit: 5 },
    { name: "email", value: email.toLowerCase(), period: 24 * HOUR, limit: 3 }
  ].map((spec) => {
    const bucket = Math.floor(now / spec.period);
    return {
      ...spec,
      ref: db.collection("rateLimits").doc("interest_" + spec.name + "_" + hmac(secret, spec.name + ":" + spec.value) + "_" + bucket),
      expires: (bucket + 2) * spec.period
    };
  });
  return db.runTransaction(async (tx) => {
    const snapshots = [];
    for (const spec of specs) snapshots.push(await tx.get(spec.ref));
    if (snapshots.some((snapshot, index) => (snapshot.exists ? snapshot.data().count || 0 : 0) >= specs[index].limit)) {
      return false;
    }
    specs.forEach((spec, index) => tx.set(spec.ref, {
      action: "interestEmailVerification",
      count: (snapshots[index].exists ? snapshots[index].data().count || 0 : 0) + 1,
      expiresAt: fs().fromMillis(spec.expires)
    }));
    return true;
  });
}

async function createPendingVerification(db, email, token, now = Date.now()) {
  const id = tokenId(token);
  if (!id) throw new Error("Invalid confirmation token");
  await db.collection("testingInterestVerifications").doc(id).create({
    email, status: "pending", createdAtMs: now, expiresAtMs: now + PENDING_MS,
    expiresAt: fs().fromMillis(now + PENDING_MS)
  });
  return id;
}

async function getVerificationState(db, token, now = Date.now()) {
  const id = tokenId(token);
  if (!id) return "invalid";
  const snapshot = await db.collection("testingInterestVerifications").doc(id).get();
  if (!snapshot.exists) return "invalid";
  const data = snapshot.data();
  if (!data || data.expiresAtMs <= now) return "expired";
  if (data.status === "notified") return "notified";
  if (data.status === "sending" && (data.claimedAtMs || 0) + CLAIM_MS > now) return "sending";
  return "ready";
}

/** Claim the link in a transaction; external Resend request runs only after commit. */
async function claimVerification(db, token, now = Date.now()) {
  const id = tokenId(token);
  if (!id) return { state: "invalid" };
  const ref = db.collection("testingInterestVerifications").doc(id);
  return db.runTransaction(async (tx) => {
    const snapshot = await tx.get(ref);
    if (!snapshot.exists) return { state: "invalid" };
    const data = snapshot.data();
    if (!data || data.expiresAtMs <= now) return { state: "expired" };
    if (data.status === "notified") return { state: "notified" };
    if (data.status === "sending" && (data.claimedAtMs || 0) + CLAIM_MS > now) return { state: "sending" };
    tx.update(ref, {
      status: "sending", claimedAtMs: now, verifiedAtMs: data.verifiedAtMs || now,
      expiresAtMs: now + RETAIN_MS, expiresAt: fs().fromMillis(now + RETAIN_MS)
    });
    return { state: "send", id, email: data.email, claim: now };
  });
}

async function finishVerification(db, id, claim, succeeded) {
  const ref = db.collection("testingInterestVerifications").doc(id);
  return db.runTransaction(async (tx) => {
    const snapshot = await tx.get(ref);
    const data = snapshot.data();
    if (!snapshot.exists || data?.status !== "sending" || data.claimedAtMs !== claim) return;
    tx.update(ref, succeeded
      ? { status: "notified", notifiedAtMs: Date.now() }
      : { status: "verified" }); // Retry can send the notification after transient failure.
  });
}

module.exports = {
  normalizeTesterEmail, isDisposableDomain, createToken, tokenId,
  enforceInterestLimits, createPendingVerification,
  getVerificationState, claimVerification, finishVerification
};
