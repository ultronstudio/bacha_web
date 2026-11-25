"use strict";

/**
 * Server-owned OAuth identity and opaque, rotating session credentials.
 *
 * No Firebase Authentication account is created for new Google users. Legacy
 * Google-linked Firebase UIDs are preserved to retain Play subscriptions,
 * usage counters, reports and historical user data.
 */
const crypto = require("node:crypto");
const { ApiError } = require("./authCore");
const { fs } = require("./fsHelpers");
const { getHmacSecret } = require("./config");

const ACCESS_MS = 20 * 60 * 1000;
const REFRESH_MS = 30 * 24 * 60 * 60 * 1000;
const TOKEN_RE = /^ba_([ar])_([a-f0-9]{32})\.([a-zA-Z0-9_-]{43})$/;

const digest = (s) => crypto.createHash("sha256").update(s).digest("hex");
const random = () => crypto.randomBytes(32).toString("base64url");
const sessionId = () => crypto.randomBytes(16).toString("hex");

function parseCredential(token, kind) {
  if (typeof token !== "string" || token.length > 128) return null;
  const parsed = TOKEN_RE.exec(token);
  return parsed && parsed[1] === kind ? { id: parsed[2], hash: digest(token) } : null;
}
function tokenEqual(a, b) {
  return typeof a === "string" && typeof b === "string" &&
    /^[0-9a-f]{64}$/.test(a) && /^[0-9a-f]{64}$/.test(b) &&
    crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function allowedEmail(email, env = process.env) {
  const mode = env.BACHA_AUTH_MODE || "closed";
  if (mode === "open") return true;
  if (mode !== "closed") return false;
  const allowed = (env.BACHA_AUTH_ALLOWED_GOOGLE_EMAILS || "").split(",")
    .map(x => x.trim().toLowerCase()).filter(Boolean);
  // Empty or invalid allowlist is always CLOSED, not unexpectedly public.
  if (!allowed.length) return false;
  return allowed.includes(String(email || "").toLowerCase());
}
function isAdminUid(uid, env = process.env) {
  return (env.BACHA_ADMIN_UIDS || "").split(",").map(x => x.trim()).filter(Boolean).includes(uid);
}
function stableUid(subject, secret) {
  const h = crypto.createHmac("sha256", secret).update("bacha-user:v1:" + subject).digest("hex");
  return "b_" + h.slice(0, 48);
}
function identityKey(subject, secret) {
  return crypto.createHmac("sha256", secret).update("google-sub:v1:" + subject).digest("hex");
}
function tokenPair(id) {
  return {
    accessToken: "ba_a_" + id + "." + random(),
    refreshToken: "ba_r_" + id + "." + random(),
  };
}
function publicUser(uid, payload, createdAtMillis) {
  return {
    uid, isAnonymous: false,
    email: payload.email,
    displayName: typeof payload.name === "string" ? payload.name.slice(0, 200) : null,
    photoUrl: typeof payload.picture === "string" && payload.picture.startsWith("https://") ? payload.picture.slice(0, 512) : null,
    createdAtMillis,
  };
}

async function findLegacyUid(auth, subject) {
  if (!auth || typeof auth.getUserByProviderUid !== "function") {
    throw new Error("Firebase Admin lookup required for safe identity migration");
  }
  try {
    const found = await auth.getUserByProviderUid("google.com", subject);
    return found.uid;
  } catch (e) {
    if (e?.code === "auth/user-not-found") return null;
    throw e; // Never create another UID when legacy lookup is unavailable.
  }
}

async function findOrCreateUser(db, auth, payload, env, nowMillis) {
  if (typeof payload?.sub !== "string" || !/^[0-9]{5,80}$/.test(payload.sub) ||
      payload.email_verified !== true || typeof payload.email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
    throw new ApiError(401, "unauthenticated", "Neplatná identita Google.");
  }
  if (!allowedEmail(payload.email, env)) {
    throw new ApiError(403, "permission-denied", "Tento Google účet není schválen pro Bacha!.");
  }
  const secret = getHmacSecret(env);
  const ref = db.collection("authIdentities").doc(identityKey(payload.sub, secret));
  const previous = await ref.get();
  const migratedUid = previous.exists ? previous.data().uid : await findLegacyUid(auth, payload.sub);
  const uid = migratedUid || stableUid(payload.sub, secret);
  const userRef = db.collection("users").doc(uid);
  const user = publicUser(uid, payload, nowMillis);
  await db.runTransaction(async tx => {
    const [identity, existingUser] = await Promise.all([tx.get(ref), tx.get(userRef)]);
    if (identity.exists && identity.data().uid !== uid) {
      throw new ApiError(409, "already-exists", "Identita se mezitím změnila. Přihlaste se znovu.");
    }
    if (existingUser.exists && existingUser.data().disabled === true) {
      throw new ApiError(403, "permission-denied", "Tento účet je deaktivovaný.");
    }
    if (!identity.exists) tx.set(ref, { uid, provider: "google.com", createdAtMillis: nowMillis, lastSeenAtMillis: nowMillis });
    else tx.set(ref, { lastSeenAtMillis: nowMillis }, { merge: true });
    tx.set(userRef, {
      accountKind: "google",
      email: user.email,
      displayName: user.displayName,
      createdAtMillis: existingUser.exists ? (existingUser.data().createdAtMillis || nowMillis) : nowMillis,
      lastSeenAt: fs().serverTimestamp(),
    }, { merge: true });
  });
  user.createdAtMillis = previous.exists ? (previous.data().createdAtMillis || nowMillis) : nowMillis;
  return user;
}

async function createSession(db, user, appId, nowMillis = Date.now()) {
  const id = sessionId();
  const pair = tokenPair(id);
  await db.collection("authSessions").doc(id).set({
    uid: user.uid,
    email: user.email,
    appId,
    accessHash: digest(pair.accessToken),
    refreshHash: digest(pair.refreshToken),
    accessExpiresAtMillis: nowMillis + ACCESS_MS,
    refreshExpiresAtMillis: nowMillis + REFRESH_MS,
    createdAtMillis: nowMillis,
    expiresAt: fs().fromMillis(nowMillis + REFRESH_MS),
    revoked: false,
  });
  return { ...pair, accessExpiresAtMillis: nowMillis + ACCESS_MS,
    refreshExpiresAtMillis: nowMillis + REFRESH_MS, user };
}

/** Access verification is server-authoritative on every request. */
async function verifySession(db, token, appId, env = process.env, nowMillis = Date.now()) {
  const parsed = parseCredential(token, "a");
  if (!parsed) return null;
  const snap = await db.collection("authSessions").doc(parsed.id).get();
  const record = snap.data();
  if (!snap.exists || record.revoked || !tokenEqual(record.accessHash, parsed.hash) ||
      record.accessExpiresAtMillis <= nowMillis || record.refreshExpiresAtMillis <= nowMillis ||
      record.appId !== appId || !allowedEmail(record.email, env)) return null;
  return { uid: record.uid, email: record.email,
    firebase: { sign_in_provider: "google.com" }, authSessionId: parsed.id };
}

/** Atomic refresh: replayed refresh tokens fail; previous access token is revoked. */
async function rotateSession(db, refreshToken, appId, env = process.env, nowMillis = Date.now()) {
  const parsed = parseCredential(refreshToken, "r");
  if (!parsed) throw new ApiError(401, "unauthenticated", "Neplatná obnovovací relace.");
  const ref = db.collection("authSessions").doc(parsed.id);
  const pair = tokenPair(parsed.id);
  let uid, email;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const data = snap.data();
    if (!snap.exists || data.revoked || data.appId !== appId ||
        !tokenEqual(data.refreshHash, parsed.hash) || data.refreshExpiresAtMillis <= nowMillis ||
        !allowedEmail(data.email, env)) {
      throw new ApiError(401, "unauthenticated", "Relace vypršela. Přihlaste se znovu.");
    }
    uid = data.uid; email = data.email;
    tx.update(ref, {
      accessHash: digest(pair.accessToken),
      refreshHash: digest(pair.refreshToken),
      accessExpiresAtMillis: nowMillis + ACCESS_MS,
      // Absolute 30-day refresh expiry: no indefinitely living session.
      lastRefreshedAtMillis: nowMillis,
    });
  });
  return { ...pair, accessExpiresAtMillis: nowMillis + ACCESS_MS,
    refreshExpiresAtMillis: (await ref.get()).data().refreshExpiresAtMillis, uid, email };
}

async function revokeSession(db, accessToken, appId) {
  const parsed = parseCredential(accessToken, "a");
  if (!parsed) return false;
  const ref = db.collection("authSessions").doc(parsed.id);
  let revoked = false;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const row = snap.data();
    if (!snap.exists || row.revoked || row.appId !== appId ||
        !tokenEqual(row.accessHash, parsed.hash)) return;
    tx.update(ref, { revoked: true, accessHash: null, refreshHash: null });
    revoked = true;
  });
  return revoked;
}

module.exports = {
  ACCESS_MS, REFRESH_MS, parseCredential, allowedEmail, isAdminUid, stableUid,
  identityKey, findOrCreateUser, createSession, verifySession, rotateSession, revokeSession,
};
