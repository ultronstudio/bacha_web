"use strict";
const { ApiError, jsonResponse, readJson } = require("./authCore");
const { limitAuthIp } = require("./authIpGuard");
const { findOrCreateUser, createSession, rotateSession, revokeSession } = require("./serverSessions");

function requireAppCheckHeader(request) {
  const token = request.headers.get("x-firebase-appcheck");
  if (!token || token.length > 4096) throw new ApiError(401, "unauthenticated", "Chybí ověření aplikace.");
  return token;
}
async function verifyAppCheck(request, appCheck) {
  try {
    const check = await appCheck.verifyToken(requireAppCheckHeader(request));
    if (!check?.appId) throw new Error("appId missing");
    return check.appId;
  } catch {
    throw new ApiError(401, "unauthenticated", "Ověření aplikace nebylo platné.");
  }
}
async function handleAuthHttp(request, path, deps) {
  const { db, appCheck, auth, verifyGoogleToken, env = process.env, now = Date.now } = deps;
  if (request.method !== "POST") throw new ApiError(405, "method-not-allowed", "Použijte metodu POST.");
  const appId = await verifyAppCheck(request, appCheck);
  if (path === "auth/google") {
    // Limit BEFORE expensive external Google token verification.
    await limitAuthIp(db, request, "google", env, now());
    const body = await readJson(request);
    if (typeof body.idToken !== "string" || body.idToken.length < 100 || body.idToken.length > 8192) {
      throw new ApiError(400, "invalid-argument", "Neplatný Google ID token.");
    }
    let payload;
    try {
      payload = await verifyGoogleToken(body.idToken);
    } catch {
      throw new ApiError(401, "unauthenticated", "Google přihlášení se nepodařilo ověřit.");
    }
    const user = await findOrCreateUser(db, auth, payload, env, now());
    const session = await createSession(db, user, appId, now());
    return jsonResponse(200, { ok: true, ...session });
  }
  if (path === "auth/refresh") {
    await limitAuthIp(db, request, "refresh", env, now());
    const body = await readJson(request);
    if (typeof body.refreshToken !== "string" || body.refreshToken.length > 128) {
      throw new ApiError(401, "unauthenticated", "Neplatná obnovovací relace.");
    }
    const session = await rotateSession(db, body.refreshToken, appId, env, now());
    return jsonResponse(200, { ok: true, ...session });
  }
  if (path === "auth/logout") {
    const value = request.headers.get("authorization") || "";
    const match = /^Bearer\s+(.+)$/i.exec(value);
    if (!match || !await revokeSession(db, match[1], appId)) {
      throw new ApiError(401, "unauthenticated", "Relace není platná.");
    }
    return jsonResponse(200, { ok: true, success: true });
  }
  throw new ApiError(404, "not-found", "Endpoint neexistuje.");
}

module.exports = { requireAppCheckHeader, verifyAppCheck, handleAuthHttp };
