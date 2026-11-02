"use strict";

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function requireIdentityWith(request, auth, appCheck) {
  const authorization = request.headers.get("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match) throw new ApiError(401, "unauthenticated", "Chybí platný přihlašovací token.");
  const appCheckToken = request.headers.get("x-firebase-appcheck");
  if (!appCheckToken) throw new ApiError(401, "unauthenticated", "Chybí platný App Check token.");
  try {
    const [decoded] = await Promise.all([
      auth.verifyIdToken(match[1], true),
      appCheck.verifyToken(appCheckToken),
    ]);
    return decoded;
  } catch {
    throw new ApiError(401, "unauthenticated", "Přihlášení nebo ověření aplikace není platné.");
  }
}

function requireAdmin(identity) {
  if (identity.admin !== true) throw new ApiError(403, "permission-denied", "Pouze pro moderátory.");
}

function jsonResponse(status, body) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store, max-age=0" } });
}

function errorResponse(error, fallbackMessage = "Požadavek se nepodařilo dokončit.") {
  const candidate = error || {};
  let status = candidate.status || 500;
  let code = typeof candidate.code === "string" ? candidate.code : "internal";
  let message = candidate.message || fallbackMessage;
  if (candidate.name === "ValidationError") {
    status = 400; code = "invalid-argument";
  } else if (candidate.name === "RateLimitError") {
    status = 429; code = "resource-exhausted"; message = "Příliš mnoho požadavků. Zkuste to prosím později.";
  } else if (candidate.name === "AnalysisUnavailableError") {
    status = 503; code = "unavailable";
  }
  const statusMap = {
    unauthenticated: 401, "permission-denied": 403, "invalid-argument": 400,
    "resource-exhausted": 429, "already-exists": 409, "failed-precondition": 412,
    unavailable: 503, internal: 500, "not-found": 404, "method-not-allowed": 405,
    "payload-too-large": 413,
  };
  if (!Object.hasOwn(statusMap, code)) code = "internal";
  status = statusMap[code] || status;
  if (status >= 500) {
    console.error("Bacha API failure", { code, message: candidate.message || "unknown" });
    message = fallbackMessage;
  }
  return jsonResponse(status, { ok: false, error: { code, message } });
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 3_500_000) throw new ApiError(413, "payload-too-large", "Požadavek je příliš velký.");
  try {
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid object");
    return value;
  } catch {
    throw new ApiError(400, "invalid-argument", "Neplatné JSON tělo požadavku.");
  }
}

module.exports = { ApiError, requireIdentityWith, requireAdmin, jsonResponse, errorResponse, readJson };
