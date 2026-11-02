"use strict";

class PubSubIdentityError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "PubSubIdentityError";
    this.status = status;
    this.code = code;
  }
}

async function verifyPubSubOidc(token, expectedEmail, audience, verifyIdToken) {
  if (typeof token !== "string" || !token) throw new PubSubIdentityError(401, "unauthenticated", "Chybí OIDC token Pub/Sub.");
  const claims = await verifyIdToken(token, audience);
  if (claims?.email_verified !== true || claims.email?.toLowerCase() !== expectedEmail.toLowerCase()) {
    throw new PubSubIdentityError(403, "permission-denied", "Identita Pub/Sub není povolena.");
  }
  return claims;
}

module.exports = { verifyPubSubOidc, PubSubIdentityError };
