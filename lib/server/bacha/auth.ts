import "server-only";

import type { DecodedIdToken } from "firebase-admin/auth";
import { firebaseAppCheck, firebaseAuth, firestore } from "./firebaseAdmin";
import { ApiError, errorResponse, jsonResponse, readJson, requireAdmin, requireRegisteredForAnalysis, requireIdentityWith } from "./authCore.js";
import { verifySession, isAdminUid, allowedEmail } from "./serverSessions.js";

export { ApiError, errorResponse, jsonResponse, readJson, requireAdmin, requireRegisteredForAnalysis };

export async function requireIdentity(request: Request): Promise<DecodedIdToken> {
  const match = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") || "");
  if (!match) throw new ApiError(401, "unauthenticated", "Chybí platná relace.");
  const appToken = request.headers.get("x-firebase-appcheck");
  if (!appToken) throw new ApiError(401, "unauthenticated", "Chybí ověření aplikace.");

  // New app: opaque server-issued access token, never a Firebase Auth ID token.
  if (match[1].startsWith("ba_")) {
    let appId: string;
    try {
      const app = await firebaseAppCheck().verifyToken(appToken);
      appId = app.appId;
    } catch {
      throw new ApiError(401, "unauthenticated", "Ověření aplikace není platné.");
    }
    const session = await verifySession(firestore(), match[1], appId);
    if (!session) throw new ApiError(401, "unauthenticated", "Relace vypršela.");
    return { ...session, admin: isAdminUid(session.uid) } as unknown as DecodedIdToken;
  }

  // Staged rollout: old Play builds use Firebase Auth; stop accepting these
  // tokens by setting BACHA_LEGACY_FIREBASE_AUTH=0 after all clients migrate.
  if (process.env.BACHA_LEGACY_FIREBASE_AUTH === "0") {
    throw new ApiError(401, "unauthenticated", "Je potřeba aktualizovat aplikaci.");
  }
  const legacy = await requireIdentityWith(request, firebaseAuth(), firebaseAppCheck());
  if (process.env.BACHA_AUTH_MODE !== "open" &&
      (legacy.firebase?.sign_in_provider !== "google.com" || legacy.email_verified !== true ||
       !allowedEmail(legacy.email))) {
    throw new ApiError(403, "permission-denied", "Tento Google účet není schválen pro testování.");
  }
  return legacy;
}

export const noStoreHeaders = { "Cache-Control": "no-store, max-age=0" };
