import "server-only";

import type { DecodedIdToken } from "firebase-admin/auth";
import { firebaseAppCheck, firebaseAuth } from "./firebaseAdmin";
import { ApiError, errorResponse, jsonResponse, readJson, requireAdmin, requireIdentityWith } from "./authCore.js";

export { ApiError, errorResponse, jsonResponse, readJson, requireAdmin };

export async function requireIdentity(request: Request): Promise<DecodedIdToken> {
  if (!/^Bearer\s+.+$/i.test(request.headers.get("authorization") || "")) {
    throw new ApiError(401, "unauthenticated", "Chybí platný přihlašovací token.");
  }
  if (!request.headers.get("x-firebase-appcheck")) {
    throw new ApiError(401, "unauthenticated", "Chybí platný App Check token.");
  }
  return requireIdentityWith(request, firebaseAuth(), firebaseAppCheck());
}

export const noStoreHeaders = { "Cache-Control": "no-store, max-age=0" };
