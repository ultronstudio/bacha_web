import "server-only";

import { OAuth2Client } from "google-auth-library";
import { GoogleGenAI } from "@google/genai";
import { google } from "googleapis";
import type { Firestore } from "firebase-admin/firestore";
import { deleteAllUserData } from "./accountDeletion.js";
import { analyzeContent } from "./analysisService.js";
import * as billing from "./billing.js";
import { requireSecret, optionalSecret } from "./config.js";
import { firestore as getFirestore, firebaseAuth } from "./firebaseAdmin";
import { enforceRateLimit, RateLimitError } from "./rateLimit.js";
import * as threatIntel from "./threatIntel.js";
import { fs } from "./fsHelpers.js";
import { validateDeviceId, validateDevicePayload } from "./deviceValidation.js";
import { decodePubSubRtdn } from "./rtdnPayload.js";
import { verifyPubSubOidc } from "./rtdnAuth.js";
import * as limits from "./limits.js";
import { ApiError, errorResponse, jsonResponse, readJson, requireAdmin, requireIdentity } from "./auth";

const playClient = () => {
  const email = requireSecret("PLAY_SERVICE_ACCOUNT_EMAIL");
  const privateKey = requireSecret("PLAY_SERVICE_ACCOUNT_PRIVATE_KEY").replace(/\\n/g, "\n");
  const auth = new google.auth.GoogleAuth({
    credentials: { client_email: email, private_key: privateKey },
    scopes: ["https://www.googleapis.com/auth/androidpublisher"],
  });
  return google.androidpublisher({ version: "v3", auth });
};

type ProviderConstructor = new (options: { apiKey: string | null }) => object;

function instantiateProvider(providerClass: unknown, apiKey: string | null) {
  const Provider = providerClass as ProviderConstructor;
  return new Provider({ apiKey });
}

function providers() {
  return [
    instantiateProvider(threatIntel.GoogleWebRiskProvider, optionalSecret("WEB_RISK_API_KEY")),
    instantiateProvider(threatIntel.PhishTankProvider, optionalSecret("PHISHTANK_API_KEY")),
    instantiateProvider(threatIntel.UrlhausProvider, optionalSecret("URLHAUS_API_KEY")),
  ];
}

function geminiGenerate() {
  const ai = new GoogleGenAI({ apiKey: requireSecret("GEMINI_API_KEY") });
  return async ({ model, systemInstruction, responseSchema, userPrompt, image }: {
    model: string; systemInstruction: string; responseSchema: object; userPrompt: string;
    image: { mimeType: string; base64: string } | null;
  }) => {
    const parts: Array<Record<string, unknown>> = [{ text: userPrompt }];
    if (image) parts.push({ inlineData: { mimeType: image.mimeType, data: image.base64 } });
    const response = await ai.models.generateContent({
      model,
      contents: [{ role: "user", parts }],
      config: { systemInstruction, responseMimeType: "application/json", responseSchema, temperature: 0.1, maxOutputTokens: 2048 },
    });
    return response.text;
  };
}

async function routeOperation(request: Request, segments: string[]) {
  const identity = await requireIdentity(request);
  const uid = identity.uid;
  const firestore = getFirestore();
  const method = request.method.toUpperCase();
  const path = segments.join("/");

  if (path === "analyze" && method === "POST") {
    await enforceRateLimit(firestore, uid, "analyzeContent");
    const input = limits.validateAnalyzeRequest(await readJson(request));
    const result = await analyzeContent({ db: firestore, generate: geminiGenerate(), providers: providers() }, uid, input);
    return jsonResponse(200, { ok: true, ...result });
  }
  if (path === "threats/lookup" && method === "POST") {
    await enforceRateLimit(firestore, uid, "lookupThreatIndicators");
    const indicators = limits.validateLookupRequest(await readJson(request));
    const results = [];
    for (const indicator of indicators) {
      const normalized = threatIntel.normalizeIndicator(indicator.type, indicator.value);
      if (normalized) results.push(await threatIntel.queryThreatIntelligence(firestore, normalized));
    }
    return jsonResponse(200, { ok: true, results });
  }
  if (path === "threats/report" && method === "POST") {
    await enforceRateLimit(firestore, uid, "reportThreat");
    const report = limits.validateReportRequest(await readJson(request));
    const provider = identity.firebase?.sign_in_provider;
    const result = await threatIntel.submitCommunityReport(firestore, uid, report, {
      accountKind: provider === "anonymous" ? "anonymous" : provider ? "google" : "unknown",
    });
    return jsonResponse(200, { ok: true, ...result });
  }
  if (path === "threats/dispute" && method === "POST") {
    await enforceRateLimit(firestore, uid, "submitThreatDispute");
    return jsonResponse(200, { ok: true, ...(await threatIntel.submitDispute(firestore, uid, limits.validateDisputeRequest(await readJson(request)))) });
  }
  if (path === "threats/watch" && method === "PUT") {
    await enforceRateLimit(firestore, uid, "subscribeThreatWatch");
    const input = limits.validateWatchRequest(await readJson(request));
    return jsonResponse(200, { ok: true, ...(await threatIntel.setThreatWatch(firestore, uid, input.lookupKey, input.enabled)) });
  }
  if (path === "threats/watches" && method === "GET") {
    return jsonResponse(200, { ok: true, watches: await threatIntel.listThreatWatches(firestore, uid) });
  }
  if (path === "billing/verify" && method === "POST") {
    await enforceRateLimit(firestore, uid, "verifyPlayPurchase");
    return jsonResponse(200, { ok: true, ...(await billing.verifyAndGrant({ db: firestore, playClient: playClient() }, uid, await readJson(request))) });
  }
  if (path === "account" && method === "DELETE") {
    await enforceRateLimit(firestore, uid, "deleteUserData").catch((error) => {
      if (error instanceof RateLimitError) throw error;
    });
    const result = await deleteAllUserData({ db: firestore, auth: firebaseAuth() }, uid);
    return jsonResponse(200, { ok: true, success: true, authDeleted: result.authDeleted });
  }
  if (path === "admin/threats/moderate" && method === "POST") {
    requireAdmin(identity);
    const data = await readJson(request);
    const lookupKey = limits.validateLookupKey(data.lookupKey);
    const allowed = [threatIntel.VERDICTS.CONFIRMED_MALICIOUS, threatIntel.VERDICTS.SUSPICIOUS, threatIntel.VERDICTS.KNOWN_SAFE, threatIntel.VERDICTS.INACTIVE];
    if (!allowed.includes(data.verdict as string)) throw new limits.ValidationError("NeplatnĂ˝ verdikt.");
    if (typeof data.reason !== "string" || data.reason.trim().length < 5) throw new limits.ValidationError("ChybĂ­ zdĹŻvodnÄ›nĂ­.");
    const result = await threatIntel.applyTrustedVerdict(firestore, {
      lookupKey, verdict: data.verdict, category: limits.REPORT_CATEGORIES.includes(data.category) ? data.category : null,
      sourceType: threatIntel.SOURCE_TYPES.MANUAL_REVIEW, actorUid: uid, reason: data.reason.slice(0, 500),
    });
    return jsonResponse(200, { ok: true, ...result });
  }
  if (path === "admin/disputes/resolve" && method === "POST") {
    requireAdmin(identity);
    const data = await readJson(request);
    if (typeof data.disputeId !== "string" || data.disputeId.length > 200) throw new limits.ValidationError("NeplatnĂ© ID.");
    const result = await threatIntel.resolveDispute(firestore, {
      disputeId: data.disputeId, resolution: data.resolution, newVerdict: data.newVerdict, actorUid: uid, note: data.note,
    });
    return jsonResponse(200, { ok: true, ...result });
  }

  const deviceMatch = /^devices\/([A-Za-z0-9_-]{1,128})$/.exec(path);
  if (deviceMatch) {
    await enforceRateLimit(firestore, uid, "deviceRegistration");
    return handleDevice(request, firestore, uid, deviceMatch[1], method);
  }
  throw new ApiError(404, "not-found", "Endpoint nebyl nalezen.");
}

async function handleDevice(request: Request, firestore: Firestore, uid: string, deviceId: string, method: string) {
  validateDeviceId(deviceId);
  const ref = firestore.collection("users").doc(uid).collection("devices").doc(deviceId);
  if (method === "DELETE") {
    await ref.delete();
    return jsonResponse(200, { ok: true, success: true });
  }
  if (method !== "PUT" && method !== "PATCH") throw new ApiError(405, "method-not-allowed", "Metoda nenĂ­ podporovĂˇna.");
  const data = validateDevicePayload(await readJson(request), method);
  const existing = method === "PATCH" ? await ref.get() : null;
  const permissionGranted = typeof data.permissionGranted === "boolean"
    ? data.permissionGranted
    : existing?.data()?.permissionGranted === true;
  const notificationsEnabled = typeof data.notificationsEnabled === "boolean"
    ? data.notificationsEnabled
    : existing?.data()?.notificationsEnabled === true;
  await ref.set({
    ...data,
    permissionGranted,
    notificationsEnabled: notificationsEnabled && permissionGranted,
    lastSeenAt: fs().serverTimestamp(),
  }, { merge: method === "PATCH" });
  return jsonResponse(200, { ok: true, success: true, deviceId });
}

export async function handleV1(request: Request, segments: string[]) {
  try {
    return await routeOperation(request, segments);
  } catch (error) {
    return errorResponse(error);
  }
}

export async function handleRtdn(request: Request) {
  try {
    const firestore = getFirestore();
    const authorization = request.headers.get("authorization") || "";
    const match = /^Bearer\s+(.+)$/i.exec(authorization);
    const expectedEmail = requireSecret("PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL").toLowerCase();
    const expectedAudience = requireSecret("PUBSUB_PUSH_AUDIENCE");
    await verifyPubSubOidc(match?.[1], expectedEmail, expectedAudience, async (token: string, audience: string) => {
      const ticket = await new OAuth2Client().verifyIdToken({ idToken: token, audience });
      return ticket.getPayload();
    });

    const payload = decodePubSubRtdn(await readJson(request));
    const result = await billing.handleRtdn({ db: firestore, playClient: playClient() }, payload);
    return jsonResponse(200, { ok: true, ...result });
  } catch (error) {
    return errorResponse(error, "RTDN se nepodaĹ™ilo zpracovat.");
  }
}

export async function handleCron(request: Request) {
  try {
    const firestore = getFirestore();
    const cronSecret = requireSecret("CRON_SECRET");
    if (cronSecret.length < 32) throw new Error("CRON_SECRET must be at least 32 characters.");
    if (request.headers.get("authorization") !== `Bearer ${cronSecret}`) {
      throw new ApiError(401, "unauthenticated", "NeplatnĂˇ autorizace cron Ăşlohy.");
    }
    const result = await threatIntel.revalidateExpiredIndicators(firestore);
    return jsonResponse(200, { ok: true, ...result });
  } catch (error) {
    return errorResponse(error, "Revalidaci hrozeb se nepodaĹ™ilo dokonÄŤit.");
  }
}
