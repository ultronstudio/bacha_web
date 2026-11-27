"use strict";

/**
 * HTTP /api/v1/analyze orchestration.
 * All security gates run before any provider call or quota reservation.
 * Explicit dependencies allow an offline, request-level smoke test with
 * mocked Firebase Auth, App Check, Firestore, and OpenAI HTTP responses.
 */
const { requireRegisteredForAnalysis, readJson, jsonResponse } = require("./authCore");
const { enforceRateLimit } = require("./rateLimit");
const { validateAnalyzeRequest } = require("./limits");
const { analyzeContent } = require("./analysisService");

async function handleAnalyzeHttp({
  request,
  identity,
  db,
  generate,
  providers,
  resolveDomain,
  logger = console,
  now = Date.now,
}) {
  requireRegisteredForAnalysis(identity);
  await enforceRateLimit(db, identity.uid, "analyzeContent", now());
  const input = validateAnalyzeRequest(await readJson(request));
  const result = await analyzeContent({ db, generate, providers, resolveDomain, logger, now }, identity.uid, input);
  return jsonResponse(200, { ok: true, ...result });
}

module.exports = { handleAnalyzeHttp };
