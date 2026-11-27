"use strict";

/**
 * Single production AI pipeline (spec P1.1):
 *   Auth -> App Check -> registered account -> rate limit -> input validation
 *   -> threat intelligence -> quota reservation -> OpenAI (schema constrained)
 *   -> output validation -> evidence-based verdict -> AnalysisResult
 */
const threatIntel = require("./threatIntel");
const { OPENAI_MODEL } = require("./config");
const { SYSTEM_INSTRUCTION, RESPONSE_SCHEMA, buildUserPrompt, validateAiOutput } = require("./aiOutput");
const { combineServerVerdict } = require("./riskEngine");
const { reconcilePickup } = require("./pickupContext");
const { lookupDomainAge, inspectThroughWorker, metadataSignals } = require("./urlMetadata");
const ledger = require("./analysisLedger");
const { assessUrlDomains } = require("./domainFacts");

const AI_TIMEOUT_MS = 45000;

class AnalysisUnavailableError extends Error {
  /**
   * @param reason provider_rate_limited | provider_timeout | provider_error | invalid_output
   */
  constructor(message, cause, reason = "provider_error", retryAfterSeconds = null) {
    super(message);
    this.name = "AnalysisUnavailableError";
    this.cause = cause;
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Classifies a provider failure without exposing its body (may contain user input). */
function providerFailureReason(e) {
  if (e && e.providerStatus === 429) return { reason: "provider_rate_limited", retryAfterSeconds: e.retryAfterSeconds || 30 };
  if (e && (e.name === "TimeoutError" || e.name === "AbortError" || /timed out/i.test(String(e.message)))) {
    return { reason: "provider_timeout", retryAfterSeconds: null };
  }
  return { reason: "provider_error", retryAfterSeconds: null };
}

/** Structured lifecycle event: technical ids only, never content, tokens or personal data. */
function logEvent(logger, evt, fields) {
  try {
    (logger.info || logger.log).call(logger, JSON.stringify({ evt, ...fields }));
  } catch {
    /* logging must never break analysis */
  }
}

const getCurrentPeriod = ledger.getCurrentPeriod;

function withTimeout(promise, ms, label) {
  let timer;
  const t = new Promise((_, rej) => {
    timer = setTimeout(() => rej(new Error(`${label} timed out`)), ms);
  });
  return Promise.race([promise, t]).finally(() => clearTimeout(timer));
}

async function resolveThreatReputation(db, text, providers, logger) {
  const candidates = threatIntel.extractCandidateIndicators(text || "");
  const reps = [];
  for (const cand of candidates) {
    let rep = await threatIntel.queryThreatIntelligence(db, cand);
    if (cand.type === threatIntel.INDICATOR_TYPES.URL && rep.verdict !== threatIntel.VERDICTS.CONFIRMED_MALICIOUS) {
      const ext = await threatIntel.checkExternalProviders(cand.canonicalValue, providers);
      if (ext.hit) {
        try {
          await threatIntel.applyTrustedVerdict(db, {
            lookupKey: rep.lookupKey,
            indicatorType: cand.type,
            maskedValue: cand.maskedDisplay,
            verdict: threatIntel.VERDICTS.CONFIRMED_MALICIOUS,
            sourceType: ext.hit.sourceType,
            category: ext.hit.category,
            evidenceSafe: ext.hit.evidenceSafe,
            reason: `External provider ${ext.hit.provider}`,
          });
        } catch (e) {
          logger.warn("Failed to persist external provider evidence:", e.message);
        }
        rep = {
          ...rep,
          verdict: threatIntel.VERDICTS.CONFIRMED_MALICIOUS,
          confidence: "HIGH",
          sourceStrength: "VERIFIED_SOURCE",
          categories: [ext.hit.category],
          safeUserFacingEvidence: [ext.hit.evidenceSafe],
        };
      }
    }
    reps.push(rep);
    if (rep.verdict === threatIntel.VERDICTS.CONFIRMED_MALICIOUS) break;
  }
  return threatIntel.pickTopReputation(reps);
}

/**
 * Advice must match the confirmed indicator (Phase 4): no "do not open the link" for a
 * phone number, no bank referral for an e-mail address unless money is involved.
 */
function knownMaliciousActions(rep) {
  const type = rep && rep.indicatorType;
  const stop = {
    URL: { title: "Odkaz neotevírejte", description: "Odkaz byl potvrzen jako nebezpečný. Neotvírejte ho a nic na stránce nezadávejte.", isCrucial: true },
    DOMAIN: { title: "Stránku neotevírejte", description: "Doména byla potvrzena jako nebezpečná. Nic na ní nezadávejte.", isCrucial: true },
    PHONE: { title: "Na číslo nevolejte a neodpovídejte", description: "Telefonní číslo bylo potvrzeno jako podvodné. Pokud volá, zavěste.", isCrucial: true },
    EMAIL: { title: "Na e-mail neodpovídejte", description: "Adresa byla potvrzena jako podvodná. Přílohy ze zprávy nespouštějte a neřiďte se jejími pokyny.", isCrucial: true },
  }[type] || { title: "Ukončete komunikaci", description: "Obsah byl potvrzen jako nebezpečný. Neřiďte se jeho pokyny.", isCrucial: true };
  return [
    stop,
    { title: "Pokud jste už něco zadali, jednejte", description: "Změňte dotčená hesla. Pokud jste zadali platební údaje nebo platili, kontaktujte banku přes oficiální číslo.", isCrucial: true },
  ];
}

function knownMaliciousSummaryAdvice(rep) {
  switch (rep && rep.indicatorType) {
    case "URL":
    case "DOMAIN":
      return "Neklikejte a nezadávejte žádné údaje.";
    case "PHONE":
      return "Na číslo nevolejte a nic mu nesdělujte.";
    case "EMAIL":
      return "Na e-mail neodpovídejte a neřiďte se jeho pokyny.";
    default:
      return "Neřiďte se jeho pokyny a nic nesdělujte.";
  }
}

function knownMaliciousResponse(rep) {
  const catList = rep.categories && rep.categories.length > 0 ? rep.categories.join(", ") : "podvod";
  return {
    quotaExhausted: false,
    quotaCharged: false,
    riskLevel: "HIGH",
    resultCategory: "KNOWN_MALICIOUS",
    confidence: "HIGH",
    summary: `Tento obsah byl důvěryhodným bezpečnostním zdrojem potvrzen jako nebezpečný (${catList}). ${knownMaliciousSummaryAdvice(rep)}`,
    threatReputation: rep,
    signals: [
      {
        id: "known_threat_confirmed",
        title: "Známá hrozba",
        description: `Indikátor (${rep.maskedDisplay}) byl potvrzen jako škodlivý důvěryhodným bezpečnostním zdrojem.`,
        severity: "HIGH",
        isPositive: false,
        source: "THREAT_INTEL",
      },
    ],
    recommendedActions: knownMaliciousActions(rep),
    limitations: [],
  };
}

function quotaExhaustedResponse(rep, limit) {
  return {
    quotaExhausted: true,
    quotaCharged: false,
    monthlyLimit: limit,
    riskLevel: "UNKNOWN",
    resultCategory: "INCONCLUSIVE",
    confidence: "LOW",
    summary: "Měsíční limit hloubkových kontrol byl vyčerpán. Základní kontrola, kontrola známých hrozeb a krizový režim fungují dál zdarma.",
    threatReputation: rep,
    signals: [],
    recommendedActions: [],
    limitations: ["Hloubková AI kontrola nebyla provedena (vyčerpaný limit)."],
  };
}

/**
 * @param deps { db, generate(params) -> Promise<string>, providers?, logger?, now? }
 *   `generate` wraps the OpenAI provider; injected for tests.
 * @param uid authenticated user id
 * @param input validated { text, analysisType, image }
 */
async function analyzeContent(deps, uid, input) {
  const { db, generate, providers, logger = console } = deps;
  const nowMillis = deps.now ? deps.now() : Date.now();
  const cid = ledger.correlationId(uid, input.requestId);
  const started = Date.now();
  logEvent(logger, "analyze.start", { cid, type: input.analysisType, hasImage: !!input.image });

  const rep = await resolveThreatReputation(db, input.text, providers, logger);
  if (rep && rep.verdict === threatIntel.VERDICTS.CONFIRMED_MALICIOUS) {
    logEvent(logger, "analyze.known_malicious", { cid });
    return knownMaliciousResponse(rep);
  }

  let reservation;
  try {
    reservation = await ledger.reserve(db, uid, input, nowMillis);
  } catch (e) {
    if (e instanceof ledger.LedgerConflictError) logEvent(logger, "analyze.conflict", { cid, reason: e.reason });
    throw e;
  }
  if (reservation.kind === "duplicate_done") {
    logEvent(logger, "analyze.recovered", { cid });
    // Same logical analysis already charged: return the stored result, never charge again.
    return {
      ...reservation.result, quotaCharged: false, duplicateRequest: true,
      deepAnalysesUsed: reservation.used, monthlyLimit: reservation.limit,
    };
  }
  if (reservation.kind === "exhausted") {
    logEvent(logger, "analyze.quota_exhausted", { cid });
    return { ...quotaExhaustedResponse(rep, reservation.limit), deepAnalysesUsed: reservation.used };
  }
  logEvent(logger, reservation.takeover ? "analyze.reservation_takeover" : "analyze.reserved", { cid });

  let validated = null;
  let urlSignals = [];
  let metadataLimitations = [];
  let domainContext = [];
  try {
    const env = deps.env || process.env;
    // DNS existence is checked only when the caller supplies a resolver (production
    // httpApi does; unit tests stay offline). BACHA_DNS_CHECK=0 is a kill switch.
    const domains = await assessUrlDomains(input.text, {
      resolve: deps.resolveDomain,
      enabled: typeof deps.resolveDomain === "function" && env.BACHA_DNS_CHECK !== "0",
    });
    urlSignals.push(...domains.signals);
    metadataLimitations.push(...domains.limitations);
    domainContext = domains.promptFacts;
    if (input.inspectLinks === true) {
      const candidate = threatIntel.extractCandidateIndicators(input.text).find((c) => c.type === threatIntel.INDICATOR_TYPES.URL);
      if (candidate) {
        const [age, inspection] = await Promise.all([
          lookupDomainAge(candidate.domainOnly, { enabled: env.BACHA_RDAP_ENABLED === "1", now: nowMillis, fetchImpl: deps.metadataFetch }),
          inspectThroughWorker(candidate.canonicalValue, { endpoint: env.BACHA_LINK_INSPECTOR_URL, token: env.BACHA_LINK_INSPECTOR_TOKEN, fetchImpl: deps.metadataFetch }),
        ]);
        urlSignals.push(...metadataSignals(age, inspection));
        if (!age.checked) metadataLimitations.push("Stáří domény nebylo ověřeno.");
        if (!inspection.checked) metadataLimitations.push("Přesměrování ani HTML nebyly ověřeny.");
        else metadataLimitations.push("Kontrola odkazů je omezená: bez parametrů URL, skriptů a úplného obsahu stránky.");
      }
    }
    logEvent(logger, "analyze.provider_call", { cid });
    const raw = await withTimeout(
      generate({
        model: OPENAI_MODEL,
        systemInstruction: SYSTEM_INSTRUCTION,
        responseSchema: RESPONSE_SCHEMA,
        userPrompt: buildUserPrompt({ text: input.text, analysisType: input.analysisType, threatContext: rep, hasImage: !!input.image, domainFacts: domainContext }),
        image: input.image,
      }),
      deps.aiTimeoutMs || deps.geminiTimeoutMs || AI_TIMEOUT_MS,
      "OpenAI"
    );
    validated = validateAiOutput(raw);
  } catch (e) {
    const { reason, retryAfterSeconds } = providerFailureReason(e);
    const refunded = await ledger.refund(db, reservation, Date.now(), reason, logger);
    logEvent(logger, "analyze.failed", { cid, reason, refunded, ms: Date.now() - started });
    throw new AnalysisUnavailableError("Hloubková kontrola selhala na straně serveru.", e, reason, retryAfterSeconds);
  }
  if (!validated) {
    const refunded = await ledger.refund(db, reservation, Date.now(), "invalid_output", logger);
    logEvent(logger, "analyze.failed", { cid, reason: "invalid_output", refunded, ms: Date.now() - started });
    throw new AnalysisUnavailableError("Hloubková kontrola vrátila neplatný výsledek.", null, "invalid_output");
  }

  validated = reconcilePickup(validated, input, rep, urlSignals);
  const verdict = combineServerVerdict({ threatReputation: rep, ai: validated, metadataSignals: urlSignals });
  const response = {
    quotaExhausted: false,
    quotaCharged: true,
    deepAnalysesUsed: reservation.used,
    monthlyLimit: reservation.limit,
    riskLevel: verdict.riskLevel,
    resultCategory: verdict.category,
    confidence: validated.confidence,
    scamType: validated.scamType,
    detectedActions: validated.detectedActions,
    requiresFurtherVerification: validated.requiresFurtherVerification,
    summary: verdict.category === "INCONCLUSIVE" ? "Nemáme dostatek informací k ověření obsahu. Ověřte zdroj nezávisle." : validated.summary,
    signals: [...urlSignals, ...validated.signals].slice(0, 12),
    recommendedActions: validated.recommendedActions,
    limitations: [...metadataLimitations, ...validated.limitations].slice(0, 4),
    threatReputation: rep,
  };
  await ledger.complete(reservation, response, Date.now(), logger);
  logEvent(logger, "analyze.completed", { cid, category: verdict.category, ms: Date.now() - started });
  return response;
}

/** Compatibility wrapper for callers/tests of the previous API. */
async function reserveQuota(db, uid, nowMillis, requestId = null) {
  const r = await ledger.reserve(db, uid, { requestId, text: "", analysisType: "TEXT_OR_URL" }, nowMillis);
  return { reserved: r.kind === "reserved", used: r.used, limit: r.limit, usageRef: r.usageRef, isPlus: r.isPlus };
}

module.exports = {
  AnalysisUnavailableError,
  knownMaliciousActions,
  knownMaliciousSummaryAdvice,
  getCurrentPeriod,
  reserveQuota,
  resolveThreatReputation,
  analyzeContent,
};
