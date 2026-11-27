"use strict";

/**
 * Single production AI pipeline (spec P1.1):
 *   Auth -> App Check -> registered account -> rate limit -> input validation
 *   -> threat intelligence -> quota reservation -> OpenAI (schema constrained)
 *   -> output validation -> evidence-based verdict -> AnalysisResult
 */
const threatIntel = require("./threatIntel");
const { FREE_MONTHLY_LIMIT, PLUS_MONTHLY_LIMIT, OPENAI_MODEL } = require("./config");
const { entitlementGrantsPlus } = require("./billing");
const { SYSTEM_INSTRUCTION, RESPONSE_SCHEMA, buildUserPrompt, validateAiOutput } = require("./aiOutput");
const { combineServerVerdict } = require("./riskEngine");
const { reconcilePickup } = require("./pickupContext");
const { fs } = require("./fsHelpers");
const { ApiError } = require("./authCore");
const { lookupDomainAge, inspectThroughWorker, metadataSignals } = require("./urlMetadata");

const AI_TIMEOUT_MS = 45000;

class AnalysisUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = "AnalysisUnavailableError";
    this.cause = cause;
  }
}

function getCurrentPeriod(nowMillis = Date.now()) {
  const d = new Date(nowMillis);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

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

const REQUEST_RECORD_TTL_MS = 60 * 60 * 1000;

/**
 * Atomic quota reservation. Returns { reserved, used, limit, usageRef, requestRef, duplicate }.
 *
 * With a client requestId (idempotency key) the reservation and a "pending" request record
 * are written in ONE transaction, so a retried/duplicated request (network retry, app
 * resend) can never be charged twice: a completed request returns its stored result, an
 * in-flight one is rejected as already-exists.
 */
async function reserveQuota(db, uid, nowMillis, requestId = null) {
  const entSnap = await db.collection("users").doc(uid).collection("entitlement").doc("current").get();
  const isPlus = entitlementGrantsPlus(entSnap.exists ? entSnap.data() : null, nowMillis);
  const limit = isPlus ? PLUS_MONTHLY_LIMIT : FREE_MONTHLY_LIMIT;
  const usageRef = db.collection("users").doc(uid).collection("usage").doc(getCurrentPeriod(nowMillis));
  const requestRef = requestId ? db.collection("users").doc(uid).collection("analysisRequests").doc(requestId) : null;
  let reserved = false;
  let used = 0;
  let duplicate = null;
  await db.runTransaction(async (tx) => {
    if (requestRef) {
      const existing = await tx.get(requestRef);
      const rec = existing.exists ? existing.data() : null;
      if (rec && Number(rec.createdAtMillis || 0) + REQUEST_RECORD_TTL_MS > nowMillis) {
        duplicate = rec;
        return;
      }
    }
    const usageDoc = await tx.get(usageRef);
    used = usageDoc.exists ? usageDoc.data().deepAnalysisCount || 0 : 0;
    if (used >= limit) {
      reserved = false;
      return;
    }
    tx.set(usageRef, { deepAnalysisCount: used + 1, monthlyLimit: limit, updatedAt: fs().serverTimestamp() }, { merge: true });
    if (requestRef) {
      tx.set(requestRef, {
        status: "pending",
        createdAtMillis: nowMillis,
        expiresAt: fs().fromMillis(nowMillis + REQUEST_RECORD_TTL_MS),
      });
    }
    used += 1;
    reserved = true;
  });
  return { reserved, used, limit, usageRef, requestRef, isPlus, duplicate };
}

async function rollbackQuota(usageRef, logger, requestRef = null) {
  try {
    await usageRef.update({ deepAnalysisCount: fs().increment(-1) });
  } catch (e) {
    logger.error("Failed to roll back quota:", e.message);
  }
  // A failed request may be retried with the same id; it was not charged.
  if (requestRef) {
    try { await requestRef.delete(); } catch (e) { logger.error("Failed to clear request record:", e.message); }
  }
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

  const rep = await resolveThreatReputation(db, input.text, providers, logger);
  if (rep && rep.verdict === threatIntel.VERDICTS.CONFIRMED_MALICIOUS) {
    return knownMaliciousResponse(rep);
  }

  const quota = await reserveQuota(db, uid, nowMillis, input.requestId || null);
  if (quota.duplicate) {
    if (quota.duplicate.status === "done" && quota.duplicate.result) {
      // Same request already analysed and charged: return it again, never charge twice.
      return { ...quota.duplicate.result, quotaCharged: false, duplicateRequest: true };
    }
    throw new ApiError(409, "already-exists", "Tento požadavek se už zpracovává.");
  }
  if (!quota.reserved) return quotaExhaustedResponse(rep, quota.limit);

  let validated = null;
  let urlSignals = [];
  let metadataLimitations = [];
  try {
    if (input.inspectLinks === true) {
      const candidate = threatIntel.extractCandidateIndicators(input.text).find((c) => c.type === threatIntel.INDICATOR_TYPES.URL);
      if (candidate) {
        const env = deps.env || process.env;
        const [age, inspection] = await Promise.all([
          lookupDomainAge(candidate.domainOnly, { enabled: env.BACHA_RDAP_ENABLED === "1", now: nowMillis, fetchImpl: deps.metadataFetch }),
          inspectThroughWorker(candidate.canonicalValue, { endpoint: env.BACHA_LINK_INSPECTOR_URL, token: env.BACHA_LINK_INSPECTOR_TOKEN, fetchImpl: deps.metadataFetch }),
        ]);
        urlSignals = metadataSignals(age, inspection);
        if (!age.checked) metadataLimitations.push("Stáří domény nebylo ověřeno.");
        if (!inspection.checked) metadataLimitations.push("Přesměrování ani HTML nebyly ověřeny.");
        else metadataLimitations.push("Kontrola odkazů je omezená: bez parametrů URL, skriptů a úplného obsahu stránky.");
      }
    }
    const raw = await withTimeout(
      generate({
        model: OPENAI_MODEL,
        systemInstruction: SYSTEM_INSTRUCTION,
        responseSchema: RESPONSE_SCHEMA,
        userPrompt: buildUserPrompt({ text: input.text, analysisType: input.analysisType, threatContext: rep, hasImage: !!input.image }),
        image: input.image,
      }),
      deps.aiTimeoutMs || deps.geminiTimeoutMs || AI_TIMEOUT_MS,
      "OpenAI"
    );
    validated = validateAiOutput(raw);
  } catch (e) {
    await rollbackQuota(quota.usageRef, logger, quota.requestRef);
    throw new AnalysisUnavailableError("Hloubková kontrola selhala na straně serveru.", e);
  }
  if (!validated) {
    await rollbackQuota(quota.usageRef, logger, quota.requestRef);
    throw new AnalysisUnavailableError("Hloubková kontrola vrátila neplatný výsledek.");
  }

  validated = reconcilePickup(validated, input, rep, urlSignals);
  const verdict = combineServerVerdict({ threatReputation: rep, ai: validated, metadataSignals: urlSignals });
  const response = {
    quotaExhausted: false,
    quotaCharged: true,
    deepAnalysesUsed: quota.used,
    monthlyLimit: quota.limit,
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
  if (quota.requestRef) {
    try {
      await quota.requestRef.set({ status: "done", result: response }, { merge: true });
    } catch (e) {
      logger.warn("Failed to store request record:", e.message);
    }
  }
  return response;
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
