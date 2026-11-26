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

function knownMaliciousResponse(rep) {
  const catList = rep.categories && rep.categories.length > 0 ? rep.categories.join(", ") : "podvod";
  return {
    quotaExhausted: false,
    quotaCharged: false,
    riskLevel: "HIGH",
    resultCategory: "KNOWN_MALICIOUS",
    confidence: "HIGH",
    summary: `Tento obsah byl důvěryhodným bezpečnostním zdrojem potvrzen jako nebezpečný (${catList}). Neklikejte a nezadávejte žádné údaje.`,
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
    recommendedActions: [
      { title: "Okamžitě zastavit interakci", description: "Neotvírejte odkaz, neodpovídejte a neposílejte žádné peníze.", isCrucial: true },
      { title: "Pokud jste už něco zadali, jednejte", description: "Kontaktujte banku přes oficiální číslo a změňte hesla.", isCrucial: true },
    ],
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

/** Atomic quota reservation. Returns { reserved, used, limit, usageRef }. */
async function reserveQuota(db, uid, nowMillis) {
  const entSnap = await db.collection("users").doc(uid).collection("entitlement").doc("current").get();
  const isPlus = entitlementGrantsPlus(entSnap.exists ? entSnap.data() : null, nowMillis);
  const limit = isPlus ? PLUS_MONTHLY_LIMIT : FREE_MONTHLY_LIMIT;
  const usageRef = db.collection("users").doc(uid).collection("usage").doc(getCurrentPeriod(nowMillis));
  let reserved = false;
  let used = 0;
  await db.runTransaction(async (tx) => {
    const usageDoc = await tx.get(usageRef);
    used = usageDoc.exists ? usageDoc.data().deepAnalysisCount || 0 : 0;
    if (used >= limit) {
      reserved = false;
      return;
    }
    tx.set(usageRef, { deepAnalysisCount: used + 1, monthlyLimit: limit, updatedAt: fs().serverTimestamp() }, { merge: true });
    used += 1;
    reserved = true;
  });
  return { reserved, used, limit, usageRef, isPlus };
}

async function rollbackQuota(usageRef, logger) {
  try {
    await usageRef.update({ deepAnalysisCount: fs().increment(-1) });
  } catch (e) {
    logger.error("Failed to roll back quota:", e.message);
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

  const quota = await reserveQuota(db, uid, nowMillis);
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
    await rollbackQuota(quota.usageRef, logger);
    throw new AnalysisUnavailableError("Hloubková kontrola selhala na straně serveru.", e);
  }
  if (!validated) {
    await rollbackQuota(quota.usageRef, logger);
    throw new AnalysisUnavailableError("Hloubková kontrola vrátila neplatný výsledek.");
  }

  validated = reconcilePickup(validated, input, rep, urlSignals);
  const verdict = combineServerVerdict({ threatReputation: rep, ai: validated, metadataSignals: urlSignals });
  return {
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
}

module.exports = {
  AnalysisUnavailableError,
  getCurrentPeriod,
  reserveQuota,
  resolveThreatReputation,
  analyzeContent,
};
