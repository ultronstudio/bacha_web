"use strict";

/**
 * Bacha! Threat Intelligence.
 *
 * Trust model (spec P0.4 / P0.5):
 *   UNKNOWN -> community reports -> SUSPICIOUS
 *   CONFIRMED_MALICIOUS only via trusted external provider, manual moderation
 *   or another server-verified security proof (`applyTrustedVerdict`).
 *   Community consensus = evidence, never the final authority (Sybil resistant).
 *   Disputes create a PENDING review and never change the verdict by themselves.
 */
const crypto = require("crypto");
const { getDomain } = require("tldts");
const { getHmacSecret, optionalSecret } = require("./config");
const { fs } = require("./fsHelpers");

const INDICATOR_TYPES = {
  DOMAIN: "DOMAIN",
  URL: "URL",
  PHONE: "PHONE",
  EMAIL: "EMAIL",
  BANK_ACCOUNT: "BANK_ACCOUNT",
  CRYPTO_WALLET: "CRYPTO_WALLET",
  SMS_SENDER: "SMS_SENDER",
  OTHER: "OTHER",
};

const VERDICTS = {
  UNKNOWN: "UNKNOWN",
  SUSPICIOUS: "SUSPICIOUS",
  CONFIRMED_MALICIOUS: "CONFIRMED_MALICIOUS",
  KNOWN_SAFE: "KNOWN_SAFE",
  /** Legacy value – no longer written. Kept so old docs still parse. */
  DISPUTED: "DISPUTED",
  INACTIVE: "INACTIVE",
};

const SOURCE_TYPES = {
  USER_REPORT: "USER_REPORT",
  EXTERNAL_FEED: "EXTERNAL_FEED",
  WEB_RISK: "WEB_RISK",
  PHISHTANK: "PHISHTANK",
  URLHAUS: "URLHAUS",
  MANUAL_REVIEW: "MANUAL_REVIEW",
  AUTOMATED_ANALYSIS: "AUTOMATED_ANALYSIS",
};

/** Sources allowed to set CONFIRMED_MALICIOUS / KNOWN_SAFE. */
const TRUSTED_SOURCES = new Set([
  SOURCE_TYPES.WEB_RISK,
  SOURCE_TYPES.PHISHTANK,
  SOURCE_TYPES.URLHAUS,
  SOURCE_TYPES.EXTERNAL_FEED,
  SOURCE_TYPES.MANUAL_REVIEW,
]);

const DISPUTE_STATUS = { PENDING: "PENDING", UPHELD: "UPHELD", REJECTED: "REJECTED" };
const INDICATOR_VALIDITY_DAYS = 90;
const MAX_WATCHES_PER_USER = 100;
const EXTERNAL_PROVIDER_TIMEOUT_MS = 5000;

/* ------------------------------------------------------------------------- */
/* Lookup keys                                                               */
/* ------------------------------------------------------------------------- */

function computeHmacLookupKey(indicatorType, canonicalValue, env = process.env) {
  const hmac = crypto.createHmac("sha256", getHmacSecret(env));
  hmac.update(`${String(indicatorType).toUpperCase()}:${String(canonicalValue).trim()}`);
  return hmac.digest("hex");
}

/* ------------------------------------------------------------------------- */
/* Normalisation                                                             */
/* ------------------------------------------------------------------------- */

function normalizeDomain(rawDomain) {
  if (!rawDomain) return "";
  let clean = String(rawDomain).trim().toLowerCase();
  clean = clean.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const slashIdx = clean.search(/[/?#]/);
  if (slashIdx !== -1) clean = clean.substring(0, slashIdx);
  const atIdx = clean.lastIndexOf("@");
  if (atIdx !== -1) clean = clean.substring(atIdx + 1);
  const colonIdx = clean.indexOf(":");
  if (colonIdx !== -1) clean = clean.substring(0, colonIdx);
  clean = clean.replace(/\.+$/, "");
  try {
    // punycode via WHATWG URL
    clean = new URL(`https://${clean}`).hostname;
  } catch {
    /* keep as-is */
  }
  return clean;
}

/** Registrable domain via the Public Suffix List (spec P1.9). */
function extractRegistrableDomain(host) {
  const cleanHost = normalizeDomain(host);
  if (!cleanHost) return "";
  const d = getDomain(cleanHost, { allowPrivateDomains: true });
  return d || cleanHost;
}

const SENSITIVE_QUERY_PARAMS = new Set([
  "token", "session", "auth", "sid", "uid", "email", "password", "pass", "pwd",
  "key", "id", "sig", "signature", "code", "jwt", "access_token", "refresh_token",
  "user_id", "account", "login", "ticket", "phone", "tel", "iban",
]);

function normalizeUrl(rawUrl) {
  if (!rawUrl) return null;
  let trimmed = String(rawUrl).trim();
  if (!/^https?:\/\//i.test(trimmed)) trimmed = "https://" + trimmed;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const host = normalizeDomain(parsed.hostname);
  if (!host) return null;
  const registrableDomain = extractRegistrableDomain(host);
  let path = (parsed.pathname || "/").replace(/\/{2,}/g, "/");

  const cleanParams = [];
  for (const [key, value] of parsed.searchParams.entries()) {
    const lowerKey = key.toLowerCase();
    if (!SENSITIVE_QUERY_PARAMS.has(lowerKey) && !lowerKey.includes("token") && !lowerKey.includes("auth")) {
      cleanParams.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  }
  const cleanQuery = cleanParams.length > 0 ? "?" + cleanParams.join("&") : "";
  let canonical = `${scheme}://${host}`;
  if (path !== "/") canonical += path.replace(/\/+$/, "");
  canonical += cleanQuery;

  const maskedDisplay = host + (path !== "/" ? path.slice(0, 24) + (path.length > 24 ? "…" : "") : "");
  return {
    type: INDICATOR_TYPES.URL,
    canonicalValue: canonical,
    maskedDisplay,
    domainOnly: host,
    registrableDomain,
  };
}

function normalizePhone(rawPhone) {
  if (!rawPhone) return null;
  let clean = String(rawPhone).trim().replace(/[\s\-()./]/g, "");
  if (!/^\+?\d{6,15}$/.test(clean.replace(/^00/, "+"))) return null;
  if (clean.startsWith("00")) {
    clean = "+" + clean.substring(2);
  } else if (!clean.startsWith("+")) {
    clean = clean.length === 9 && /^[2-79]/.test(clean) ? "+420" + clean : "+" + clean;
  }
  let masked = "***";
  if (clean.startsWith("+420") && clean.length === 13) masked = `+420 *** *** ${clean.slice(-3)}`;
  else if (clean.length > 6) masked = `${clean.slice(0, 4)} *** ${clean.slice(-3)}`;
  return { type: INDICATOR_TYPES.PHONE, canonicalValue: clean, maskedDisplay: masked };
}

function normalizeEmail(rawEmail) {
  if (!rawEmail) return null;
  const trimmed = String(rawEmail).trim();
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx <= 0 || atIdx >= trimmed.length - 1) return null;
  const localPart = trimmed.substring(0, atIdx).trim().toLowerCase();
  const domainPart = normalizeDomain(trimmed.substring(atIdx + 1).trim());
  if (!domainPart) return null;
  const maskedLocal = localPart.length > 2 ? `${localPart[0]}***${localPart[localPart.length - 1]}` : "***";
  return {
    type: INDICATOR_TYPES.EMAIL,
    canonicalValue: `${localPart}@${domainPart}`,
    maskedDisplay: `${maskedLocal}@${domainPart}`,
    domainOnly: domainPart,
  };
}

function normalizeIndicator(type, value) {
  switch (type) {
    case INDICATOR_TYPES.URL:
      return normalizeUrl(value);
    case INDICATOR_TYPES.DOMAIN: {
      const d = normalizeDomain(value);
      return d ? { type, canonicalValue: d, maskedDisplay: d, domainOnly: d, registrableDomain: extractRegistrableDomain(d) } : null;
    }
    case INDICATOR_TYPES.PHONE:
      return normalizePhone(value);
    case INDICATOR_TYPES.EMAIL:
      return normalizeEmail(value);
    default:
      return null;
  }
}

/** Extracts candidate indicators from free text (server side, bounded). */
function extractCandidateIndicators(text, maxCandidates = 15) {
  if (!text || typeof text !== "string") return [];
  const candidates = [];
  const urlMatches = text.match(/https?:\/\/[^\s<>"]+|www\.[^\s<>"]+/gi) || [];
  for (const rawUrl of urlMatches) {
    const norm = normalizeUrl(rawUrl);
    if (norm) {
      candidates.push(norm);
      candidates.push({ type: INDICATOR_TYPES.DOMAIN, canonicalValue: norm.domainOnly, maskedDisplay: norm.domainOnly, domainOnly: norm.domainOnly, registrableDomain: norm.registrableDomain });
    }
  }
  const phoneMatches = text.match(/(?:\+420|00420)?\s*[1-9][0-9]{2}\s*[0-9]{3}\s*[0-9]{3}/g) || [];
  for (const rawPhone of phoneMatches) {
    const norm = normalizePhone(rawPhone);
    if (norm) candidates.push(norm);
  }
  const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  for (const rawEmail of emailMatches) {
    const norm = normalizeEmail(rawEmail);
    if (norm) candidates.push(norm);
  }
  const seen = new Set();
  const deduped = [];
  for (const c of candidates) {
    const key = `${c.type}:${c.canonicalValue}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(c);
    }
    if (deduped.length >= maxCandidates) break;
  }
  return deduped;
}

/* ------------------------------------------------------------------------- */
/* External providers (all with hard timeouts; failure = "not checked")      */
/* ------------------------------------------------------------------------- */

async function fetchWithTimeout(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

class GoogleWebRiskProvider {
  constructor({ apiKey, fetchImpl = globalThis.fetch, timeoutMs = EXTERNAL_PROVIDER_TIMEOUT_MS } = {}) {
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.name = "WEB_RISK";
  }

  async checkUrl(url) {
    if (!this.apiKey) return { checked: false, isMalicious: false, reason: "NO_API_KEY" };
    try {
      const endpoint = `https://webrisk.googleapis.com/v1/uris:search?uri=${encodeURIComponent(url)}` +
        `&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key=${encodeURIComponent(this.apiKey)}`;
      const res = await fetchWithTimeout(this.fetchImpl, endpoint, {}, this.timeoutMs);
      if (!res.ok) return { checked: false, isMalicious: false, error: `HTTP ${res.status}` };
      const data = await res.json();
      const threat = data && data.threat;
      if (threat && Array.isArray(threat.threatTypes) && threat.threatTypes.length > 0) {
        return {
          checked: true,
          isMalicious: true,
          provider: "WEB_RISK",
          category: threat.threatTypes.includes("SOCIAL_ENGINEERING") ? "PHISHING" : "MALWARE",
        };
      }
      return { checked: true, isMalicious: false };
    } catch (e) {
      return { checked: false, isMalicious: false, error: e.name === "AbortError" ? "TIMEOUT" : e.message };
    }
  }
}

class PhishTankProvider {
  constructor({ apiKey, fetchImpl = globalThis.fetch, timeoutMs = EXTERNAL_PROVIDER_TIMEOUT_MS } = {}) {
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.name = "PHISHTANK";
  }

  async checkUrl(url) {
    if (!this.apiKey) return { checked: false, isMalicious: false, reason: "NO_API_KEY" };
    try {
      const body = new URLSearchParams({ url, format: "json", app_key: this.apiKey });
      const res = await fetchWithTimeout(
        this.fetchImpl,
        "https://checkurl.phishtank.com/checkurl/",
        { method: "POST", body, headers: { "User-Agent": "phishtank/BachaSecurityAssistant" } },
        this.timeoutMs
      );
      if (!res.ok) return { checked: false, isMalicious: false, error: `HTTP ${res.status}` };
      const data = await res.json();
      const r = data && data.results;
      if (r && r.in_database && r.verified && r.valid !== false) {
        return { checked: true, isMalicious: true, provider: "PHISHTANK", category: "PHISHING" };
      }
      return { checked: true, isMalicious: false };
    } catch (e) {
      return { checked: false, isMalicious: false, error: e.name === "AbortError" ? "TIMEOUT" : e.message };
    }
  }
}

class UrlhausProvider {
  constructor({ apiKey, fetchImpl = globalThis.fetch, timeoutMs = EXTERNAL_PROVIDER_TIMEOUT_MS } = {}) {
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.name = "URLHAUS";
  }

  async checkUrl(url) {
    if (!this.apiKey) return { checked: false, isMalicious: false, reason: "NO_API_KEY" };
    try {
      const res = await fetchWithTimeout(
        this.fetchImpl,
        "https://urlhaus-api.abuse.ch/v1/url/",
        {
          method: "POST",
          body: new URLSearchParams({ url }),
          headers: { "User-Agent": "BachaSecurityAssistant", "Auth-Key": this.apiKey },
        },
        this.timeoutMs
      );
      if (!res.ok) return { checked: false, isMalicious: false, error: `HTTP ${res.status}` };
      const data = await res.json();
      if (data && data.query_status === "ok" && data.url_status === "online") {
        return { checked: true, isMalicious: true, provider: "URLHAUS", category: "MALWARE" };
      }
      return { checked: true, isMalicious: false };
    } catch (e) {
      return { checked: false, isMalicious: false, error: e.name === "AbortError" ? "TIMEOUT" : e.message };
    }
  }
}

const PROVIDER_EVIDENCE_TEXT = {
  WEB_RISK: "Detekováno bezpečnostní službou Google Web Risk.",
  PHISHTANK: "Ověřeno v databázi PhishTank.",
  URLHAUS: "Evidováno jako aktivní zdroj škodlivého softwaru v databázi URLhaus.",
};

function defaultProviders(env = process.env) {
  return [
    new GoogleWebRiskProvider({ apiKey: optionalSecret("WEB_RISK_API_KEY", env) }),
    new PhishTankProvider({ apiKey: optionalSecret("PHISHTANK_API_KEY", env) }),
    new UrlhausProvider({ apiKey: optionalSecret("URLHAUS_API_KEY", env) }),
  ];
}

/**
 * Queries all external providers in parallel. A provider that errors or
 * times out is reported as `checked: false` – never as "clean".
 */
async function checkExternalProviders(url, providers = defaultProviders()) {
  if (!url) return { hit: null, results: [] };
  const results = await Promise.all(
    providers.map(async (p) => {
      try {
        return { provider: p.name, ...(await p.checkUrl(url)) };
      } catch (e) {
        return { provider: p.name, checked: false, isMalicious: false, error: e.message };
      }
    })
  );
  const hitRes = results.find((r) => r.isMalicious);
  const hit = hitRes
    ? {
        provider: hitRes.provider,
        sourceType: SOURCE_TYPES[hitRes.provider] || SOURCE_TYPES.EXTERNAL_FEED,
        category: hitRes.category || "PHISHING",
        evidenceSafe: PROVIDER_EVIDENCE_TEXT[hitRes.provider] || "Detekováno důvěryhodným bezpečnostním zdrojem.",
      }
    : null;
  return { hit, results: results.map((r) => ({ provider: r.provider, checked: !!r.checked, error: r.error || null })) };
}

/* ------------------------------------------------------------------------- */
/* Database lookup                                                           */
/* ------------------------------------------------------------------------- */

function tsToMillis(ts) {
  if (!ts) return null;
  if (typeof ts.toMillis === "function") return ts.toMillis();
  if (typeof ts === "number") return ts;
  return null;
}

async function lookupSingleIndicatorInDb(db, indicatorType, canonicalValue) {
  const lookupKey = computeHmacLookupKey(indicatorType, canonicalValue);
  const docSnap = await db.collection("threatIndicators").doc(lookupKey).get();
  if (!docSnap.exists) return null;
  const data = docSnap.data();
  const expiresAt = tsToMillis(data.expiresAt);
  if (expiresAt && expiresAt < Date.now() && data.verdict !== VERDICTS.KNOWN_SAFE) {
    return { ...data, lookupKey, verdict: VERDICTS.INACTIVE };
  }
  return { ...data, lookupKey };
}

function toReputation(match, { indicatorType, canonicalValue, maskedDisplay, isExactMatch, matchType }) {
  return {
    indicatorType,
    canonicalValue,
    maskedDisplay: maskedDisplay || match.maskedValue || "***",
    lookupKey: match.lookupKey,
    verdict: match.verdict === VERDICTS.DISPUTED ? VERDICTS.SUSPICIOUS : match.verdict,
    categories: match.categories || [],
    confidence: match.confidence || "MEDIUM",
    sourceStrength: (match.verifiedSourceCount || 0) > 0 || match.manuallyReviewed ? "VERIFIED_SOURCE" : "COMMUNITY",
    reportCount: match.reportCount || 0,
    independentReporterCount: match.independentReporterCount || 0,
    underReview: (match.openDisputeCount || 0) > 0,
    firstSeenAt: tsToMillis(match.firstSeenAt),
    lastVerifiedAt: tsToMillis(match.lastVerifiedAt),
    isExactMatch,
    matchType,
    safeUserFacingEvidence: (match.safeUserFacingEvidence || []).slice(0, 5),
  };
}

/** Hierarchical lookup: exact URL -> host -> registrable domain. */
async function queryThreatIntelligence(db, indicator) {
  const { type, canonicalValue, maskedDisplay, domainOnly, registrableDomain } = indicator;

  const exactMatch = await lookupSingleIndicatorInDb(db, type, canonicalValue);
  if (exactMatch && exactMatch.active !== false) {
    return toReputation(exactMatch, {
      indicatorType: type, canonicalValue, maskedDisplay, isExactMatch: true,
      matchType: type === INDICATOR_TYPES.URL ? "EXACT_URL" : type,
    });
  }

  if ((type === INDICATOR_TYPES.URL || type === INDICATOR_TYPES.DOMAIN) && domainOnly) {
    if (type === INDICATOR_TYPES.URL) {
      const domainMatch = await lookupSingleIndicatorInDb(db, INDICATOR_TYPES.DOMAIN, domainOnly);
      if (domainMatch && domainMatch.active !== false) {
        return toReputation(domainMatch, {
          indicatorType: INDICATOR_TYPES.DOMAIN, canonicalValue: domainOnly, maskedDisplay: domainOnly,
          isExactMatch: false, matchType: "DOMAIN",
        });
      }
    }
    if (registrableDomain && registrableDomain !== domainOnly) {
      const regMatch = await lookupSingleIndicatorInDb(db, INDICATOR_TYPES.DOMAIN, registrableDomain);
      if (regMatch && regMatch.active !== false) {
        return toReputation(regMatch, {
          indicatorType: INDICATOR_TYPES.DOMAIN, canonicalValue: registrableDomain, maskedDisplay: registrableDomain,
          isExactMatch: false, matchType: "REGISTRABLE_DOMAIN",
        });
      }
    }
  }

  return {
    indicatorType: type,
    canonicalValue,
    maskedDisplay: maskedDisplay || "***",
    lookupKey: computeHmacLookupKey(type, canonicalValue),
    verdict: VERDICTS.UNKNOWN,
    categories: [],
    confidence: "LOW",
    sourceStrength: "NONE",
    reportCount: 0,
    independentReporterCount: 0,
    underReview: false,
    isExactMatch: true,
    matchType: type,
    safeUserFacingEvidence: [],
  };
}

const VERDICT_PRIORITY = {
  CONFIRMED_MALICIOUS: 5,
  SUSPICIOUS: 4,
  DISPUTED: 3,
  INACTIVE: 2,
  KNOWN_SAFE: 1,
  UNKNOWN: 0,
};

/** Picks the most severe reputation (KNOWN_SAFE never wins over negative evidence). */
function pickTopReputation(reps) {
  let top = null;
  for (const r of reps) {
    if (!r) continue;
    if (!top || (VERDICT_PRIORITY[r.verdict] || 0) > (VERDICT_PRIORITY[top.verdict] || 0)) top = r;
  }
  return top;
}

/* ------------------------------------------------------------------------- */
/* Trusted verdict changes (external providers, moderation) + audit trail    */
/* ------------------------------------------------------------------------- */

/**
 * The ONLY function allowed to set CONFIRMED_MALICIOUS or KNOWN_SAFE.
 * Every change writes an `indicatorHistory` audit entry.
 */
async function applyTrustedVerdict(db, params) {
  const { lookupKey, indicatorType, maskedValue, verdict, sourceType, category, evidenceSafe, actorUid = null, reason } = params;
  if (!TRUSTED_SOURCES.has(sourceType)) {
    throw new Error(`Source ${sourceType} is not trusted to set verdicts.`);
  }
  if (!Object.values(VERDICTS).includes(verdict) || verdict === VERDICTS.DISPUTED) {
    throw new Error(`Invalid verdict ${verdict}`);
  }
  const now = fs().now();
  const ref = db.collection("threatIndicators").doc(lookupKey);
  let previousVerdict = VERDICTS.UNKNOWN;

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() : {};
    previousVerdict = data.verdict || VERDICTS.UNKNOWN;
    const categories = new Set(data.categories || []);
    if (category) categories.add(category);
    const evidence = [...(data.safeUserFacingEvidence || [])];
    if (evidenceSafe && !evidence.includes(evidenceSafe)) evidence.unshift(evidenceSafe);
    const isManual = sourceType === SOURCE_TYPES.MANUAL_REVIEW;

    tx.set(
      ref,
      {
        lookupKey,
        type: indicatorType || data.type || INDICATOR_TYPES.OTHER,
        verdict,
        categories: Array.from(categories).slice(0, 10),
        confidence: "HIGH",
        verifiedSourceCount: (data.verifiedSourceCount || 0) + (isManual ? 0 : 1),
        manuallyReviewed: isManual || !!data.manuallyReviewed,
        maskedValue: maskedValue || data.maskedValue || "***",
        firstSeenAt: data.firstSeenAt || now,
        lastSeenAt: now,
        lastVerifiedAt: now,
        expiresAt: fs().fromMillis(now.toMillis() + INDICATOR_VALIDITY_DAYS * 86400000),
        active: verdict !== VERDICTS.INACTIVE,
        version: (data.version || 0) + 1,
        safeUserFacingEvidence: evidence.slice(0, 5),
        reportCount: data.reportCount || 0,
        independentReporterCount: data.independentReporterCount || 0,
        openDisputeCount: data.openDisputeCount || 0,
      },
      { merge: true }
    );
    tx.set(ref.collection("evidence").doc(), {
      sourceType,
      observedAt: now,
      category: category || null,
      weight: 1.0,
      status: "ACTIVE",
      actorUid,
    });
    tx.set(db.collection("indicatorHistory").doc(), {
      lookupKey,
      previousVerdict,
      newVerdict: verdict,
      timestamp: now,
      sourceType,
      actorUid,
      reason: reason || `Trusted source ${sourceType}`,
    });
  });

  if (previousVerdict !== VERDICTS.CONFIRMED_MALICIOUS && verdict === VERDICTS.CONFIRMED_MALICIOUS) {
    await notifyWatchers(db, lookupKey);
  }
  return { lookupKey, previousVerdict, verdict };
}

/* ------------------------------------------------------------------------- */
/* Community reports                                                          */
/* ------------------------------------------------------------------------- */

/** Pure verdict transition for a community report. Exported for tests. */
function verdictAfterCommunityReport(currentVerdict) {
  switch (currentVerdict) {
    case VERDICTS.CONFIRMED_MALICIOUS:
    case VERDICTS.KNOWN_SAFE: // stays; report is recorded as evidence & flagged for review
      return currentVerdict;
    default:
      return VERDICTS.SUSPICIOUS;
  }
}

async function submitCommunityReport(db, uid, report, opts = {}) {
  const { rawValue, indicatorType, category, financialHarm, note } = report;
  const normalized = normalizeIndicator(indicatorType, rawValue);
  if (!normalized || !normalized.canonicalValue) {
    throw new Error("Neplatný formát nahlašovaného indikátoru.");
  }
  const lookupKey = computeHmacLookupKey(normalized.type, normalized.canonicalValue);
  const now = fs().now();
  const reportRef = db.collection("userReports").doc(`${uid}_${lookupKey}`);
  const indicatorRef = db.collection("threatIndicators").doc(lookupKey);

  let newVerdict = VERDICTS.SUSPICIOUS;
  let oldVerdict = VERDICTS.UNKNOWN;
  let isNewReporter = false;

  await db.runTransaction(async (tx) => {
    const existingReport = await tx.get(reportRef);
    const doc = await tx.get(indicatorRef);
    const data = doc.exists ? doc.data() : null;
    isNewReporter = !existingReport.exists;
    oldVerdict = data ? data.verdict || VERDICTS.UNKNOWN : VERDICTS.UNKNOWN;
    newVerdict = verdictAfterCommunityReport(oldVerdict === VERDICTS.DISPUTED ? VERDICTS.SUSPICIOUS : oldVerdict);

    tx.set(
      reportRef,
      {
        uid,
        lookupKey,
        indicatorType: normalized.type,
        category,
        financialHarm: financialHarm || "PREFER_NOT_TO_SAY",
        note: note ? String(note).slice(0, 500) : null,
        reporterAccountKind: opts.accountKind || "unknown",
        updatedAt: now,
        createdAt: existingReport.exists ? existingReport.data().createdAt : now,
      },
      { merge: true }
    );

    if (!isNewReporter) {
      // Duplicate report from the same user: no aggregate change (dedup).
      return;
    }

    const reportCount = (data ? data.reportCount || 0 : 0) + 1;
    const independentReporterCount = (data ? data.independentReporterCount || 0 : 0) + 1;
    const categories = new Set(data ? data.categories || [] : []);
    if (category) categories.add(category);
    const safeEvidence = data ? [...(data.safeUserFacingEvidence || [])].filter((m) => !m.startsWith("Nahlášeno ")) : [];
    if (independentReporterCount > 1) safeEvidence.push(`Nahlášeno ${independentReporterCount} uživateli (komunitní hlášení, neověřeno)`);

    const expiresAtMillis = Math.max(
      tsToMillis(data && data.expiresAt) || 0,
      now.toMillis() + INDICATOR_VALIDITY_DAYS * 86400000
    );

    tx.set(
      indicatorRef,
      {
        lookupKey,
        type: normalized.type,
        verdict: newVerdict,
        categories: Array.from(categories).slice(0, 10),
        // Community evidence alone never exceeds MEDIUM confidence.
        confidence: data && data.confidence === "HIGH" && newVerdict !== VERDICTS.SUSPICIOUS ? "HIGH" : "MEDIUM",
        reportCount,
        independentReporterCount,
        verifiedSourceCount: data ? data.verifiedSourceCount || 0 : 0,
        maskedValue: normalized.maskedDisplay,
        firstSeenAt: data ? data.firstSeenAt || now : now,
        lastSeenAt: now,
        expiresAt: fs().fromMillis(expiresAtMillis),
        active: true,
        needsReview: newVerdict === VERDICTS.KNOWN_SAFE || independentReporterCount >= 5 || !!(data && data.needsReview),
        version: (data ? data.version || 0 : 0) + 1,
        safeUserFacingEvidence: safeEvidence.slice(0, 5),
      },
      { merge: true }
    );
    tx.set(indicatorRef.collection("evidence").doc(), {
      sourceType: SOURCE_TYPES.USER_REPORT,
      observedAt: now,
      category,
      weight: opts.accountKind === "google" ? 0.6 : 0.3,
      status: "ACTIVE",
      metadataSafe: { financialHarm: financialHarm || "PREFER_NOT_TO_SAY" },
    });
    if (oldVerdict !== newVerdict) {
      tx.set(db.collection("indicatorHistory").doc(), {
        lookupKey,
        previousVerdict: oldVerdict,
        newVerdict,
        timestamp: now,
        sourceType: SOURCE_TYPES.USER_REPORT,
        actorUid: null,
        reason: `Community report (independent reporters: ${independentReporterCount})`,
      });
    }
  });

  return { success: true, lookupKey, verdict: newVerdict, isNewReporter };
}

/* ------------------------------------------------------------------------- */
/* Disputes                                                                   */
/* ------------------------------------------------------------------------- */

async function submitDispute(db, uid, dispute) {
  const { lookupKey, indicatorType, reason } = dispute;
  const now = fs().now();
  const disputeRef = db.collection("threatDisputes").doc(`${uid}_${lookupKey}`);
  const indicatorRef = db.collection("threatIndicators").doc(lookupKey);
  let created = false;

  await db.runTransaction(async (tx) => {
    const existing = await tx.get(disputeRef);
    const ind = await tx.get(indicatorRef);
    if (existing.exists && existing.data().status === DISPUTE_STATUS.PENDING) {
      return; // one pending dispute per user and indicator
    }
    created = true;
    const verdictAtSubmission = ind.exists ? ind.data().verdict || VERDICTS.UNKNOWN : VERDICTS.UNKNOWN;
    tx.set(disputeRef, {
      disputeId: disputeRef.id,
      lookupKey,
      indicatorType: indicatorType || "OTHER",
      submittedByUid: uid,
      reason: String(reason).slice(0, 1000),
      status: DISPUTE_STATUS.PENDING,
      verdictAtSubmission,
      createdAt: now,
      resolvedAt: null,
      resolvedByUid: null,
    });
    if (ind.exists) {
      // NOTE: verdict is intentionally NOT modified (spec P0.5).
      tx.update(indicatorRef, { openDisputeCount: (ind.data().openDisputeCount || 0) + 1, needsReview: true });
    }
    tx.set(db.collection("indicatorHistory").doc(), {
      lookupKey,
      previousVerdict: verdictAtSubmission,
      newVerdict: verdictAtSubmission,
      timestamp: now,
      sourceType: "DISPUTE",
      actorUid: null,
      event: "DISPUTE_OPENED",
      disputeId: disputeRef.id,
      reason: "User dispute submitted – verdict unchanged pending review",
    });
  });

  return { success: true, disputeId: disputeRef.id, status: DISPUTE_STATUS.PENDING, duplicate: !created };
}

/**
 * Manual / trusted resolution of a dispute. UPHELD may change the verdict
 * (via applyTrustedVerdict -> audit). REJECTED leaves the verdict as-is.
 */
async function resolveDispute(db, { disputeId, resolution, newVerdict, actorUid, note }) {
  if (![DISPUTE_STATUS.UPHELD, DISPUTE_STATUS.REJECTED].includes(resolution)) {
    throw new Error("Invalid resolution");
  }
  const disputeRef = db.collection("threatDisputes").doc(disputeId);
  const snap = await disputeRef.get();
  if (!snap.exists) throw new Error("Dispute not found");
  const d = snap.data();
  if (d.status !== DISPUTE_STATUS.PENDING) throw new Error("Dispute already resolved");

  if (resolution === DISPUTE_STATUS.UPHELD) {
    const target = newVerdict || VERDICTS.INACTIVE;
    if (![VERDICTS.KNOWN_SAFE, VERDICTS.INACTIVE, VERDICTS.SUSPICIOUS].includes(target)) {
      throw new Error("Upheld dispute may only move to KNOWN_SAFE, INACTIVE or SUSPICIOUS");
    }
    await applyTrustedVerdict(db, {
      lookupKey: d.lookupKey,
      verdict: target,
      sourceType: SOURCE_TYPES.MANUAL_REVIEW,
      actorUid,
      reason: `Dispute ${disputeId} upheld${note ? `: ${String(note).slice(0, 200)}` : ""}`,
    });
  }

  const now = fs().now();
  await db.runTransaction(async (tx) => {
    const indRef = db.collection("threatIndicators").doc(d.lookupKey);
    const ind = await tx.get(indRef);
    tx.update(disputeRef, { status: resolution, resolvedAt: now, resolvedByUid: actorUid, resolutionNote: note ? String(note).slice(0, 500) : null });
    if (ind.exists) {
      tx.update(indRef, { openDisputeCount: Math.max(0, (ind.data().openDisputeCount || 0) - 1) });
    }
    tx.set(db.collection("indicatorHistory").doc(), {
      lookupKey: d.lookupKey,
      timestamp: now,
      sourceType: SOURCE_TYPES.MANUAL_REVIEW,
      actorUid,
      event: `DISPUTE_${resolution}`,
      disputeId,
      reason: note ? String(note).slice(0, 200) : `Dispute ${resolution.toLowerCase()}`,
    });
  });
  return { success: true, status: resolution };
}

/* ------------------------------------------------------------------------- */
/* Watches & notifications                                                    */
/* ------------------------------------------------------------------------- */

async function setThreatWatch(db, uid, lookupKey, enabled) {
  const watchRef = db.collection("threatWatches").doc(`${uid}_${lookupKey}`);
  if (!enabled) {
    await watchRef.delete();
    return { success: true, enabled: false };
  }
  const existing = await db.collection("threatWatches").where("uid", "==", uid).limit(MAX_WATCHES_PER_USER + 1).get();
  const alreadyWatched = existing.docs.some((d) => d.id === watchRef.id);
  if (!alreadyWatched && existing.size >= MAX_WATCHES_PER_USER) {
    throw new Error("Byl dosažen maximální počet sledovaných hrozeb.");
  }
  const ind = await db.collection("threatIndicators").doc(lookupKey).get();
  await watchRef.set({
    uid,
    lookupKey,
    enabled: true,
    maskedDisplay: ind.exists ? ind.data().maskedValue || "***" : "***",
    createdAt: fs().serverTimestamp(),
    lastNotifiedAt: null,
  });
  return { success: true, enabled: true };
}

async function listThreatWatches(db, uid) {
  const snap = await db.collection("threatWatches").where("uid", "==", uid).limit(MAX_WATCHES_PER_USER).get();
  return snap.docs.map((d) => ({ lookupKey: d.data().lookupKey, maskedDisplay: d.data().maskedDisplay || "***" }));
}

async function notifyWatchers(db, lookupKey, messaging = null) {
  try {
    const querySnap = await db
      .collection("threatWatches")
      .where("lookupKey", "==", lookupKey)
      .where("enabled", "==", true)
      .get();
    if (querySnap.empty) return 0;
    const msg = messaging || require("firebase-admin").messaging();
    let sent = 0;
    for (const doc of querySnap.docs) {
      const { uid } = doc.data();
      const devicesSnap = await db.collection("users").doc(uid).collection("devices").where("notificationsEnabled", "==", true).get();
      for (const devDoc of devicesSnap.docs) {
        const token = devDoc.data().fcmToken;
        if (!token) continue;
        try {
          // No URL / phone / identifiers on the lock screen.
          await msg.send({
            token,
            notification: {
              title: "Nové bezpečnostní zjištění",
              body: "Obsah, který jste dříve kontrolovali, byl mezitím potvrzen jako podvodný.",
            },
            data: { category: "account_security", action: "threat_confirmed" },
            android: { priority: "high", notification: { channelId: "bacha_account_security" } },
          });
          sent++;
        } catch (e) {
          console.warn(`Push delivery failed: ${e.message}`);
        }
      }
      await doc.ref.update({ lastNotifiedAt: fs().serverTimestamp() });
    }
    return sent;
  } catch (e) {
    console.error(`Error notifying watchers: ${e.message}`);
    return 0;
  }
}

/* ------------------------------------------------------------------------- */
/* Maintenance                                                                */
/* ------------------------------------------------------------------------- */

async function revalidateExpiredIndicators(db) {
  const now = fs().now();
  const expiredSnap = await db
    .collection("threatIndicators")
    .where("active", "==", true)
    .where("expiresAt", "<", now)
    .limit(200)
    .get();
  let count = 0;
  for (const doc of expiredSnap.docs) {
    const data = doc.data();
    if (data.verdict === VERDICTS.KNOWN_SAFE) continue;
    await doc.ref.update({ verdict: VERDICTS.INACTIVE, active: false, lastVerifiedAt: now });
    await db.collection("indicatorHistory").add({
      lookupKey: doc.id,
      previousVerdict: data.verdict,
      newVerdict: VERDICTS.INACTIVE,
      timestamp: now,
      sourceType: SOURCE_TYPES.AUTOMATED_ANALYSIS,
      actorUid: null,
      reason: "Automated expiration without renewed evidence",
    });
    count++;
  }
  return { expiredCount: count };
}

module.exports = {
  INDICATOR_TYPES,
  VERDICTS,
  SOURCE_TYPES,
  TRUSTED_SOURCES,
  DISPUTE_STATUS,
  MAX_WATCHES_PER_USER,
  computeHmacLookupKey,
  normalizeDomain,
  extractRegistrableDomain,
  normalizeUrl,
  normalizePhone,
  normalizeEmail,
  normalizeIndicator,
  extractCandidateIndicators,
  GoogleWebRiskProvider,
  PhishTankProvider,
  UrlhausProvider,
  checkExternalProviders,
  queryThreatIntelligence,
  pickTopReputation,
  applyTrustedVerdict,
  verdictAfterCommunityReport,
  submitCommunityReport,
  submitDispute,
  resolveDispute,
  setThreatWatch,
  listThreatWatches,
  notifyWatchers,
  revalidateExpiredIndicators,
};
