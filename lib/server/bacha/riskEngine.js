"use strict";

/**
 * Server-side evidence-based risk combination (spec P1.3–P1.5).
 *
 * Each piece of evidence has a strength. Result categories:
 *   NO_KNOWN_RED_FLAGS | SUSPICIOUS | HIGH_RISK | KNOWN_MALICIOUS | INCONCLUSIVE
 * "No known red flags" never means "safe". KNOWN_SAFE is positive evidence
 * that can never downgrade strong negative evidence.
 * Weights are initial values to be calibrated against the eval corpus.
 */

const STRENGTH = Object.freeze({
  VERY_HIGH: 1.0, // verified threat feed, manual verification
  HIGH: 0.7, // impersonation, credential stealing, remote access scam
  MEDIUM: 0.4, // community reports, AI-only high suspicion
  LOW: 0.15, // shortener, unusual TLD, plain HTTP
});

const CATEGORIES = Object.freeze({
  NO_KNOWN_RED_FLAGS: "NO_KNOWN_RED_FLAGS",
  SUSPICIOUS: "SUSPICIOUS",
  HIGH_RISK: "HIGH_RISK",
  KNOWN_MALICIOUS: "KNOWN_MALICIOUS",
  INCONCLUSIVE: "INCONCLUSIVE",
});

function evidenceFromThreatReputation(rep) {
  if (!rep) return [];
  switch (rep.verdict) {
    case "CONFIRMED_MALICIOUS":
      return [{ type: "threat_feed", source: "THREAT_INTEL", strength: STRENGTH.VERY_HIGH, negative: true, definitive: true }];
    case "SUSPICIOUS":
      return [{ type: "community_reports", source: "THREAT_INTEL", strength: STRENGTH.MEDIUM, negative: true }];
    case "DISPUTED":
      return [{ type: "disputed_record", source: "THREAT_INTEL", strength: STRENGTH.LOW, negative: true }];
    case "KNOWN_SAFE":
      return [{ type: "known_safe", source: "THREAT_INTEL", strength: STRENGTH.MEDIUM, negative: false }];
    default:
      return [];
  }
}

function evidenceFromAi(ai) {
  if (!ai) return [];
  const out = [];
  // Model self-confidence is not calibrated evidence. Use bounded severity weights instead.
  for (const s of ai.signals || []) {
    if (s.isPositive) continue;
    const base = s.severity === "HIGH" ? STRENGTH.HIGH : s.severity === "CAUTION" ? STRENGTH.MEDIUM * 0.75 : STRENGTH.LOW;
    out.push({ type: s.id, source: "AI", strength: base, group: `AI:${s.evidenceGroup || "OTHER"}`, negative: true });
  }
  if (out.length === 0 && ai.riskLevel === "HIGH") {
    out.push({ type: "ai_overall_high", source: "AI", strength: STRENGTH.MEDIUM, group: "AI:OTHER", negative: true });
  }
  return out;
}

/** Noisy-OR aggregation of negative evidence. */
function combine(evidence) {
  const negatives = evidence.filter((e) => e.negative);
  if (negatives.some((e) => e.definitive)) {
    return { category: CATEGORIES.KNOWN_MALICIOUS, riskLevel: "HIGH", score: 1 };
  }
  let p = 0;
  const groups = new Map();
  for (const e of negatives) {
    const key = e.group || `${e.source}:${e.type}`;
    groups.set(key, Math.max(groups.get(key) || 0, Math.min(1, Math.max(0, e.strength))));
  }
  for (const weight of groups.values()) p = 1 - (1 - p) * (1 - weight);
  // KNOWN_SAFE may only soften weak signals – never strong ones (P1.5)
  const hasKnownSafe = evidence.some((e) => !e.negative && e.type === "known_safe");
  const strongestNegative = negatives.reduce((m, e) => Math.max(m, e.strength), 0);
  if (hasKnownSafe && strongestNegative < STRENGTH.HIGH) p = p * 0.5;

  if (p >= 0.65) return { category: CATEGORIES.HIGH_RISK, riskLevel: "HIGH", score: p };
  if (p >= 0.25) return { category: CATEGORIES.SUSPICIOUS, riskLevel: "CAUTION", score: p };
  return { category: CATEGORIES.NO_KNOWN_RED_FLAGS, riskLevel: "LOW", score: p };
}

/**
 * Combines threat intel + validated AI output into a final verdict.
 * When AI result is UNKNOWN with no other evidence -> INCONCLUSIVE.
 */
function combineServerVerdict({ threatReputation, ai, metadataSignals = [] }) {
  const metadata = metadataSignals.filter((s) => s.source === "URL_METADATA" && !s.isPositive).map((s) => ({
    type: s.id, group: `METADATA:${s.evidenceGroup}`, source: "URL_METADATA",
    strength: s.severity === "CAUTION" ? STRENGTH.MEDIUM : STRENGTH.LOW, negative: true,
  }));
  const evidence = [...evidenceFromThreatReputation(threatReputation), ...evidenceFromAi(ai), ...metadata];
  if (ai && ai.riskLevel === "UNKNOWN" && evidence.filter((e) => e.negative).length === 0) {
    return { category: CATEGORIES.INCONCLUSIVE, riskLevel: "UNKNOWN", score: 0 };
  }
  const result = combine(evidence);
  // Unsupported AI-only HIGH is a warning, not independent high-strength evidence.
  if (ai && ai.riskLevel === "HIGH" && result.riskLevel === "LOW") {
    return { category: CATEGORIES.SUSPICIOUS, riskLevel: "CAUTION", score: Math.max(result.score, 0.25) };
  }
  if (ai?.requiresFurtherVerification && result.riskLevel === "LOW") {
    return { category: CATEGORIES.INCONCLUSIVE, riskLevel: "UNKNOWN", score: result.score };
  }
  if (ai && ai.riskLevel === "CAUTION" && result.riskLevel === "LOW") {
    return { category: CATEGORIES.SUSPICIOUS, riskLevel: "CAUTION", score: Math.max(result.score, 0.25) };
  }
  return result;
}

module.exports = { STRENGTH, CATEGORIES, combine, combineServerVerdict, evidenceFromAi, evidenceFromThreatReputation };
