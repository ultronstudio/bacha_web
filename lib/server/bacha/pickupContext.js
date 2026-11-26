"use strict";

/**
 * Very narrow recognition of ordinary pickup instructions. This is NOT a safe
 * allowlist. Ambiguous or mixed content, attachments, URLs and external
 * evidence are never suppressed. Codes are never logged or persisted.
 */
function ordinaryPickupOnly(text) {
  if (typeof text !== "string" || text.length > 240) return false;
  const norm = text.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase().trim();
  if (!/^[a-z0-9 ,.!?;\n\t]+$/.test(norm)) return false;
  const clauses = norm.split(/[.!?;\n]+/).map(s => s.trim()).filter(Boolean);
  let pickup = false, code = false;
  for (const clause of clauses) {
    if (/^(?:ahoj|dobry den|cau)(?:[, ]+(?:mami|tati|babi|dedo))?$/.test(clause)) continue;
    if (/^(?:potrebuju|potrebuji|prosim|muzes|muzete|vyzvedni|vyzvednete)(?:[, ]+(?:mi|nam|prosim|potrebuji|potrebuju|vyzvednout|vyzvedni|vyzvednete))* +(?:balicek|balik|zasilku)$/.test(clause)) { pickup = true; continue; }
    if (/^(?:(?:vyzvedavaci|vydejni) )?kod (?:je )?[0-9]{3} ?[0-9]{3}$/.test(clause)) { code = true; continue; }
    if (/^(?:dej|dejte) mi vedet az (?:ho|ji|jej) vyzvedn(?:es|ete)$/.test(clause)) continue;
    if (/^(?:dik|diky|dekuji|dekuju)$/.test(clause)) continue;
    return false;
  }
  return pickup && code;
}
function reconcilePickup(ai, input, rep, metadata) {
  if (input.image || input.analysisType !== "TEXT_OR_URL" || !ordinaryPickupOnly(input.text) ||
      (rep && !["UNKNOWN", "INACTIVE", "KNOWN_SAFE"].includes(rep.verdict)) || metadata.length) return ai;
  // Even when the cloud hallucinates a credential request, don't assert safety:
  // the sender / actual purpose of the code has not been authenticated.
  return {
    ...ai, riskLevel: "UNKNOWN", confidence: "LOW", scamType: "UNKNOWN",
    detectedActions: [], requiresFurtherVerification: true, signals: [],
    summary: "Zpráva připomíná běžnou domluvu o vyzvednutí zásilky. Odesílatele ani účel kódu nelze ověřit pouze z textu.",
    recommendedActions: [{ title: "Ověřte účel kódu", description: "Vyzvedávací kód sdílejte jen s osobou, která má zásilku převzít. Bankovní a přihlašovací kódy nikomu nepředávejte.", isCrucial: false }],
    limitations: ["Totožnost odesílatele a účel kódu nebyly nezávisle ověřeny."]
  };
}
module.exports = { ordinaryPickupOnly, reconcilePickup };
