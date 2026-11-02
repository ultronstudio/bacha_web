"use strict";

/**
 * Server-side input limits. These are the real security boundary
 * (client-side limits only exist for UX) – spec P0.9.
 */
const LIMITS = Object.freeze({
  MAX_TEXT_CHARS: 15000,
  // base64 of a JPEG; ~1.5 MB of binary data
  MAX_IMAGE_BASE64_CHARS: 2 * 1024 * 1024,
  MAX_IMAGE_BYTES: 1536 * 1024,
  MAX_LOOKUP_INDICATORS: 10,
  MAX_INDICATOR_VALUE_CHARS: 2048,
  MAX_REPORT_NOTE_CHARS: 500,
  MAX_DISPUTE_REASON_CHARS: 1000,
  MIN_DISPUTE_REASON_CHARS: 10,
  MAX_PURCHASE_TOKEN_CHARS: 4096,
  MAX_LOOKUP_KEY_CHARS: 128,
  MAX_EXTRACTED_CANDIDATES: 15,
});

const ANALYSIS_TYPES = ["TEXT_OR_URL", "SCREENSHOT", "QR_CODE", "PHONE_NUMBER"];
const INDICATOR_TYPES_ALLOWED = ["URL", "DOMAIN", "PHONE", "EMAIL"];
// Must stay in sync with Android `ThreatCategory` / `FinancialHarmChoice`.
const REPORT_CATEGORIES = [
  "PHISHING", "MALWARE", "FAKE_BANK", "FAKE_DELIVERY", "MARKETPLACE_SCAM", "FAKE_SHOP",
  "INVESTMENT_SCAM", "CRYPTO_SCAM", "CREDENTIAL_THEFT", "OTP_THEFT", "REMOTE_ACCESS_SCAM",
  "IMPERSONATION", "PAYMENT_SCAM", "OTHER",
];
const FINANCIAL_HARM = ["YES", "NO", "PREFER_NOT_TO_SAY"];

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

function isPlainString(v) {
  return typeof v === "string";
}

/** JPEG (FF D8 FF) or PNG (89 50 4E 47) or WEBP (RIFF....WEBP) magic bytes. */
function detectImageMime(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }
  if (buffer.length >= 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return "image/png";
  }
  if (
    buffer.length >= 12 &&
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "image/webp";
  }
  return null;
}

function validateAnalyzeRequest(data) {
  const d = data || {};
  const text = d.text == null ? "" : d.text;
  if (!isPlainString(text)) throw new ValidationError("Text musí být řetězec.");
  if (text.length > LIMITS.MAX_TEXT_CHARS) {
    throw new ValidationError(`Text je příliš dlouhý (max ${LIMITS.MAX_TEXT_CHARS} znaků).`);
  }
  const analysisType = d.analysisType == null ? "TEXT_OR_URL" : d.analysisType;
  if (!ANALYSIS_TYPES.includes(analysisType)) {
    throw new ValidationError("Neplatný typ analýzy.");
  }

  let image = null;
  if (d.imageBase64 != null && d.imageBase64 !== "") {
    if (!isPlainString(d.imageBase64)) throw new ValidationError("Neplatný obrázek.");
    if (d.imageBase64.length > LIMITS.MAX_IMAGE_BASE64_CHARS) {
      throw new ValidationError("Obrázek je příliš velký.");
    }
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(d.imageBase64)) {
      throw new ValidationError("Obrázek není platně zakódovaný.");
    }
    const buffer = Buffer.from(d.imageBase64, "base64");
    if (buffer.length === 0 || buffer.length > LIMITS.MAX_IMAGE_BYTES) {
      throw new ValidationError("Obrázek je příliš velký nebo prázdný.");
    }
    const mimeType = detectImageMime(buffer);
    if (!mimeType) throw new ValidationError("Nepodporovaný formát obrázku.");
    image = { base64: buffer.toString("base64"), mimeType, bytes: buffer.length };
  }

  if (text.trim() === "" && !image) {
    throw new ValidationError("Nebyl zadán žádný obsah ke kontrole.");
  }
  return { text, analysisType, image };
}

function validateLookupRequest(data) {
  const indicators = data && data.indicators;
  if (!Array.isArray(indicators) || indicators.length === 0) {
    throw new ValidationError("Chybí pole indikátorů k prověření.");
  }
  if (indicators.length > LIMITS.MAX_LOOKUP_INDICATORS) {
    throw new ValidationError(`Příliš mnoho indikátorů (max ${LIMITS.MAX_LOOKUP_INDICATORS}).`);
  }
  return indicators.map((ind) => {
    const type = ind && ind.type;
    const value = ind && ind.value;
    if (!INDICATOR_TYPES_ALLOWED.includes(type)) throw new ValidationError("Neplatný typ indikátoru.");
    if (!isPlainString(value) || value.trim() === "" || value.length > LIMITS.MAX_INDICATOR_VALUE_CHARS) {
      throw new ValidationError("Neplatná hodnota indikátoru.");
    }
    return { type, value };
  });
}

function validateReportRequest(data) {
  const d = data || {};
  if (!isPlainString(d.rawValue) || d.rawValue.trim() === "" || d.rawValue.length > LIMITS.MAX_INDICATOR_VALUE_CHARS) {
    throw new ValidationError("Chybí nebo je neplatná hodnota nahlašovaného obsahu.");
  }
  const indicatorType = d.indicatorType || "URL";
  if (!INDICATOR_TYPES_ALLOWED.includes(indicatorType)) throw new ValidationError("Neplatný typ indikátoru.");
  const category = d.category || "OTHER";
  if (!REPORT_CATEGORIES.includes(category)) throw new ValidationError("Neplatná kategorie.");
  const financialHarm = d.financialHarm || "PREFER_NOT_TO_SAY";
  if (!FINANCIAL_HARM.includes(financialHarm)) throw new ValidationError("Neplatná hodnota škody.");
  let note = null;
  if (d.note != null && d.note !== "") {
    if (!isPlainString(d.note)) throw new ValidationError("Poznámka musí být text.");
    if (d.note.length > LIMITS.MAX_REPORT_NOTE_CHARS) {
      throw new ValidationError(`Poznámka je příliš dlouhá (max ${LIMITS.MAX_REPORT_NOTE_CHARS} znaků).`);
    }
    note = d.note;
  }
  return { rawValue: d.rawValue, indicatorType, category, financialHarm, note };
}

function validateLookupKey(lookupKey) {
  if (!isPlainString(lookupKey) || !/^[a-f0-9]{64}$/.test(lookupKey)) {
    throw new ValidationError("Neplatný lookupKey.");
  }
  return lookupKey;
}

function validateDisputeRequest(data) {
  const d = data || {};
  const lookupKey = validateLookupKey(d.lookupKey);
  if (!isPlainString(d.reason)) throw new ValidationError("Chybí odůvodnění.");
  const reason = d.reason.trim();
  if (reason.length < LIMITS.MIN_DISPUTE_REASON_CHARS || reason.length > LIMITS.MAX_DISPUTE_REASON_CHARS) {
    throw new ValidationError(
      `Odůvodnění musí mít ${LIMITS.MIN_DISPUTE_REASON_CHARS}–${LIMITS.MAX_DISPUTE_REASON_CHARS} znaků.`
    );
  }
  const indicatorType = INDICATOR_TYPES_ALLOWED.includes(d.indicatorType) ? d.indicatorType : "OTHER";
  return { lookupKey, reason, indicatorType };
}

function validateWatchRequest(data) {
  const d = data || {};
  return { lookupKey: validateLookupKey(d.lookupKey), enabled: d.enabled !== false };
}

module.exports = {
  LIMITS,
  ANALYSIS_TYPES,
  INDICATOR_TYPES_ALLOWED,
  REPORT_CATEGORIES,
  FINANCIAL_HARM,
  ValidationError,
  detectImageMime,
  validateAnalyzeRequest,
  validateLookupRequest,
  validateReportRequest,
  validateDisputeRequest,
  validateWatchRequest,
  validateLookupKey,
};
