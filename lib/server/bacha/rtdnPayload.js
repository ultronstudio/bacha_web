"use strict";

class RtdnPayloadError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

function decodePubSubRtdn(envelope) {
  const encoded = envelope && envelope.message && envelope.message.data;
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 100_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new RtdnPayloadError("Neplatná Pub/Sub zpráva.");
  }
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid object");
    return payload;
  } catch {
    throw new RtdnPayloadError("Neplatná RTDN zpráva.");
  }
}

module.exports = { decodePubSubRtdn, RtdnPayloadError };
