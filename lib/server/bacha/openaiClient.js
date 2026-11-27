"use strict";

const { requireSecret } = require("./config");

const OPENAI_ENDPOINT = "https://api.openai.com/v1/responses";
const DEFAULT_TIMEOUT_MS = 40000;

/** Only validated and quota-authorized analysis calls reach this adapter.
 * No client credentials, content, images, or response bodies are logged.
 */
function buildOpenAiRequest({ model, systemInstruction, responseSchema, userPrompt, image }) {
  const content = [{ type: "input_text", text: userPrompt }];
  if (image) {
    if (!["image/jpeg", "image/png", "image/webp"].includes(image.mimeType)) {
      throw new Error("Unsupported image MIME");
    }
    content.push({
      type: "input_image",
      image_url: `data:${image.mimeType};base64,${image.base64}`,
      detail: "auto",
    });
  }
  return {
    model,
    instructions: systemInstruction,
    input: [{ role: "user", content }],
    text: {
      format: {
        type: "json_schema",
        name: "bacha_analysis",
        strict: true,
        schema: responseSchema,
      },
    },
    store: false,
    // Reasoning models count reasoning tokens against this limit. 2200 risked
    // status "incomplete" (truncated JSON) on longer Czech outputs; an incomplete
    // response is rejected and the credit rolled back, never parsed partially.
    max_output_tokens: 6000,
  };
}

function extractOpenAiText(body) {
  if (!body || body.status !== "completed" || !Array.isArray(body.output)) {
    throw new Error("Incomplete OpenAI response");
  }
  const segments = [];
  for (const item of body.output) {
    if (item.type !== "message" || !Array.isArray(item.content)) continue;
    for (const part of item.content) {
      if (part.type === "refusal") throw new Error("OpenAI refused the request");
      if (part.type === "output_text" && typeof part.text === "string") segments.push(part.text);
    }
  }
  if (!segments.length) throw new Error("OpenAI returned no output text");
  return segments.join("");
}

async function generateOpenAi(params, options = {}) {
  const env = options.env || process.env;
  const apiKey = requireSecret("OPENAI_API_KEY", env);
  const fetchImpl = options.fetchImpl || fetch;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const response = await fetchImpl(OPENAI_ENDPOINT, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(buildOpenAiRequest(params)),
    signal: AbortSignal.timeout(timeoutMs),
    cache: "no-store",
  });
  if (!response.ok) {
    // Never embed the provider's response body: it may contain user input.
    const err = new Error(`OpenAI API failed (HTTP ${response.status})`);
    err.providerStatus = response.status;
    const ra = Number(response.headers && response.headers.get ? response.headers.get("retry-after") : NaN);
    if (Number.isFinite(ra) && ra > 0) err.retryAfterSeconds = Math.min(600, ra);
    throw err;
  }
  const json = await response.json();
  return extractOpenAiText(json);
}

module.exports = { buildOpenAiRequest, extractOpenAiText, generateOpenAi };
