"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildOpenAiRequest, extractOpenAiText, generateOpenAi } = require("../../lib/server/bacha/openaiClient");
const { RESPONSE_SCHEMA, SYSTEM_INSTRUCTION, buildUserPrompt, validateAiOutput } = require("../../lib/server/bacha/aiOutput");
const { validateAnalyzeRequest } = require("../../lib/server/bacha/limits");

const good = { riskLevel: "CAUTION", confidence: "MEDIUM", summary: "Podezřelé chování.",
  signals: [], recommendedActions: [], limitations: [] };
const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]).toString("base64");
function params(type, text, imageBase64) {
  const input = validateAnalyzeRequest({ analysisType: type, text, imageBase64 });
  return { model: "gpt-5.4-mini", systemInstruction: SYSTEM_INSTRUCTION, responseSchema: RESPONSE_SCHEMA,
    userPrompt: buildUserPrompt({ text: input.text, analysisType: input.analysisType, hasImage: !!input.image }),
    image: input.image };
}
test("text, QR URL and phone use structured outputs and untrusted content separation", () => {
  for (const [type, text] of [["TEXT_OR_URL", "Zaplať hned"], ["QR_CODE", "https://example.org/pay"], ["PHONE_NUMBER", "+420 777 888 999"]]) {
    const body = buildOpenAiRequest(params(type, text));
    assert.equal(body.store, false);
    assert.equal(body.text.format.type, "json_schema");
    assert.equal(body.text.format.strict, true);
    assert.equal(body.text.format.schema.additionalProperties, false);
    assert.equal(body.input[0].content.length, 1);
    assert.ok(body.input[0].content[0].text.includes(text));
    assert.equal(body.instructions.includes(text), false);
  }
});
test("screenshot sends base64 image without external image URL", () => {
  const body = buildOpenAiRequest(params("SCREENSHOT", "", jpeg));
  assert.equal(body.input[0].content.length, 2);
  assert.equal(body.input[0].content[1].type, "input_image");
  assert.equal(body.input[0].content[1].image_url, `data:image/jpeg;base64,${jpeg}`);
  assert.equal(body.store, false);
});
test("QR image plus decoded URL are analyzed together", () => {
  const body = buildOpenAiRequest(params("QR_CODE", "https://example.org/pay", jpeg));
  assert.equal(body.input[0].content.length, 2);
  assert.match(body.input[0].content[0].text, /QR kód/);
});
test("rejects untrusted MIME and absent structured output", () => {
  assert.throws(() => buildOpenAiRequest({ ...params("TEXT_OR_URL", "x"), image: { mimeType: "image/svg+xml", base64: "x" } }));
  assert.throws(() => extractOpenAiText({ status: "incomplete", output: [] }));
  assert.throws(() => extractOpenAiText({ status: "completed", output: [{ type: "message", content: [{ type: "refusal" }] }] }));
});
test("mock OpenAI response is validated and authenticated server-side, never store request", async () => {
  let captured;
  const output = { status: "completed", output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify(good) }] }] };
  const raw = await generateOpenAi(params("TEXT_OR_URL", "podezřelá SMS"), {
    env: { OPENAI_API_KEY: "test-secret" },
    fetchImpl: async (url, init) => { captured = { url, init }; return { ok: true, json: async () => output }; },
  });
  assert.equal(validateAiOutput(raw).riskLevel, "CAUTION");
  assert.equal(captured.url, "https://api.openai.com/v1/responses");
  assert.equal(captured.init.headers.Authorization, "Bearer test-secret");
  assert.equal(JSON.parse(captured.init.body).store, false);
  assert.equal(captured.init.cache, "no-store");
  await assert.rejects(generateOpenAi(params("TEXT_OR_URL", "x"), { env: {}, fetchImpl: () => { throw Error("unexpected"); } }), /Required server secret/);
  await assert.rejects(generateOpenAi(params("TEXT_OR_URL", "x"), {
    env: { OPENAI_API_KEY: "test-secret" }, fetchImpl: async () => ({ ok: false, status: 429, text: async () => "PRIVATE" }),
  }), e => e.message.includes("429") && !e.message.includes("PRIVATE"));
});
