"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { decodePubSubRtdn } = require("../../lib/server/bacha/rtdnPayload");
const { verifyPubSubOidc } = require("../../lib/server/bacha/rtdnAuth");

test("decodes the standard Pub/Sub RTDN push envelope", () => {
  const payload = { packageName: "cz.petrvurm.bacha", subscriptionNotification: { purchaseToken: "token", notificationType: 2 } };
  const envelope = { message: { data: Buffer.from(JSON.stringify(payload)).toString("base64") } };
  assert.deepEqual(decodePubSubRtdn(envelope), payload);
});

test("rejects missing, malformed, oversized, or non-object RTDN data", () => {
  assert.throws(() => decodePubSubRtdn({}));
  assert.throws(() => decodePubSubRtdn({ message: { data: "%%%" } }));
  assert.throws(() => decodePubSubRtdn({ message: { data: Buffer.from("[]").toString("base64") } }));
  assert.throws(() => decodePubSubRtdn({ message: { data: "A".repeat(100_001) } }));
});

test("accepts only verified OIDC identity and the configured push audience", async () => {
  let seenAudience;
  const verify = async (_token, audience) => {
    seenAudience = audience;
    return { email: "PUSH@EXAMPLE.COM", email_verified: true };
  };
  await verifyPubSubOidc("signed-token", "push@example.com", "https://api.example/rtdn", verify);
  assert.equal(seenAudience, "https://api.example/rtdn");
  await assert.rejects(verifyPubSubOidc("token", "other@example.com", "aud", verify), (e) => e.status === 403);
  await assert.rejects(verifyPubSubOidc("token", "push@example.com", "aud", async () => ({ email: "push@example.com", email_verified: false })), (e) => e.status === 403);
});
