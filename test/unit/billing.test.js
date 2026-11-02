"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { freshDb, silentLogger } = require("../helpers/setup");
const billing = require("../../lib/server/bacha/billing");

const NOW = Date.parse("2026-11-01T10:00:00Z");
const FUTURE = new Date(NOW + 20 * 86400000).toISOString();
const PAST = new Date(NOW - 86400000).toISOString();
const TOKEN = "valid-purchase-token-abcdefghij";

function sub(state, { expiry = FUTURE, autoRenew = true, ack = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED", productId = "bacha_plus", obf } = {}) {
  return {
    subscriptionState: state,
    acknowledgementState: ack,
    lineItems: [{ productId, expiryTime: expiry, autoRenewingPlan: { autoRenewEnabled: autoRenew }, offerDetails: { basePlanId: "monthly" } }],
    externalAccountIdentifiers: obf ? { obfuscatedExternalAccountId: obf } : undefined,
  };
}

function playClient({ data, error, hang = false, onAck } = {}) {
  return {
    purchases: {
      subscriptionsv2: {
        get: async () => {
          if (hang) return new Promise(() => {});
          if (error) throw error;
          return { data };
        },
      },
      subscriptions: {
        acknowledge: async (args) => {
          if (onAck) onAck(args);
          return {};
        },
      },
    },
  };
}

function deps(db, pc, extra = {}) {
  return { db, playClient: pc, logger: silentLogger, now: () => NOW, timeoutMs: 50, ...extra };
}

function entitlement(db, uid) {
  return db.raw(`users/${uid}/entitlement/current`);
}

describe("mapSubscriptionToEntitlement", () => {
  test("active auto-renewing -> PLUS_ACTIVE", () => {
    const e = billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_ACTIVE"), NOW);
    assert.equal(e.tier, "PLUS");
    assert.equal(e.status, "PLUS_ACTIVE");
  });
  test("active but expiry in past -> EXPIRED / FREE", () => {
    const e = billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_ACTIVE", { expiry: PAST }), NOW);
    assert.equal(e.tier, "FREE");
    assert.equal(e.status, "EXPIRED");
  });
  test("canceled before expiry -> active until expiry", () => {
    const e = billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_CANCELED", { autoRenew: false }), NOW);
    assert.equal(e.tier, "PLUS");
    assert.equal(e.status, "PLUS_CANCELED_BUT_ACTIVE_UNTIL_EXPIRY");
  });
  test("canceled after expiry -> FREE", () => {
    const e = billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_CANCELED", { expiry: PAST }), NOW);
    assert.equal(e.tier, "FREE");
  });
  test("grace period keeps Plus", () => {
    const e = billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_IN_GRACE_PERIOD"), NOW);
    assert.equal(e.tier, "PLUS");
    assert.equal(e.status, "PLUS_GRACE_PERIOD");
  });
  test("on hold / paused -> FREE", () => {
    for (const s of ["SUBSCRIPTION_STATE_ON_HOLD", "SUBSCRIPTION_STATE_PAUSED"]) {
      const e = billing.mapSubscriptionToEntitlement(sub(s), NOW);
      assert.equal(e.tier, "FREE", s);
      assert.equal(e.status, "PLUS_ON_HOLD");
    }
  });
  test("expired / pending / unknown -> FREE", () => {
    for (const s of ["SUBSCRIPTION_STATE_EXPIRED", "SUBSCRIPTION_STATE_PENDING", "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED", "SUBSCRIPTION_STATE_UNSPECIFIED", undefined]) {
      assert.equal(billing.mapSubscriptionToEntitlement(sub(s), NOW).tier, "FREE", String(s));
    }
  });
  test("foreign product is rejected", () => {
    assert.throws(() => billing.mapSubscriptionToEntitlement(sub("SUBSCRIPTION_STATE_ACTIVE", { productId: "other" }), NOW), billing.BillingVerificationError);
  });
});

describe("entitlementGrantsPlus (server quota check)", () => {
  test("requires non-expired PLUS status", () => {
    assert.equal(billing.entitlementGrantsPlus({ tier: "PLUS", status: "PLUS_ACTIVE", expiryTimeMillis: NOW + 1000 }, NOW), true);
    assert.equal(billing.entitlementGrantsPlus({ tier: "PLUS", status: "PLUS_ACTIVE", expiryTimeMillis: NOW - 1000 }, NOW), false);
    assert.equal(billing.entitlementGrantsPlus({ tier: "PLUS", status: "PLUS_ACTIVE" }, NOW), false);
    assert.equal(billing.entitlementGrantsPlus({ tier: "PLUS", status: "PLUS_ON_HOLD", expiryTimeMillis: NOW + 1000 }, NOW), false);
    assert.equal(billing.entitlementGrantsPlus(null, NOW), false);
  });
});

describe("verifyAndGrant – fail closed", () => {
  test("valid active purchase grants Plus and acknowledges", async () => {
    const db = freshDb(() => NOW);
    let acked = false;
    const res = await billing.verifyAndGrant(
      deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE", { ack: "ACKNOWLEDGEMENT_STATE_PENDING" }), onAck: () => (acked = true) })),
      "u1",
      { purchaseToken: TOKEN, productId: "bacha_plus" }
    );
    assert.equal(res.verified, true);
    assert.equal(entitlement(db, "u1").tier, "PLUS");
    assert.equal(acked, true);
    assert.equal(entitlement(db, "u1").purchaseToken, undefined, "raw token must not be stored");
  });

  test("Google Play API outage -> no entitlement, unavailable error", async () => {
    const db = freshDb(() => NOW);
    const err = Object.assign(new Error("503"), { code: 503 });
    await assert.rejects(
      billing.verifyAndGrant(deps(db, playClient({ error: err })), "u1", { purchaseToken: TOKEN }),
      (e) => e.code === "unavailable"
    );
    assert.equal(entitlement(db, "u1"), undefined);
    assert.equal(db.docsIn("purchases").length, 0);
  });

  test("Play API timeout -> no entitlement", async () => {
    const db = freshDb(() => NOW);
    await assert.rejects(billing.verifyAndGrant(deps(db, playClient({ hang: true })), "u1", { purchaseToken: TOKEN }), (e) => e.code === "unavailable");
    assert.equal(entitlement(db, "u1"), undefined);
  });

  test("fake / invalid token (404 from Play) -> invalid-argument, no entitlement", async () => {
    const db = freshDb(() => NOW);
    const err = Object.assign(new Error("not found"), { code: 404 });
    await assert.rejects(billing.verifyAndGrant(deps(db, playClient({ error: err })), "u1", { purchaseToken: TOKEN }), (e) => e.code === "invalid-argument");
    assert.equal(entitlement(db, "u1"), undefined);
  });

  test("malformed token is rejected before calling Play", async () => {
    const db = freshDb(() => NOW);
    let called = false;
    const pc = playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") });
    pc.purchases.subscriptionsv2.get = async () => {
      called = true;
      return { data: {} };
    };
    for (const bad of [undefined, "", "short", 42, "x".repeat(5000)]) {
      await assert.rejects(billing.verifyAndGrant(deps(db, pc), "u1", { purchaseToken: bad }), (e) => e.code === "invalid-argument");
    }
    await assert.rejects(billing.verifyAndGrant(deps(db, pc), "u1", { purchaseToken: TOKEN, productId: "free_money" }), (e) => e.code === "invalid-argument");
    assert.equal(called, false);
  });

  test("expired subscription -> FREE entitlement, verified=false", async () => {
    const db = freshDb(() => NOW);
    const res = await billing.verifyAndGrant(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_EXPIRED", { expiry: PAST }) })), "u1", { purchaseToken: TOKEN });
    assert.equal(res.verified, false);
    assert.equal(entitlement(db, "u1").tier, "FREE");
  });

  test("on hold -> FREE", async () => {
    const db = freshDb(() => NOW);
    const res = await billing.verifyAndGrant(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_ON_HOLD") })), "u1", { purchaseToken: TOKEN });
    assert.equal(res.verified, false);
    assert.equal(entitlement(db, "u1").tier, "FREE");
  });

  test("same token for two users -> second rejected (replay)", async () => {
    const db = freshDb(() => NOW);
    const pc = playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") });
    await billing.verifyAndGrant(deps(db, pc), "u1", { purchaseToken: TOKEN });
    await assert.rejects(billing.verifyAndGrant(deps(db, pc), "attacker", { purchaseToken: TOKEN }), (e) => e.code === "already-exists");
    assert.equal(entitlement(db, "attacker"), undefined);
  });

  test("purchase replay by same user is idempotent", async () => {
    const db = freshDb(() => NOW);
    const pc = playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") });
    await billing.verifyAndGrant(deps(db, pc), "u1", { purchaseToken: TOKEN });
    const res = await billing.verifyAndGrant(deps(db, pc), "u1", { purchaseToken: TOKEN });
    assert.equal(res.verified, true);
    assert.equal(db.docsIn("purchases").length, 1);
  });

  test("obfuscated account id mismatch -> permission-denied", async () => {
    const db = freshDb(() => NOW);
    const pc = playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE", { obf: billing.obfuscatedAccountIdForUid("owner") }) });
    await assert.rejects(billing.verifyAndGrant(deps(db, pc), "other", { purchaseToken: TOKEN }), (e) => e.code === "permission-denied");
    const ok = await billing.verifyAndGrant(deps(db, pc), "owner", { purchaseToken: TOKEN });
    assert.equal(ok.verified, true);
  });

  test("concurrent claims of one token by two users -> exactly one wins", async () => {
    const db = freshDb(() => NOW);
    const pc = playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") });
    const results = await Promise.allSettled([
      billing.verifyAndGrant(deps(db, pc), "a", { purchaseToken: TOKEN }),
      billing.verifyAndGrant(deps(db, pc), "b", { purchaseToken: TOKEN }),
    ]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  });
});

describe("handleRtdn", () => {
  test("re-reads state from Play and revokes on expiry", async () => {
    const db = freshDb(() => NOW);
    await billing.verifyAndGrant(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") })), "u1", { purchaseToken: TOKEN });
    const res = await billing.handleRtdn(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_EXPIRED", { expiry: PAST }) })), {
      packageName: "cz.petrvurm.bacha",
      subscriptionNotification: { purchaseToken: TOKEN, notificationType: 2 /* RENEWED (lie) */ },
    });
    assert.equal(res.handled, true);
    assert.equal(entitlement(db, "u1").tier, "FREE", "notification type alone must not grant");
  });

  test("Play outage during RTDN throws (Pub/Sub retry) and keeps state", async () => {
    const db = freshDb(() => NOW);
    await billing.verifyAndGrant(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") })), "u1", { purchaseToken: TOKEN });
    await assert.rejects(
      billing.handleRtdn(deps(db, playClient({ error: Object.assign(new Error("x"), { code: 500 }) })), {
        subscriptionNotification: { purchaseToken: TOKEN, notificationType: 13 },
      })
    );
  });

  test("unknown token is ignored", async () => {
    const db = freshDb(() => NOW);
    const res = await billing.handleRtdn(deps(db, playClient({ data: sub("SUBSCRIPTION_STATE_ACTIVE") })), {
      subscriptionNotification: { purchaseToken: "unknown-token-123456", notificationType: 2 },
    });
    assert.equal(res.handled, false);
  });
});
