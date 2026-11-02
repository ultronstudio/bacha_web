"use strict";

/**
 * Google Play subscription verification – FAIL CLOSED (spec P0.1).
 *
 *   Google Play validation SUCCESS                    -> entitlement may be granted
 *   FAILURE / timeout / API unavailable / bad token   -> entitlement is NEVER granted
 *
 * There is deliberately no code path that assumes an ACTIVE subscription
 * when the Play Developer API cannot be reached.
 */
const crypto = require("crypto");
const { PACKAGE_NAME, PRODUCT_ID, ALLOWED_BASE_PLANS } = require("./config");
const { LIMITS } = require("./limits");
const { fs } = require("./fsHelpers");

const PLAY_API_TIMEOUT_MS = 10000;

class BillingVerificationError extends Error {
  /**
   * @param {string} code one of: invalid-argument | unavailable | failed-precondition | already-exists | permission-denied
   */
  constructor(code, message) {
    super(message);
    this.name = "BillingVerificationError";
    this.code = code;
  }
}

/** Statuses that grant Plus. Anything else is FREE. */
const PLUS_GRANTING_STATUSES = Object.freeze([
  "PLUS_ACTIVE",
  "PLUS_GRACE_PERIOD",
  "PLUS_CANCELED_BUT_ACTIVE_UNTIL_EXPIRY",
]);

function hashPurchaseToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/** The Android client passes sha256(uid) as obfuscatedAccountId to BillingFlowParams. */
function obfuscatedAccountIdForUid(uid) {
  return crypto.createHash("sha256").update(`bacha:${uid}`).digest("hex").slice(0, 64);
}

function validateVerifyRequest(data) {
  const d = data || {};
  if (typeof d.purchaseToken !== "string" || d.purchaseToken.length < 10 || d.purchaseToken.length > LIMITS.MAX_PURCHASE_TOKEN_CHARS) {
    throw new BillingVerificationError("invalid-argument", "Chybí nebo je neplatný purchaseToken.");
  }
  const productId = d.productId || PRODUCT_ID;
  if (productId !== PRODUCT_ID) {
    throw new BillingVerificationError("invalid-argument", "Neznámý produkt.");
  }
  return { purchaseToken: d.purchaseToken, productId };
}

/**
 * Maps a SubscriptionPurchaseV2 resource to an internal entitlement.
 * Pure function – unit tested for every subscription state.
 */
function mapSubscriptionToEntitlement(sub, nowMillis = Date.now()) {
  if (!sub || typeof sub !== "object") {
    throw new BillingVerificationError("failed-precondition", "Prázdná odpověď Google Play.");
  }
  const lineItems = Array.isArray(sub.lineItems) ? sub.lineItems : [];
  const item = lineItems.find((li) => li && li.productId === PRODUCT_ID);
  if (!item) {
    throw new BillingVerificationError("failed-precondition", "Nákup neodpovídá produktu Bacha!+.");
  }

  const expiryTimeMillis = item.expiryTime ? Date.parse(item.expiryTime) : NaN;
  const hasValidExpiry = Number.isFinite(expiryTimeMillis);
  const notExpired = hasValidExpiry && expiryTimeMillis > nowMillis;
  const autoRenewing = !!(item.autoRenewingPlan && item.autoRenewingPlan.autoRenewEnabled);
  const basePlanIdRaw = item.offerDetails && item.offerDetails.basePlanId;
  const basePlanId = ALLOWED_BASE_PLANS.includes(basePlanIdRaw) ? basePlanIdRaw : null;

  let status;
  switch (sub.subscriptionState) {
    case "SUBSCRIPTION_STATE_ACTIVE":
      status = notExpired ? (autoRenewing ? "PLUS_ACTIVE" : "PLUS_CANCELED_BUT_ACTIVE_UNTIL_EXPIRY") : "EXPIRED";
      break;
    case "SUBSCRIPTION_STATE_CANCELED":
      status = notExpired ? "PLUS_CANCELED_BUT_ACTIVE_UNTIL_EXPIRY" : "EXPIRED";
      break;
    case "SUBSCRIPTION_STATE_IN_GRACE_PERIOD":
      status = "PLUS_GRACE_PERIOD";
      break;
    case "SUBSCRIPTION_STATE_ON_HOLD":
      status = "PLUS_ON_HOLD";
      break;
    case "SUBSCRIPTION_STATE_PAUSED":
      status = "PLUS_ON_HOLD";
      break;
    case "SUBSCRIPTION_STATE_PENDING":
      status = "PLUS_PENDING";
      break;
    case "SUBSCRIPTION_STATE_EXPIRED":
    case "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED":
      status = "EXPIRED";
      break;
    default:
      status = "UNKNOWN";
  }

  const grantsPlus = PLUS_GRANTING_STATUSES.includes(status);
  return {
    tier: grantsPlus ? "PLUS" : "FREE",
    status,
    productId: PRODUCT_ID,
    basePlanId,
    expiryTimeMillis: hasValidExpiry ? expiryTimeMillis : null,
    autoRenewing,
    subscriptionState: sub.subscriptionState || "SUBSCRIPTION_STATE_UNSPECIFIED",
    acknowledgementState: sub.acknowledgementState || null,
    linkedPurchaseToken: sub.linkedPurchaseToken || null,
    obfuscatedAccountId:
      (sub.externalAccountIdentifiers && sub.externalAccountIdentifiers.obfuscatedExternalAccountId) || null,
    testPurchase: !!sub.testPurchase,
  };
}

/** Server-side check used by quota logic – fail closed on stale/missing expiry. */
function entitlementGrantsPlus(entitlement, nowMillis = Date.now()) {
  if (!entitlement || entitlement.tier !== "PLUS") return false;
  if (!PLUS_GRANTING_STATUSES.includes(entitlement.status)) return false;
  if (entitlement.status === "PLUS_GRACE_PERIOD") return true;
  const expiry = Number(entitlement.expiryTimeMillis);
  return Number.isFinite(expiry) && expiry > nowMillis;
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Fetches the subscription from the Play Developer API.
 * Any error (network, 4xx, 5xx, timeout) is converted into a
 * BillingVerificationError – the caller MUST NOT grant anything.
 */
async function fetchSubscription(playClient, purchaseToken, timeoutMs = PLAY_API_TIMEOUT_MS) {
  try {
    const res = await withTimeout(
      playClient.purchases.subscriptionsv2.get({ packageName: PACKAGE_NAME, token: purchaseToken }),
      timeoutMs,
      "Google Play API"
    );
    if (!res || !res.data) {
      throw new Error("Empty Play API response");
    }
    return res.data;
  } catch (err) {
    const status = err && (err.code || (err.response && err.response.status));
    if (status === 400 || status === 404 || status === 410) {
      throw new BillingVerificationError("invalid-argument", "Nákup nebyl v Google Play nalezen.");
    }
    throw new BillingVerificationError("unavailable", "Ověření nákupu je dočasně nedostupné. Zkuste to prosím později.");
  }
}

async function acknowledgeIfNeeded(playClient, purchaseToken, entitlement, logger = console) {
  if (entitlement.acknowledgementState !== "ACKNOWLEDGEMENT_STATE_PENDING") return false;
  if (!PLUS_GRANTING_STATUSES.includes(entitlement.status)) return false;
  try {
    await withTimeout(
      playClient.purchases.subscriptions.acknowledge({
        packageName: PACKAGE_NAME,
        subscriptionId: PRODUCT_ID,
        token: purchaseToken,
        requestBody: {},
      }),
      PLAY_API_TIMEOUT_MS,
      "Play acknowledge"
    );
    return true;
  } catch (e) {
    // Not fatal for this request: the client re-verifies on next start and
    // we retry the acknowledgement then. Google refunds unacknowledged
    // purchases after 3 days, which RTDN then reports as revoked.
    logger.warn("Purchase acknowledgement failed:", e.message);
    return false;
  }
}

/**
 * Full verification flow. Writes entitlement ONLY after a successful
 * Play API response. Anti-replay: a purchase token is bound to the first
 * UID that verified it (transactionally).
 *
 * @param {object} deps { db, playClient, now, logger }
 */
async function verifyAndGrant(deps, uid, request) {
  const { db, playClient, logger = console } = deps;
  const now = deps.now ? deps.now() : Date.now();
  const { purchaseToken } = validateVerifyRequest(request);
  const tokenHash = hashPurchaseToken(purchaseToken);
  const purchaseRef = db.collection("purchases").doc(tokenHash);

  // Early replay check (cheap) – repeated transactionally below.
  const existing = await purchaseRef.get();
  if (existing.exists && existing.data().userId !== uid) {
    throw new BillingVerificationError("already-exists", "Tento nákup je již přiřazen k jinému účtu.");
  }

  const sub = await fetchSubscription(playClient, purchaseToken, deps.timeoutMs);
  const entitlement = mapSubscriptionToEntitlement(sub, now);

  if (entitlement.obfuscatedAccountId && entitlement.obfuscatedAccountId !== obfuscatedAccountIdForUid(uid)) {
    throw new BillingVerificationError("permission-denied", "Nákup patří jinému účtu.");
  }

  const entitlementRef = db.collection("users").doc(uid).collection("entitlement").doc("current");

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(purchaseRef);
    if (snap.exists && snap.data().userId !== uid) {
      throw new BillingVerificationError("already-exists", "Tento nákup je již přiřazen k jinému účtu.");
    }
    tx.set(
      purchaseRef,
      {
        userId: uid,
        tokenHash,
        productId: entitlement.productId,
        basePlanId: entitlement.basePlanId,
        subscriptionState: entitlement.subscriptionState,
        linkedPurchaseTokenHash: entitlement.linkedPurchaseToken
          ? hashPurchaseToken(entitlement.linkedPurchaseToken)
          : null,
        testPurchase: entitlement.testPurchase,
        verifiedAt: fs().serverTimestamp(),
        createdAt: snap.exists ? snap.data().createdAt || fs().serverTimestamp() : fs().serverTimestamp(),
      },
      { merge: true }
    );
    tx.set(
      entitlementRef,
      {
        tier: entitlement.tier,
        status: entitlement.status,
        productId: entitlement.productId,
        basePlanId: entitlement.basePlanId,
        expiryTimeMillis: entitlement.expiryTimeMillis,
        autoRenewing: entitlement.autoRenewing,
        verifiedAtMillis: now,
        purchaseTokenHash: tokenHash,
        source: "PLAY_DEVELOPER_API",
      },
      { merge: false }
    );
  });

  await acknowledgeIfNeeded(playClient, purchaseToken, entitlement, logger);

  return {
    verified: entitlement.tier === "PLUS",
    status: entitlement.status,
    expiryTime: entitlement.expiryTimeMillis,
  };
}

/**
 * RTDN handler: never trusts the notification type alone. It re-reads the
 * authoritative subscription state from Play. Errors are rethrown so that
 * Pub/Sub retries delivery.
 */
async function handleRtdn(deps, rtdnPayload) {
  const { db, playClient } = deps;
  const now = deps.now ? deps.now() : Date.now();
  const n = rtdnPayload && rtdnPayload.subscriptionNotification;
  if (!n || typeof n.purchaseToken !== "string") return { handled: false, reason: "not_subscription" };
  if (rtdnPayload.packageName && rtdnPayload.packageName !== PACKAGE_NAME) {
    return { handled: false, reason: "foreign_package" };
  }

  const tokenHash = hashPurchaseToken(n.purchaseToken);
  const purchaseSnap = await db.collection("purchases").doc(tokenHash).get();
  if (!purchaseSnap.exists) return { handled: false, reason: "unknown_token" };
  const userId = purchaseSnap.data().userId;
  if (!userId) return { handled: false, reason: "unbound_token" };

  let entitlement;
  try {
    const sub = await fetchSubscription(playClient, n.purchaseToken, deps.timeoutMs);
    entitlement = mapSubscriptionToEntitlement(sub, now);
  } catch (e) {
    if (e.code === "invalid-argument") {
      // Token no longer known to Play -> revoke (fail closed).
      entitlement = { tier: "FREE", status: "EXPIRED", expiryTimeMillis: null, autoRenewing: false, subscriptionState: "UNKNOWN", basePlanId: null };
    } else {
      throw e; // retry later
    }
  }

  await db.collection("users").doc(userId).collection("entitlement").doc("current").set(
    {
      tier: entitlement.tier,
      status: entitlement.status,
      productId: PRODUCT_ID,
      basePlanId: entitlement.basePlanId,
      expiryTimeMillis: entitlement.expiryTimeMillis,
      autoRenewing: entitlement.autoRenewing,
      verifiedAtMillis: now,
      purchaseTokenHash: tokenHash,
      source: "PLAY_RTDN",
      lastNotificationType: n.notificationType || null,
    },
    { merge: false }
  );
  await purchaseSnap.ref.set({ subscriptionState: entitlement.subscriptionState }, { merge: true });
  return { handled: true, userId, status: entitlement.status };
}

module.exports = {
  PLUS_GRANTING_STATUSES,
  BillingVerificationError,
  hashPurchaseToken,
  obfuscatedAccountIdForUid,
  validateVerifyRequest,
  mapSubscriptionToEntitlement,
  entitlementGrantsPlus,
  fetchSubscription,
  verifyAndGrant,
  handleRtdn,
};
