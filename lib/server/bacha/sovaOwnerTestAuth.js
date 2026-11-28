"use strict";

const { ApiError } = require("./authCore");

/**
 * Separate, dedicated authorization for the SOVA OTA "owner-test" channel - deliberately NOT the
 * same allowlist as general moderator/admin access (BACHA_ADMIN_UIDS): compromising one must not
 * automatically grant the other. Add the owner's own uid to BOTH env vars if they want both.
 */
function isOwnerTestChannelUid(uid, env = process.env) {
  return (env.BACHA_SOVA_OWNER_TEST_UIDS || "").split(",").map((x) => x.trim()).filter(Boolean).includes(uid);
}

/** Throws 403 unless the caller is explicitly allowlisted for the owner-test channel. Call this
 * BEFORE resolveSovaCatalogEntry whenever channel === "owner-test"; never gate "stable". */
function requireOwnerTestChannelAccess(identity, env = process.env) {
  if (!isOwnerTestChannelUid(identity && identity.uid, env)) {
    throw new ApiError(403, "permission-denied", "Kanál owner-test není pro tento účet povolen.");
  }
}

module.exports = { isOwnerTestChannelUid, requireOwnerTestChannelAccess };
