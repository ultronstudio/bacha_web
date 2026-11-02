"use strict";

/** Security limit failures must prevent account deletion from proceeding. */
async function deleteAccountAfterRateLimit({ enforceRateLimit, deleteUserData }) {
  await enforceRateLimit();
  return deleteUserData();
}

module.exports = { deleteAccountAfterRateLimit };
