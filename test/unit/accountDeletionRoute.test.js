"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { deleteAccountAfterRateLimit } = require("../../lib/server/bacha/accountDeletionRoute");

describe("account deletion route rate-limit boundary", () => {
  test("does not delete when the limit is exceeded", async () => {
    let deleted = false;
    await assert.rejects(deleteAccountAfterRateLimit({
      enforceRateLimit: async () => { throw Object.assign(new Error("limit"), { name: "RateLimitError" }); },
      deleteUserData: async () => { deleted = true; },
    }));
    assert.equal(deleted, false);
  });

  test("fails closed when the rate limiter has an internal error", async () => {
    let deleted = false;
    await assert.rejects(deleteAccountAfterRateLimit({
      enforceRateLimit: async () => { throw new Error("Firestore unavailable"); },
      deleteUserData: async () => { deleted = true; },
    }), /Firestore unavailable/);
    assert.equal(deleted, false);
  });

  test("deletes after rate limiting succeeds", async () => {
    const calls = [];
    const result = await deleteAccountAfterRateLimit({
      enforceRateLimit: async () => { calls.push("limit"); },
      deleteUserData: async () => { calls.push("delete"); return { authDeleted: true }; },
    });
    assert.deepEqual(calls, ["limit", "delete"]);
    assert.deepEqual(result, { authDeleted: true });
  });
});
