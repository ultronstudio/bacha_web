"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { validateDeviceId, validateDevicePayload } = require("../../lib/server/bacha/deviceValidation");

const valid = {
  fcmToken: "fcm-token-value-123456789",
  appVersion: "1.2.3",
  deviceModel: "Example Phone",
  osVersion: "16",
  notificationsEnabled: true,
  permissionGranted: true,
};

describe("device registration validation", () => {
  test("accepts bounded device identifiers and registration data", () => {
    assert.equal(validateDeviceId("installation_id-1"), "installation_id-1");
    assert.deepEqual(validateDevicePayload(valid, "PUT"), valid);
  });
  test("rejects malformed identifiers, missing fields, oversized fields, and untrusted attributes", () => {
    assert.throws(() => validateDeviceId("../other-user"));
    assert.throws(() => validateDevicePayload({ ...valid, osVersion: undefined }, "PUT"));
    assert.throws(() => validateDevicePayload({ ...valid, fcmToken: "bad token" }, "PUT"));
    assert.throws(() => validateDevicePayload({ ...valid, appVersion: "v".repeat(65) }, "PUT"));
    assert.throws(() => validateDevicePayload({ ...valid, uid: "attacker" }, "PUT"));
  });
  test("allows partial preference updates but validates booleans", () => {
    assert.deepEqual(validateDevicePayload({ notificationsEnabled: false, permissionGranted: true }, "PATCH"), {
      notificationsEnabled: false, permissionGranted: true,
    });
    assert.throws(() => validateDevicePayload({ notificationsEnabled: "yes" }, "PATCH"));
  });
});
