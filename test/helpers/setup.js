"use strict";
// Shared test environment: a strong test-only HMAC secret (never used in prod).
process.env.THREAT_INTEL_HMAC_SECRET = "test-only-hmac-secret-0123456789abcdef0123456789";
process.env.GCLOUD_PROJECT = process.env.GCLOUD_PROJECT || "demo-bacha";
const { FakeFirestore, FakeTimestamp, installFakeHelpers } = require("./fakeFirestore");

function freshDb(clock) {
  installFakeHelpers(clock);
  return new FakeFirestore({ clock });
}

const silentLogger = { info() {}, warn() {}, error() {}, log() {} };

module.exports = { freshDb, FakeTimestamp, silentLogger };
