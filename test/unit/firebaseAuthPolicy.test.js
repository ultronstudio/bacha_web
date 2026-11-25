"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseAllowedEmails, isApprovedGoogleIdentity } = require("../../functions/authPolicy");

const google = (email, emailVerified = true, eventType = "providers/cloud.auth/eventTypes/user.beforeCreate:google.com") => ({
  data: { email, emailVerified },
  eventType
});

test("Firebase: only approved verified Google identity may be created", () => {
  const allowed = "tester@gmail.com, authorized@example.org";
  assert.equal(isApprovedGoogleIdentity(google("tester@gmail.com"), allowed), true);
  assert.equal(isApprovedGoogleIdentity(google("  TESTER@GMAIL.COM "), allowed), true);
  assert.equal(isApprovedGoogleIdentity(google("outsider@gmail.com"), allowed), false);
  assert.equal(isApprovedGoogleIdentity(google("tester@gmail.com", false), allowed), false);
  assert.equal(isApprovedGoogleIdentity(google("tester@gmail.com", true, "providers/cloud.auth/eventTypes/user.beforeCreate:password"), allowed), false);
  assert.equal(isApprovedGoogleIdentity(google("tester@gmail.com", true, "providers/cloud.auth/eventTypes/user.beforeSignIn:google.com"), allowed), true);
});

test("Firebase: empty allowlist never defaults to open access", () => {
  assert.throws(() => isApprovedGoogleIdentity(google("tester@gmail.com"), ""), /empty/);
  assert.throws(() => isApprovedGoogleIdentity(google("tester@gmail.com"), "  ,  "), /empty/);
  assert.equal(parseAllowedEmails(" ONE@EXAMPLE.COM,one@example.com ").size, 1);
  assert.equal(isApprovedGoogleIdentity({ data: { email: null, emailVerified: true }, eventType: "providers/cloud.auth/eventTypes/user.beforeCreate:google.com" }, "tester@gmail.com"), false);
});

test("Firebase: prefix matches, domains, and names cannot bypass exact email check", () => {
  for (const candidate of ["tester@gmail.com.evil.net", "test@gmail.com", "another@gmail.com", "tester+alias@gmail.com"]) {
    assert.equal(isApprovedGoogleIdentity(google(candidate), "tester@gmail.com"), false);
  }
});
