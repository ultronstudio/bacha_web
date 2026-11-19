"use strict";

/** Strict closed-beta policy. Unknown identities must be rejected before
 * Firebase creates or signs in the user.
 * Does not apply to anonymous/custom auth: disable Anonymous in Firebase
 * Sign-in method while a closed beta needs a zero-signup guarantee.
 */
function parseAllowedEmails(csv) {
  return new Set(
    String(csv || "")
      .split(",")
      .map((email) => email.trim().toLowerCase())
      .filter((email) => email.includes("@") && !/\s/.test(email))
  );
}

function isApprovedGoogleIdentity(event, approvedEmails) {
  const allow = parseAllowedEmails(approvedEmails);
  // Must never fall back to open registration for a missing configuration.
  if (allow.size === 0) throw new Error("Firebase auth beta allowlist is empty");
  const email = event?.data?.email;
  const normalized = typeof email === "string" ? email.trim().toLowerCase() : "";
  // Only a verified Google identity can claim an allowlisted email address.
  // Prevent email/password sign-up with the same address from impersonating a tester.
  const provider = typeof event?.eventType === "string" ? event.eventType.split(":").pop() : "";
  if (provider !== "google.com" || event?.data?.emailVerified !== true) return false;
  return allow.has(normalized);
}

module.exports = { parseAllowedEmails, isApprovedGoogleIdentity };
