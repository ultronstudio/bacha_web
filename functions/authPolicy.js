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

function approveEmailOrThrow(email, approvedEmails) {
  const allow = parseAllowedEmails(approvedEmails);
  // Must never fall back to open registration for a missing configuration.
  if (allow.size === 0) throw new Error("Firebase auth beta allowlist is empty");
  const normalized = typeof email === "string" ? email.trim().toLowerCase() : "";
  return allow.has(normalized);
}

module.exports = { parseAllowedEmails, approveEmailOrThrow };
