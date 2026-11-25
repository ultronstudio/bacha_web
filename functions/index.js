"use strict";

const { beforeUserCreated, beforeUserSignedIn, HttpsError } = require("firebase-functions/v2/identity");
const { defineString } = require("firebase-functions/params");
const { isApprovedGoogleIdentity } = require("./authPolicy");

// Firebase CLI requests this parameter during deployment. Never commit email
// addresses or tester lists to the source code.
const approvedEmails = defineString("BETA_APPROVED_GOOGLE_EMAILS");

function checkAllowed(event) {
  let approved = false;
  try {
    approved = isApprovedGoogleIdentity(event, approvedEmails.value());
  } catch (error) {
    // Fail closed if not configured. Only generic messages reach clients.
    console.error("Bacha beta authentication configuration missing");
    throw new HttpsError("internal", "Přihlašování není nakonfigurováno.");
  }
  if (!approved) {
    throw new HttpsError("permission-denied", "Přístup do uzavřeného testování Bacha! není povolen.");
  }
}

// This trigger executes BEFORE a normal Google-account user is created.
// Identity Platform is required; on Spark this function cannot be deployed.
exports.beforeBachaUserCreated = beforeUserCreated({ region: "europe-west1" }, checkAllowed);

// Existing unapproved Google accounts must not be allowed to sign in either.
// Does not revoke already-issued ID tokens: also use the bacha_web UID gate.
exports.beforeBachaUserSignedIn = beforeUserSignedIn({ region: "europe-west1" }, checkAllowed);
