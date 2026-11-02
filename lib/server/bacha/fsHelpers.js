"use strict";

/**
 * Thin indirection over Firestore sentinels/timestamps so that business
 * logic can be unit tested with an in-memory Firestore fake.
 */
let impl = null;

function defaultImpl() {
  const admin = require("firebase-admin");
  return {
    serverTimestamp: () => admin.firestore.FieldValue.serverTimestamp(),
    increment: (n) => admin.firestore.FieldValue.increment(n),
    now: () => admin.firestore.Timestamp.now(),
    fromMillis: (ms) => admin.firestore.Timestamp.fromMillis(ms),
  };
}

function fs() {
  if (!impl) impl = defaultImpl();
  return impl;
}

/** Test hook. Pass null to restore the firebase-admin implementation. */
function overrideFirestoreHelpers(custom) {
  impl = custom;
}

module.exports = { fs, overrideFirestoreHelpers };
