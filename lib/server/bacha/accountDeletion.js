"use strict";

/**
 * Server-side account deletion (spec P0.6).
 *
 * Inventory of UID-linked cloud data:
 *   users/{uid}                      profile (displayName, email, accountKind)
 *   users/{uid}/devices/*            FCM tokens, device model, OS, app version
 *   users/{uid}/usage/*              monthly deep-analysis counters
 *   users/{uid}/entitlement/*        subscription entitlement
 *   purchases/* (userId == uid)      purchase-token -> uid binding
 *   threatWatches/* (uid == uid)     watched indicators
 *   userReports/* (uid == uid)       link between user and community reports
 *   threatDisputes/* (submittedByUid)  pending -> deleted, resolved -> anonymised
 *   rateLimits/* (uid == uid)        abuse-protection counters
 *   Firebase Auth user
 *
 * Aggregated, non-identifying threat indicator counters are kept (they no
 * longer reference the user once the userReports link is gone).
 * Any failure throws – the caller must NOT report success.
 */

const PAGE_SIZE = 200;

async function deleteQueryInPages(db, query) {
  let deleted = 0;
  while (true) {
    const snap = await query.limit(PAGE_SIZE).get();
    if (snap.empty) break;
    const batch = db.batch();
    for (const doc of snap.docs) batch.delete(doc.ref);
    await batch.commit();
    deleted += snap.size;
    if (snap.size < PAGE_SIZE) break;
  }
  return deleted;
}

async function anonymiseDisputes(db, uid) {
  let pendingDeleted = 0;
  let anonymised = 0;
  while (true) {
    const snap = await db.collection("threatDisputes").where("submittedByUid", "==", uid).limit(PAGE_SIZE).get();
    if (snap.empty) break;
    const batch = db.batch();
    for (const doc of snap.docs) {
      if (doc.data().status === "PENDING") {
        batch.delete(doc.ref);
        pendingDeleted++;
      } else {
        batch.update(doc.ref, { submittedByUid: null, reason: "[smazáno na žádost uživatele]", anonymised: true });
        anonymised++;
      }
    }
    await batch.commit();
    if (snap.size < PAGE_SIZE) break;
  }
  return { pendingDeleted, anonymised };
}

/**
 * @param {object} deps { db, auth } – auth is firebase-admin Auth (or fake)
 */
async function deleteAllUserData(deps, uid) {
  const { db, auth } = deps;
  if (!uid || typeof uid !== "string") throw new Error("Missing uid");
  const report = {};
  const userRef = db.collection("users").doc(uid);

  for (const sub of ["devices", "usage", "entitlement"]) {
    report[sub] = await deleteQueryInPages(db, userRef.collection(sub));
  }
  report.purchases = await deleteQueryInPages(db, db.collection("purchases").where("userId", "==", uid));
  report.threatWatches = await deleteQueryInPages(db, db.collection("threatWatches").where("uid", "==", uid));
  report.userReports = await deleteQueryInPages(db, db.collection("userReports").where("uid", "==", uid));
  report.rateLimits = await deleteQueryInPages(db, db.collection("rateLimits").where("uid", "==", uid));
  report.disputes = await anonymiseDisputes(db, uid);
  await userRef.delete();
  report.userProfile = 1;

  // Delete the Auth user server-side so the client does not need a recent login.
  let authDeleted = false;
  if (auth) {
    try {
      await auth.deleteUser(uid);
      authDeleted = true;
    } catch (e) {
      if (e && e.code === "auth/user-not-found") {
        authDeleted = true;
      } else {
        throw e;
      }
    }
  }
  return { success: true, authDeleted, report };
}

module.exports = { deleteAllUserData };
