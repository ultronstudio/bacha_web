import "server-only";

import { applicationDefault, cert, getApps, initializeApp } from "firebase-admin/app";
import { getAppCheck } from "firebase-admin/app-check";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { getMessaging } from "firebase-admin/messaging";

function getFirebaseApp() {
  const existing = getApps()[0];
  if (existing) return existing;

  const projectId = process.env.FIREBASE_PROJECT_ID?.trim();
  const clientEmail = process.env.FIREBASE_ADMIN_CLIENT_EMAIL?.trim();
  const privateKey = process.env.FIREBASE_ADMIN_PRIVATE_KEY?.replace(/\\n/g, "\n");
  const emulatorConfigured = !!(process.env.FIRESTORE_EMULATOR_HOST || process.env.FIREBASE_AUTH_EMULATOR_HOST);

  if (process.env.NODE_ENV === "production" && emulatorConfigured) {
    throw new Error("Firebase emulator hosts must not be configured in production.");
  }

  if (projectId && clientEmail && privateKey) {
    return initializeApp({ credential: cert({ projectId, clientEmail, privateKey }), projectId });
  }
  if (process.env.NODE_ENV !== "production" && emulatorConfigured) {
    return initializeApp({ projectId: projectId || "demo-bacha" });
  }
  if (process.env.NODE_ENV !== "production" && process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return initializeApp({ credential: applicationDefault(), projectId });
  }
  throw new Error("Firebase Admin credentials are not configured.");
}

export const firebaseAuth = () => getAuth(getFirebaseApp());
export const firebaseAppCheck = () => getAppCheck(getFirebaseApp());
export const firestore = () => getFirestore(getFirebaseApp());
export const firebaseMessaging = () => getMessaging(getFirebaseApp());
