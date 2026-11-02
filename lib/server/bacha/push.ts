import "server-only";

import { firebaseMessaging } from "./firebaseAdmin";

export const SAFE_NOTIFICATION_CATEGORIES = new Set([
  "analysis_completed",
  "account_security",
  "family_request",
]);

export async function sendUserNotification(input: {
  token: string;
  category: string;
  title: string;
  body: string;
  data?: Record<string, string>;
}) {
  if (!SAFE_NOTIFICATION_CATEGORIES.has(input.category)) throw new Error("Unsupported notification category.");
  return firebaseMessaging().send({
    token: input.token,
    notification: { title: input.title, body: input.body },
    data: { ...(input.data || {}), category: input.category },
  });
}
