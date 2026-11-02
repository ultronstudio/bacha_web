"use strict";

const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const STRING_LIMITS = { fcmToken: 4096, appVersion: 64, deviceModel: 128, osVersion: 32 };
const ALLOWED_FIELDS = new Set([...Object.keys(STRING_LIMITS), "notificationsEnabled", "permissionGranted"]);

class DeviceValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

function validateDeviceId(deviceId) {
  if (typeof deviceId !== "string" || !DEVICE_ID.test(deviceId)) throw new DeviceValidationError("Neplatné ID zařízení.");
  return deviceId;
}

function validateDevicePayload(value, method) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DeviceValidationError("Neplatné údaje zařízení.");
  const data = value;
  if (Object.keys(data).some((key) => !ALLOWED_FIELDS.has(key))) throw new DeviceValidationError("Neplatné pole zařízení.");
  for (const [key, max] of Object.entries(STRING_LIMITS)) {
    if (data[key] === undefined) continue;
    if (typeof data[key] !== "string" || data[key].length > max) throw new DeviceValidationError(`Neplatná hodnota ${key}.`);
    if ((key === "fcmToken" || method === "PUT") && !data[key].trim()) throw new DeviceValidationError(`Neplatná hodnota ${key}.`);
    if (key === "fcmToken" && /\s/.test(data[key])) throw new DeviceValidationError("Neplatný FCM token.");
  }
  for (const key of ["notificationsEnabled", "permissionGranted"]) {
    if (data[key] !== undefined && typeof data[key] !== "boolean") throw new DeviceValidationError(`Neplatná hodnota ${key}.`);
  }
  if (method === "PUT" && (
    typeof data.fcmToken !== "string" || typeof data.appVersion !== "string" ||
    typeof data.deviceModel !== "string" || typeof data.osVersion !== "string" ||
    typeof data.notificationsEnabled !== "boolean" || typeof data.permissionGranted !== "boolean"
  )) throw new DeviceValidationError("Registrace zařízení není úplná.");
  if (method !== "PUT" && method !== "PATCH") throw new DeviceValidationError("Nepodporovaná metoda zařízení.");
  return { ...data };
}

module.exports = { validateDeviceId, validateDevicePayload, DeviceValidationError };
