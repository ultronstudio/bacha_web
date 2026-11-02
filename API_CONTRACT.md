# Bacha! API contract v1

Base URL: `https://bacha.petrvurm.cz/api/v1/`. JSON requesty i response používají UTF-8.

## Ověření

Všechny endpointy pod `/api/v1`, kromě RTDN receiveru, vyžadují:

```http
Authorization: Bearer <Firebase ID token>
X-Firebase-AppCheck: <Firebase App Check token>
Content-Type: application/json
```

Server ověřuje ID token přes Firebase Admin `verifyIdToken(token, true)` a App Check token přes Firebase Admin `verifyToken`. UID pochází výhradně z ověřeného ID tokenu. Těla požadavků nikdy nepřenášejí autoritativní UID. Admin operace vyžadují claim `admin: true`.

Úspěch vrací `{ "ok": true, ...data }`. Chyba vrací `{ "ok": false, "error": { "code": "...", "message": "..." } }`. Citlivé odpovědi mají `Cache-Control: no-store, max-age=0`.

| Metoda a cesta | Požadavek | Odpověď |
| --- | --- | --- |
| `POST /analyze` | `{ text, analysisType, imageBase64? }` | Původní `AnalysisResult` plus `quotaExhausted`, `quotaCharged`, `deepAnalysesUsed`, `monthlyLimit`, `threatReputation` |
| `POST /threats/lookup` | `{ indicators: [{ type, value }] }` | `{ results: [ThreatReputationResult] }` |
| `POST /threats/report` | `{ rawValue, indicatorType, category, financialHarm, note? }` | původní report success data |
| `POST /threats/dispute` | `{ lookupKey, indicatorType, reason }` | původní dispute success data |
| `PUT /threats/watch` | `{ lookupKey, enabled }` | `{ success, enabled }` |
| `GET /threats/watches` | bez těla | `{ watches: [{ lookupKey, maskedDisplay }] }` |
| `POST /billing/verify` | `{ purchaseToken, productId }` | `{ verified, status, expiryTime }`; `expiryTime` je Unix čas v milisekundách nebo `null` |
| `DELETE /account` | bez těla | `{ success: true, authDeleted }` |
| `POST /admin/threats/moderate` | `{ lookupKey, verdict, category?, reason }` | původní moderation success data |
| `POST /admin/disputes/resolve` | `{ disputeId, resolution, newVerdict?, note? }` | původní dispute resolution data |
| `PUT /devices/{deviceId}` | `{ fcmToken, appVersion, deviceModel, osVersion, notificationsEnabled, permissionGranted }` | `{ success: true, deviceId }` |
| `PATCH /devices/{deviceId}` | část device polí; pro preference pošlete `notificationsEnabled` a `permissionGranted` | `{ success: true, deviceId }` |
| `DELETE /devices/{deviceId}` | bez těla | `{ success: true }` |

`analysisType`: `TEXT_OR_URL`, `SCREENSHOT`, `QR_CODE`, `PHONE_NUMBER`. Threat `type`: `URL`, `DOMAIN`, `PHONE`, `EMAIL`. Limity, normalizace, response enumy, reputační trust model, billing a quota jsou beze změny podle původního Functions backendu.

## RTDN a cron

`POST /api/v1/billing/rtdn` přijímá standardní Pub/Sub push JSON envelope. Je ověřen Google OIDC bearer tokenem, očekávaným audience a nakonfigurovaným service-account e-mailem. `message.data` obsahuje base64 JSON Play RTDN; samotnému `notificationType` se nedůvěřuje a subscription stav se vždy znovu čte přes Play Developer API.

`GET|POST /api/internal/cron/revalidate-threat-indicators` je chráněný `Authorization: Bearer $CRON_SECRET`.

## HTTP chyby

`unauthenticated` → 401; `permission-denied` → 403; `invalid-argument` → 400; `resource-exhausted` → 429; `already-exists` → 409; `failed-precondition` → 412; `unavailable` → 503; interní chyba → 500. Purchase anti-replay používá `already-exists`. RTDN používá OIDC identity autorizovaného Pub/Sub service accountu místo Firebase Auth/App Check.
