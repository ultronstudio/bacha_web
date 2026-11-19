# Bacha! API contract v1

Base URL: `https://bacha.petrvurm.cz/api/v1/`. JSON requesty i response používají UTF-8.

## Ověření

Nový Android klient používá vlastní backendovou relaci a hlavičky:

```http
Authorization: Bearer <ba_a_access_token>
X-Firebase-AppCheck: <Firebase App Check token>
Content-Type: application/json
```

Google Sign-In běží přes Credential Manager, který předá Google ID token pouze na `POST /auth/google` (bez `Authorization`, stále vyžaduje App Check). Backend ověřuje token podpisem a povinnou audience, issuerem, expirací a `email_verified`, zkontroluje uzavřený seznam testerů a vydá vlastní krátkodobý access + rotující refresh token. **Nový uživatel se nevytváří ve Firebase Authentication.**

Při přechodu stávajících Android verzí zůstává volitelná kompatibilita s Firebase ID tokenem (`BACHA_LEGACY_FIREBASE_AUTH=1`); po rollout nastavit `0`. UID je vždy odvozené serverově z ověřené Google identity, pro existující Google-linked Firebase uživatele se zachovává původní UID. Server i nadále ověřuje App Check pro každý požadavek a nepřijímá UID z klientského payloadu. Admin operace pro nové backendové relace vyžadují explicitní `BACHA_ADMIN_UIDS` v zabezpečeném Vercel prostředí.

| Metoda a cesta | Požadavek | Odpověď |
| --- | --- | --- |
| `POST /auth/google` | `{ idToken }` + App Check | `{ ok, accessToken, refreshToken, accessExpiresAtMillis, refreshExpiresAtMillis, user }` |
| `POST /auth/refresh` | `{ refreshToken }` + App Check | nové rotované tokeny (absolutní expiry relace) |
| `POST /auth/logout` | access token + App Check | `{ ok:true, success:true }`; relace revokována |
| `GET /me` | access token + App Check | `{ ok, user, entitlement, usage }` |

**Pokročilá analýza:** `POST /analyze` navíc vyžaduje přihlášeného uživatele backendu (lokální host -> bez access tokenu, HTTP 401). Limit Free je 5 úspěšných hloubkových kontrol za UTC měsíc, Plus 100. Limit se vyhodnocuje transakčně ve Firestore a neúspěšné provider volání se do kvóty nezapočítává. Lokální analýza Androidu se tím nemění.

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
