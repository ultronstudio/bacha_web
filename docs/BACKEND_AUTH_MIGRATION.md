# Bacha! – migrace na backendem řízené Google přihlášení

## Bezpečnost a kompatibilita

Android už pro nové přihlášení nepoužívá Firebase Authentication. Google Credential Manager vrací **Google ID token**, který klient předá přes TLS na `POST /api/v1/auth/google` společně s `X-Firebase-AppCheck`. Server ověří Google podpis, `aud=GOOGLE_OAUTH_WEB_CLIENT_ID`, `iss` a expiraci přes `google-auth-library`. Po ověření e-mailu a beta allowlistu server vydá vlastní náhodné neprůhledné credentials. **Nový účet se ve Firebase Authentication nezaloží**.

Serverová identita používá ověřené Google `sub`, nikoli e-mail. Při prvním přihlášení vyhledá existujícího Firebase uživatele přes `getUserByProviderUid("google.com", sub)`. Pokud existuje, zachová jeho původní Firebase UID (a s ním Play purchase binding, entitlement, usage, reporty a FCM device records). Nové účty dostanou stabilní neprůhledné UID z HMAC Google subject. Mapování `authIdentities` je soukromá serverová kolekce. Výpadek Firebase Admin lookup **nepovede** k vytvoření duplicitní identity.

Access token platí 20 minut. Refresh token má absolutní platnost 30 dní a rotuje se atomicky při každé obnově (starý refresh i access token jsou okamžitě neplatné). Relace v `authSessions` je svázaná s `appId` ověřeným přes Firebase App Check; v databázi jsou jen SHA-256 hashe tokenů. Logout či smazání účtu relaci serverově zneplatní; staré relace se čistí Firestore TTL. Guest je **pouze lokální režim v Androidu**, nikoliv Firebase Anonymous účet.

### Produkční Vercel proměnné

| Jméno | Hodnota | Význam |
|---|---|---|
| `GOOGLE_OAUTH_WEB_CLIENT_ID` | Skutečné OAuth Web client ID z Credential Manager konfigurace Androidu | Povinná kontrola Google ID token audience |
| `BACHA_AUTH_MODE` | `closed` | Režim uzavřeného testování (výchozí); `open` až při veřejném launchi |
| `BACHA_AUTH_ALLOWED_GOOGLE_EMAILS` | Čárkami oddělené ověřené Google e-maily testerů | Povinné pro closed mode; **nejprve vlastní účet** |
| `BACHA_LEGACY_FIREBASE_AUTH` | `1` během migrace, pak `0` | Dočasná kompatibilita starých APK |

Ponechat existující `FIREBASE_PROJECT_ID`, `FIREBASE_ADMIN_CLIENT_EMAIL`, `FIREBASE_ADMIN_PRIVATE_KEY`, `THREAT_INTEL_HMAC_SECRET` (min. 32 znaků) a ostatní bezpečnostní proměnné. **Neměnit `THREAT_INTEL_HMAC_SECRET`**, pokud už existují nové účty – jejich UID se odvozuje pomocí HMAC.

Vercel přepisuje `X-Forwarded-For` na edge; `auth/google` má sdílený transakční limit 20 pokusů/hodinu/IP, `auth/refresh` 120/hodinu/IP. Bez důvěryhodné IP v produkci login i refresh fail-closed. Kromě toho každá žádost vyžaduje platný App Check token. Privátní kolekce `authIdentities`, `authSessions`, `rateLimits` jsou server-only (žádná klientská pravidla Firestore).

### Endpointy

- `POST /api/v1/auth/google` – body `{ "idToken": "<Google ID token>" }`; hlavička `X-Firebase-AppCheck`; odpověď `{ ok, accessToken, refreshToken, accessExpiresAtMillis, refreshExpiresAtMillis, user }`.
- `POST /api/v1/auth/refresh` – body `{ "refreshToken": "ba_r_..." }`; hlavička `X-Firebase-AppCheck`; odpověď jako výše bez `user`; klient nesmí poslat refresh token na jiné endpointy.
- `POST /api/v1/auth/logout` – `Authorization: Bearer ba_a_...` + App Check; revokuje celou relaci.
- `GET /api/v1/me` – vrací profil, serverové entitlement a aktuální usage; žádné přímé Firestore listenery v Androidu.
- Ostatní `/api/v1` – `Authorization: Bearer ba_a_...` + App Check; po serverové kontrole je UID stejné jako pro starý Play billing a threat data.

### Nasazení bez výpadku

1. Nastavit Vercel Preview proměnné pro **izolovaný Firebase projekt** a testovací Google OAuth audience. Nepropojovat Preview se skutečnými Play nákupy.
2. V Preview otestovat povolené Google přihlášení, odmítnutý neznámý účet (žádný záznam Firebase Auth ani Firestore), serverovou obnovu tokenu, odhlášení, různé `appId`, data `/me`, FCM a Billing.
3. Přidat výše uvedené produkční proměnné **před** nasazením backendu. Poté nasadit backend a ponechat `BACHA_LEGACY_FIREBASE_AUTH=1`.
4. Změny Androidu vydat interním testerům; zachovat vlastním testem UID a Bacha!+ ověření po přihlášení.
5. Teprve po potvrzení migrace nastavit `BACHA_LEGACY_FIREBASE_AUTH=0`, odebrat přímá klientská Firestore Auth rules a případně vypnout Google/Firebase Anonymous providers ve Firebase Authentication. `Enable create (sign-up)` zůstane vypnuté – nový backend jej nepotřebuje.

**Nezapínat Firebase Authentication blocking functions z PR #6**: tato varianta používá backendovou registraci a nepotřebuje placené Identity Platform hooks. IP ochrana backend API může být nasazena nezávisle.

### Původní neznámé účty

Migrace sama o sobě neodstraní dříve vzniklé Firebase Authentication účty. Zachovat UID a časy pro audit, potom je po schválení deaktivovat. Backendem řízený login je nevpustí, pokud nejsou na allowlistu, i když jejich Firebase Auth záznam stále existuje. Firebase SDK může zůstat v APK kvůli App Check, FCM, Analytics, Crashlytics a Remote Config; ne kvůli Authentication.
