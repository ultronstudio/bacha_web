# Nasazení Bacha! API na Vercel

## Architektura

Veřejný web i API zůstávají v tomto Next.js App Router projektu. `/api/interest` dál zpracovává webový formulář, reCAPTCHA a Resend. Produkční Android API je `/api/v1/...`; route handlers běží na Node.js. Serverové moduly v `lib/server/bacha/` zachovávají dosavadní Firebase Functions logiku pro Gemini analýzu, threat intelligence, quota, billing, spory, watch listy a smazání účtu.

Firebase zůstává autoritou pro Authentication (včetně anonymous), App Check/Play Integrity, Firestore, FCM, Remote Config, Analytics a Crashlytics. Firebase Admin SDK se inicializuje jako lazy singleton z Vercel secrets. Vercel poskytuje HTTP API a denní cron; Google Pub/Sub push posílá RTDN na HTTP endpoint.

## Vercel environment variables

Nastavte v Project Settings → Environment Variables pro Production a odpovídající Preview/Development scopes. Následující hodnoty nikdy nedávejte do `NEXT_PUBLIC_*` proměnných.

| Proměnná | Požadavek |
| --- | --- |
| `FIREBASE_PROJECT_ID` | Firebase/Google Cloud project ID |
| `FIREBASE_ADMIN_CLIENT_EMAIL` | Service account e-mail používaný Firebase Admin |
| `FIREBASE_ADMIN_PRIVATE_KEY` | Service account private key; zachovat nové řádky nebo escapované `\n` |
| `GEMINI_API_KEY` | Gemini API key pro stávající model `gemini-2.5-flash` |
| `THREAT_INTEL_HMAC_SECRET` | **Přesně stejná hodnota jako v produkčních Cloud Functions. Neměnit** — vytváří existující Firestore lookup keys |
| `WEB_RISK_API_KEY` | Google Web Risk; provider se při prázdné hodnotě přeskočí stejně jako dříve |
| `PHISHTANK_API_KEY` | PhishTank; provider se při prázdné hodnotě přeskočí |
| `URLHAUS_API_KEY` | URLhaus; provider se při prázdné hodnotě přeskočí |
| `PLAY_SERVICE_ACCOUNT_EMAIL` | Service account s Play Developer API přístupem |
| `PLAY_SERVICE_ACCOUNT_PRIVATE_KEY` | Privátní klíč service accountu Play API, jako Vercel secret |
| `PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL` | E-mail identity v OIDC push tokenu |
| `PUBSUB_PUSH_AUDIENCE` | Přesná audience, typicky `https://bacha.petrvurm.cz/api/v1/billing/rtdn` |
| `CRON_SECRET` | Náhodná dlouhá hodnota použitá jako Vercel Cron bearer secret |
| `FIREBASE_EMULATOR_HOST` | Volitelné pouze pro lokální vývoj; nikdy nenastavovat v produkci |

Webové proměnné současného formuláře zůstávají beze změny: `NEXT_PUBLIC_RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`, `RECAPTCHA_EXPECTED_HOSTNAME`, `RESEND_API_KEY`, `APP_ORIGIN`, `ALLOWED_ORIGINS`.

Použijte samostatné, omezené service accounty podle možností projektu. Nedávejte JSON klíče do souborů v repozitáři. Vercel private key secret může obsahovat skutečné nové řádky; pokud se ukládá escapovaný zápis, runtime převádí `\\n` na nový řádek.

## Firebase Admin a App Check

1. V Firebase Console otevřete Project Settings → Service accounts a vyberte service account pro server. Přidejte jeho ID, e-mail a privátní klíč pouze do Vercel environment variables výše.
2. Ujistěte se, že service account může ověřovat Firebase ID tokeny, App Check tokeny, číst a zapisovat stávající Firestore kolekce a odesílat FCM. Admin SDK obchází Firestore rules, proto oprávnění service accountu chraňte.
3. Zapněte Anonymous a Google providers v Firebase Authentication. Klient získá aktuální ID token před každým požadavkem.
4. V Firebase App Check ponechte Play Integrity pro release a pouze registrovaný Debug provider pro debug aplikaci. API každý App Check token ověřuje serverově; žádný production bypass není implementován.
5. Při přepnutí provozu ověřte App Check enforcement a Android package/projekt shodu. Vercel ověřuje tokeny, ale nenahrazuje správné nastavení Play Integrity v konzolích.

## Firestore

Kolekce a dokumenty zůstávají kompatibilní: `users`, uživatelské subkolekce `devices`, `entitlement`, `usage`, a kořenové `threatIndicators`, `indicatorHistory`, `userReports`, `threatDisputes`, `threatWatches`, `purchases`, `rateLimits`. Firestore rules/indexes jsou uloženy v `firestore/`; nasazují se Firebase CLI z tohoto repozitáře:

```sh
npm ci
npm run test:rules
firebase deploy --only firestore:rules,firestore:indexes
```

Rules neudělují klientovi oprávnění k autoritativním datům. Quota, entitlement, purchase binding, hrozby a rate limits zapisuje Admin SDK.

## Gemini a threat providers

Nastavte Gemini secret a používejte původní klíče providerů. `THREAT_INTEL_HMAC_SECRET` migrujte byte-for-byte ze stávajícího Firebase Secret Manageru; při změně se existující HMAC klíče indikátorů již nespárují. Provider timeouty a chování při výpadku zůstávají podle původního backendu.

## Google Play Developer API

1. V Google Cloud projektu povolte Google Play Android Developer API.
2. Vytvořte service account pro ověřování nákupů.
3. V Play Console → Users and permissions pozvěte jeho e-mail a udělte pouze potřebná read-only oprávnění k aplikaci a předplatným/objednávkám (v současném setupu `View app information` a `Manage orders and subscriptions`).
4. Vložte e-mail a klíč do `PLAY_SERVICE_ACCOUNT_EMAIL` a `PLAY_SERVICE_ACCOUNT_PRIVATE_KEY` ve Vercelu.
5. Ověřte interním licenčním testerem. Backend zůstává fail-closed, token sváže s prvním UID transakčně, kontroluje `obfuscatedAccountId` a entitlement uděluje jen po skutečné odpovědi Play API.

## Google Play RTDN přes Pub/Sub push

Endpoint je `https://bacha.petrvurm.cz/api/v1/billing/rtdn`. Ověřuje Google OIDC ID token: podpis, přesnou audience, ověřený e-mail a e-mail push service accountu. Nezpřístupňujte veřejný neautentizovaný subscription.

1. V Google Cloud Console otevřete projekt propojený s Play Console a zapněte Pub/Sub API.
2. Vytvořte topic `play-billing-rtdn`.
3. Topic permissions: přidejte `google-play-developer-notifications@system.gserviceaccount.com` s rolí `Pub/Sub Publisher`.
4. Vytvořte dedikovaný service account pro push OIDC, například `bacha-rtdn-push@PROJECT_ID.iam.gserviceaccount.com`. Uložte e-mail do `PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL`.
5. Vytvořte push subscription na topic `play-billing-rtdn` s endpointem `https://bacha.petrvurm.cz/api/v1/billing/rtdn`, Authentication → OIDC token, service account výše a audience přesně `https://bacha.petrvurm.cz/api/v1/billing/rtdn`. Nastavte stejnou audience do `PUBSUB_PUSH_AUDIENCE`.
6. Zajistěte, aby Pub/Sub service agent projektu (`service-PROJECT_NUMBER@gcp-sa-pubsub.iam.gserviceaccount.com`) měl oprávnění `roles/iam.serviceAccountTokenCreator` na tomto push service accountu, aby mohl vystavovat OIDC tokeny.
7. Nastavte retry policy subscriptionu. Endpoint při přechodném Play API výpadku vrací chybu, aby Pub/Sub opakoval doručení. Duplicitní notifikace jsou bezpečné: stav se znovu čte z Play API.
8. V Play Console → Monetize → Monetization setup → Real-time developer notifications nastavte topic `projects/PROJECT_ID/topics/play-billing-rtdn`, odešlete testovací notifikaci a uložte.
9. Zkontrolujte Vercel Runtime Logs pro validní RTDN push. Nezakládejte jiný endpoint bez OIDC ověření.

## Denní revalidace ve Vercelu

`vercel.json` spouští `/api/internal/cron/revalidate-threat-indicators` denně v 02:17 UTC. Vercel Cron běží v UTC; při původním zimním čase odpovídá 03:17 Europe/Prague a během letního času se místní čas posune o hodinu. V Production nastavte silný `CRON_SECRET`; endpoint ověřuje `Authorization: Bearer <CRON_SECRET>` a bez něj nic nespustí. Cron se neprovádí jako fire-and-forget.

## Nasazení Vercel

1. Připojte `ultronstudio/bacha_web` k existujícímu Vercel projektu a ponechte Next.js framework preset a root directory repository.
2. Přidejte všechny produkční proměnné. Nejdřív zkontrolujte HMAC hodnotu proti běžícímu backendu.
3. Vytvořte Preview secrets pro testovací Firebase/Play prostředí. Nepoužívejte production Play klíče pro nechráněné Preview URL.
4. Spusťte CI a nasaďte preview deployment. Otestujte landing page, `/api/interest` s platným reCAPTCHA formulářem, Firebase auth/App Check, analýzu, threat lookup a zařízení.
5. Nastavte produkční doménu `bacha.petrvurm.cz` a nasaďte Production. Potom aktivujte Play Pub/Sub push subscription.
6. Před vypnutím původních Cloud Functions dokončete Android release migraci a ověřte produkční volání z Play Integrity buildu.

Analýza může běžet do 120 sekund. Route používá Vercel Node.js Function `maxDuration: 120`; nejde o úlohu na pozadí. Vercel request body limit je menší než 4,5 MB a aplikace navíc odmítá body nad 3,5 MB; obrázkové limity zůstávají z původního backendu.

## Lokální vývoj a bezpečné testování

1. `Copy-Item .env.example .env.local` a použijte oddělený Firebase test projekt a oddělené Play test credentials. Pro lokální Auth/Firestore emulator nastavte `FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099` a `FIRESTORE_EMULATOR_HOST=127.0.0.1:8080`; v Production jsou emulator hosty odmítnuty.
2. Pro volání chráněného endpointu potřebujete platný Firebase Auth ID token a App Check token projektu; produkční bypass neexistuje. Debug App Check token musí být registrován ve Firebase Console.
3. Spusťte `npm ci`, `npm run lint`, `npm test`, `npm run test:rules`, `npm run build`, `npm run check:client-secrets`, `npm run audit:critical`, `npm run audit:high` a `npm run audit:production`.
4. Unit testy používají fake Firestore a mockované API odpovědi. Nevyžadují placené Gemini, Web Risk, PhishTank, URLhaus ani Google Play API keys.
5. Rules testy používají lokální Firestore Emulator. K ověření HTTP/OIDC integrace vytvořte Preview deployment a Pub/Sub testovací topic; neposílejte testovací purchase tokeny na produkční účet.

Webový formulář `/api/interest` si ponechává vlastní základní IP limiter v paměti, reCAPTCHA a Resend workflow. Není používán pro security API. Serverové API používá původní Firestore transakční `rateLimits` kolekci.
