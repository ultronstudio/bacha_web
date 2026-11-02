# Bacha! web

Web Bacha! běží na Next.js App Routeru a je připravený pro nasazení na Vercel. Vzhled, vlastní CSS, Bootstrap 5.3.8 a SVG ikony vycházejí z původní PHP verze.

## Lokální spuštění

1. Zkopírujte `.env.example` do `.env.local` a doplňte klíče.
2. Spusťte `npm install`.
3. Spusťte `npm run dev`.

`npm run build` vytvoří produkční build.

## Server API Bacha!

Projekt současně obsluhuje veřejný web a produkční API aplikace na `/api/v1/...`. API běží v Node.js Functions na Vercelu. Serverová logika a její testy jsou v `lib/server/bacha/` a `test/`; Firebase Cloud Functions už nejsou runtime této služby. Přehled endpointů a přesných JSON payloadů je v [API_CONTRACT.md](./API_CONTRACT.md), nasazení v [BACKEND_DEPLOY.md](./BACKEND_DEPLOY.md).

Každé Android API volání vyžaduje Firebase ID token v `Authorization: Bearer ...` a Firebase App Check token v `X-Firebase-AppCheck`. Firebase Admin ověřuje oba tokeny; server vždy používá UID z ověřeného Auth tokenu. Chybějící nebo neplatné ověření je odmítnuto. Serverové proměnné nikdy nepoužívejte s prefixem `NEXT_PUBLIC_`.

Produkční validace backendu: `npm run lint`, `npm test`, `npm run test:rules`, `npm run build`, `npm run check:client-secrets`, `npm run audit:critical`, `npm run audit:high` a `npm run audit:production`.

## Proměnné prostředí

Nastavte stejné proměnné v lokálním prostředí i v projektu Vercel:

| Proměnná | Použití |
| --- | --- |
| `NEXT_PUBLIC_RECAPTCHA_SITE_KEY` | Veřejný site key pro klasickou Google reCAPTCHA checkbox na formuláři. |
| `RECAPTCHA_SECRET_KEY` | Tajný serverový klíč pro ověření tokenu u Google. |
| `RECAPTCHA_EXPECTED_HOSTNAME` | Očekávaný hostname reCAPTCHA, produkčně `bacha.petrvurm.cz`. |
| `RESEND_API_KEY` | Serverový API klíč Resend. |
| `APP_ORIGIN` | Hlavní povolený origin, produkčně `https://bacha.petrvurm.cz`. |
| `ALLOWED_ORIGINS` | Volitelné další přesně povolené originy oddělené čárkou, například Vercel preview URL. |

Pro každý preview deployment přidejte jeho přesný `https://...vercel.app` origin do `ALLOWED_ORIGINS` a hostname daného preview nastavte také v reCAPTCHA konzoli, případně použijte zvláštní preview site key/secret a odpovídající `RECAPTCHA_EXPECTED_HOSTNAME` v Preview env scope Vercelu. Nepovolujte wildcard origin.

## Rate limit

API omezuje odesílání na 5 požadavků za 15 minut na IP. Ukládá HMAC-SHA-256 hash adresy, nikoli otevřenou IP. Současný jednoduchý limiter drží okna v paměti instance, takže je vhodný pro základní ochranu, ale není sdílený mezi serverless instancemi a po jejich restartu se vynuluje. Pro trvalý limit napříč instancemi připojte Redis/KV provider (například Upstash) a nahraďte `requestsByIpHash` atomickou operací v úložišti; potřebné KV proměnné zatím nejsou vyžadované.

## Nasazení

Připojte Git repozitář ve Vercelu, nastavte uvedené proměnné a nasaďte jako standardní Next.js projekt. DNS doména `bacha.petrvurm.cz`, povolené hostname v Google reCAPTCHA a ověřená odesílací doména/adresa `petrvurm.cz` v Resendu se nastavují v příslušných službách.
