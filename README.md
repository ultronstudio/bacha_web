# Bacha! web

Web Bacha! běží na Next.js App Routeru a je připravený pro nasazení na Vercel. Vzhled, vlastní CSS, Bootstrap 5.3.8 a SVG ikony vycházejí z původní PHP verze.

## Lokální spuštění

1. Zkopírujte `.env.example` do `.env.local` a doplňte klíče.
2. Spusťte `npm install`.
3. Spusťte `npm run dev`.

`npm run build` vytvoří produkční build.

## Server API Bacha!

Projekt současně obsluhuje veřejný web a produkční API aplikace na `/api/v1/...`. API běží v Node.js Functions na Vercelu. Serverová logika a její testy jsou v `lib/server/bacha/` a `test/`; Firebase Cloud Functions už nejsou runtime této služby. Přehled endpointů a přesných JSON payloadů je v [API_CONTRACT.md](./API_CONTRACT.md), nasazení v [BACKEND_DEPLOY.md](./BACKEND_DEPLOY.md).

Nový Android klient se přihlašuje Google Credential Managerem na `POST /api/v1/auth/google`. Backend ověří Google ID token a Firebase App Check, potom vrátí **vlastní backendem spravovanou relaci** – žádný nový účet v Firebase Authentication. Následná API volání posílají `Authorization: Bearer ba_a_...` a `X-Firebase-AppCheck`; obnovování probíhá pomocí jednorázového rotujícího refresh tokenu. UID se odvozuje ze serverově ověřeného Google subjectu nebo zachová existující Firebase UID kvůli Google Play předplatnému. Pro staré Play buildy lze dočasně ponechat legacy Firebase ID tokeny. Lokální host nevytváří cloudový účet. Hloubková analýza = Free 5, Plus 100 úspěšných kontrol/UTC měsíc, transakční serverová kvóta. Podrobnosti [docs/BACKEND_AUTH_MIGRATION.md](./docs/BACKEND_AUTH_MIGRATION.md).

OpenAI multimodální analýza používá Responses API, striktní JSON schema, `store: false`, text a obrázky (JPEG/PNG/WebP). Přenesený obsah může zpracovat OpenAI; viz zásady soukromí. `OPENAI_API_KEY` nastavujte pouze na serveru ve Vercelu; před vydáním ověřte OpenAI účtování i náklady.

Offline API smoke test: `npm run test:smoke` simuluje celý požadavek na hloubkovou analýzu v paměti (ověření Firebase Auth + App Check, anonymní/Free/Plus, Firestore kvóty, validace, OpenAI Responses API pomocí HTTP mocku a vrácení kvóty při chybě). Nevolá žádnou externí službu, nepoužívá Vercel secrets ani reálný OpenAI kredit. Samostatný GitHub Actions workflow **Offline AI Smoke** lze spustit ručně z Actions → Run workflow, spouští se také při PR změnách analyzačního backendu.

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
| `INTEREST_BLOCKED_EMAIL_DOMAINS` | Volitelný čárkami oddělený doplněk blokovaných dočasných e-mailových domén. Vestavěný seznam už obsahuje `anonmart.com`. |

Pro každý preview deployment přidejte jeho přesný `https://...vercel.app` origin do `ALLOWED_ORIGINS` a hostname daného preview nastavte také v reCAPTCHA konzoli, případně použijte zvláštní preview site key/secret a odpovídající `RECAPTCHA_EXPECTED_HOSTNAME` v Preview env scope Vercelu. Nepovolujte wildcard origin.

## Ověřování zájmu o uzavřené testování

Formulář `POST /api/interest` nejprve ověřuje origin, honeypot, formát e-mailu, blokované dočasné domény a reCAPTCHA. Poté uloží do Firestore `testingInterestVerifications` pouze SHA-256 hash náhodného 32bytového ověřovacího tokenu, adresu a expiraci. **Oznámení provozovateli se neposílá, dokud zájemce adresu nepotvrdí.** Resend nejprve odešle potvrzovací e-mail. Odkaz je platný 24 hodin. GET `/api/interest/confirm?token=...` jej pouze zobrazí; až kliknutí na potvrzovací tlačítko (POST) transakčně rezervuje a pošle upozornění na `kontakt@petrvurm.cz`.

Jedna přihláška může provozovateli vytvořit nejvýše jedno oznámení v běžném průchodu; souběžné požadavky chrání Firestore transakce, retry po chybě zajišťuje Resend `Idempotency-Key`. Při dočasném selhání Resendu lze potvrzení opakovat. Záznam po potvrzení zůstává nejvýše 7 dní do vypršení TTL (fyzické smazání je asynchronní). V `firestore/firestore.indexes.json` je pro `testingInterestVerifications.expiresAt` deklarované TTL; **před nasazením znovu deployujte Firestore indexes**.

Proti zneužití odesílání běží distribuované Firestore limity: 5 žádostí / 15 minut / IP a 3 žádosti / 24 hodin / e-mail, s HMAC identifikátory v existující kolekci `rateLimits`, jejíž `expiresAt` už má TTL. Domény se ověřují na serveru; vestavěný blokovací seznam je záměrně konzervativní, nikoli úplný a lze jej doplnit `INTEREST_BLOCKED_EMAIL_DOMAINS`. Potvrzení adresy **neprokazuje**, že je použita jako Google účet; přidání do interního Google Play testování zůstává ruční.

Testy: `npm test` zahrnují `test/unit/interestVerification.test.js` (blokované domény, tokeny, omezení, expirace, souběžné stavy a retry). Integraci s Resendem, reálným Firestore a reCAPTCHA je nutné ověřit přes preview nasazení bez skutečných uživatelů.

## Nasazení

Připojte Git repozitář ve Vercelu, nastavte uvedené proměnné a nasaďte jako standardní Next.js projekt. DNS doména `bacha.petrvurm.cz`, povolené hostname v Google reCAPTCHA a ověřená odesílací doména/adresa `petrvurm.cz` v Resendu se nastavují v příslušných službách.
