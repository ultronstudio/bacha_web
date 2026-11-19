# Bacha! – uzavřené testování a ochrana Firebase Authentication

## Podstatné: ochrana webového API nestačí

Firebase Android SDK posílá Google přihlášení přímo do Firebase Authentication. Omezení na `bacha_web` tedy **nemůže zastavit vytváření nových Firebase Auth účtů**. Pro aktuální incident ponechte ve Firebase Authentication → Settings → User actions **Enable create (sign-up) = OFF**. Dokud je to vypnuté, nemohou se klientsky vytvářet ani legitimní nové účty (včetně Anonymous). Stávající účty zůstávají.

### A. App Check pro Authentication (Firebase Console)

1. Firebase → App Check → APIs → Authentication: aktuálně `Monitoring`. Záznamy s **invalid App Check token** mohou indikovat neautorizované klienty. Neprokazují ale identitu ani původ osmi neznámých účtů.
2. Ověřte na vlastním telefonu se *skutečnou Play-installed verzí*, že tok Google Sign-In při obnovení relace přichází jako `Verified`. Rozdíl vůči přímému získání integrity tokenu je důležitý: API potřebuje platný **App Check** token.
3. Po úspěšném testu přepněte u **Authentication** na **Enforce**. Vynucování odmítá neplatné a chybějící App Check tokeny. Při aktivaci mohou starší/nepodporovaní klienti přestat fungovat. Neřeší to osoby, které mají platnou kopii aplikace nebo získají token.

### B. Přísný whitelist při vytváření i přihlášení uživatelů – volitelná Cloud Function

Ve složce `functions/` jsou dvě server-side Firebase Authentication *blocking functions*:
- `beforeBachaUserCreated` odmítne neschválenou Google adresu **před uložením nového Firebase Auth účtu**.
- `beforeBachaUserSignedIn` odmítne opětovné přihlášení existujícího neschváleného Google účtu.

Policy je fail-closed: pouze **přesná e-mailová adresa**, která je v `BETA_APPROVED_GOOGLE_EMAILS`, a současně **ověřená Google identita**. Žádný wildcard, shoda domény nebo vlastní tvrzení klienta nestačí. Přidejte svou skutečnou Google adresu a až potom účty konkrétních schválených testerů. Nenastavený parametr zablokuje i provozovatele!

**Požadavky:** Firebase Authentication **with Identity Platform** (upgrade v Firebase Console) a tarif **Blaze** pro Cloud Functions. Na aktuálním Spark plánu tyto dvě funkce **nelze nasadit**. Změna tarifu není automatická součást PR a může mít finanční důsledky. Před nasazením nastavte rozpočtové alerty, zkontrolujte cenové podmínky a otestujte všechna přihlášení v izolovaném projektu.

Lokální příprava (pouze po rozhodnutí pro Identity Platform + Blaze):

```powershell
cd functions
npm install
npm test
cd ..
npx firebase login
npx firebase deploy --only functions:auth-guards --project bacha-security-prod
```

Při deployi se Firebase CLI zeptá na parametr `BETA_APPROVED_GOOGLE_EMAILS`. Vyplňte čárkami oddělený seznam **schválených skutečných Google e-mailů**. Nedávejte tento seznam do veřejného GitHubu. Otestujte s autorizovaným a neautorizovaným **testovacím** Google účtem. Teprve potom zvažte obnovení `Enable create (sign-up)`.

**Výjimka:** blocking functions se **nespouštějí pro Anonymous ani custom authentication**. Pro skutečně uzavřenou betu s blokací všech neznámých registrací musíte mít také vypnutý provider **Anonymous** (Authentication → Sign-in method), nebo nechat vytváření účtů globálně vypnuté. Pokud vypnete Anonymous, stávající aplikace se bude při spuštění i nadále pokoušet o anonymní login a selže; Google Sign-In existujících uživatelů a offline základní funkce musí být zvlášť otestovány. Budoucí veřejná verze může Anonymous znovu používat, ale nejde současně povolit libovolné anonymní účty a absolutně zabránit jejich vytváření.

**Stávajících osm neznámých Google účtů** funkce zpětně nevymaže ani neodvolá vydané ID tokeny. Před deaktivací zapište UID a čas přihlášení pro audit. Poté neznámým účtům zakažte přístup v Firebase Authentication (Disable user), případně revoke refresh tokens; nevytvářejte doklady identity pouze z podobnosti názvů e-mailů.

### C. Ochrana bacha_web (volitelná, nezávislá)

V `lib/server/bacha/apiAccessGuard.js` je připravena druhá vrstva:

| Vercel environment proměnná | Příklad | Význam |
|---|---|---|
| `BETA_ACCESS_MODE` | `closed` | Zapne povinný UID whitelist API. Výchozí `open` je beze změny. |
| `BETA_ALLOWED_UIDS` | `uid-provozovatele,uid-testera` | Přesný seznam povolených UID (minimálně vlastní účet!). |
| `API_IP_RATE_LIMIT_ENABLED` | `1` | Zapne transakční IP limit Vercel API. |
| `API_IP_RATE_LIMIT_PER_15M` | `100` | Počet požadavků / 15 minut / IP. Platí pro celé API včetně čtení; limit 100 může být nízký při velkém provozu. |

Tato vrstva běží **až po ověření Firebase ID + App Check**; k omezení neověřených požadavků použijte i Vercel Firewall na vstupu. IP bere pouze z platformou přepsané `X-Forwarded-For` (Vercel), nikdy z nedůvěryhodného vlastní proxy. Limity jsou sdílené mezi serverless instancemi přes Firestore transakce, identifikátor IP je pouze HMAC a TTL existuje v `rateLimits.expiresAt`. Tím však **nevzniká whitelist Firebase Authentication**.

**Pozor:** whitelist API podle UID není propojený s allowlistem e-mailů ve Firebase funkcích. Kdo smí do Auth, nemusí automaticky smět do API. Aktualizujte oba seznamy řízeně.

### D. Bezpečnostní kontrola

- Po aktivaci neprovádějte nové testy se skutečnými cizími Google účty a žádné rušení jejich relací bez zajištění záznamů.
- Neotevírejte Firestore rules `allow read, write: if true`, nezakazujte Firebase ID token validaci a neukládejte admin service account klíče do Android APK.
- Používejte `npm test` v kořenu repozitáře pro policy a IP-rate testy; `cd functions; npm test` pro Firebase policy. Testy jsou offline a nezasahují do projektu.
- Na Firebase Spark je pro teď nejspolehlivější nouzová kombinace: **sign-ups vypnuté** + ověřená a vynucená App Check pro Authentication. Pro flexibilní seznam nových schválených Google testerů při zapnutých sign-upech je potřeba **Identity Platform blocking function**.
