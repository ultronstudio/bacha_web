import type { Metadata } from "next";
import Link from "next/link";
export const metadata: Metadata = {
  alternates: { canonical: "/ochrana-soukromi" },
  openGraph: {
    type: "website",
    locale: "cs_CZ",
    siteName: "Bacha!",
    url: "/ochrana-soukromi",
    title: "Ochrana soukromí – Bacha!",
    description: "Informace o ochraně soukromí na webu a v aplikaci Bacha!.",
    images: ["/og-image?theme=light"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Ochrana soukromí – Bacha!",
    description: "Informace o ochraně soukromí na webu a v aplikaci Bacha!.",
    images: ["/og-image?theme=light"],
  },
  title: "Ochrana soukromí – Bacha!",
  description: "Informace o ochraně soukromí na webu a v aplikaci Bacha!.",
};

export default function PrivacyPage() {
  return (
    <section className="page-main">
      <div className="container">
        <h1 className="mb-4">Ochrana soukromí</h1>
        <div className="content">
          <p className="lead-text">
            Tato stránka shrnuje, jak web Bacha! pracuje s údaji návštěvníků a
            jaké údaje mohou být zpracovány při použití formuláře pro zájem o
            uzavřené testování.
          </p>
          <h2>Web Bacha!</h2>
          <p>
            Samotné procházení webu nevyžaduje vytvoření účtu. Web používá
            technické prostředky nezbytné pro svůj provoz, zabezpečení a
            zobrazení.
          </p>
          <h2>Formulář pro uzavřené testování</h2>
          <p>
            Pokud odešlete zájem o uzavřené testování, zpracujeme e-mailovou
            adresu, kterou sami zadáte. Nejprve na ni pošleme potvrzovací odkaz.
            Teprve po potvrzení dostane provozovatel zprávu o zájmu.
            Potvrzení adresy samo o sobě neznamená registraci Google účtu ani přidání do testovacího programu.
          </p>
          <div className="info-box">
            <strong>Účel formuláře:</strong> evidence zájmu o uzavřené testování
            a následný kontakt se zájemcem.
          </div>
          <h2>Ochrana proti spamu</h2>
          <p>
            Formulář používá Google reCAPTCHA. Při jejím použití může Google
            zpracovat technické údaje potřebné k rozpoznání automatizovaného
            nebo zneužívajícího provozu. Server formuláře také používá limit
            požadavků podle IP adresy a e-mailové adresy. Pro rate limit se ukládají
            pouze HMAC hashe identifikátorů, nikoli IP adresa v otevřeném tvaru.
            Limity jsou sdílené přes Firestore napříč instancemi.
            Známé jednorázové e-mailové domény jsou odmítány.
          </p>
          <h2>Ochrana cloudového API</h2>
          <p>
            Cloudové API aplikace Bacha! vyžaduje ověřené přihlášení Firebase
            a ověřovací token App Check. Abychom omezili automatizované
            požadavky a zneužití služby, vedle limitů podle uživatelského UID
            uplatňujeme limity také podle zdrojové IP adresy. Pro jejich
            vyhodnocování uchováváme ve Firestore pouze HMAC otisk IP adresy,
            druh operace, počet požadavků a datum vypršení limitu;
            původní IP adresu do těchto záznamů neukládáme. Záznamy
            automaticky expirují podle nastavení Firestore TTL.
          </p>
          <h2>Odesílání e-mailů</h2>
          <p>
            Služba Resend nejprve doručí potvrzovací odkaz na zadanou adresu.
            Po potvrzení odešle e-mail provozovateli.
            Ověřovací odkaz platí 24 hodin; ověřovací záznam včetně adresy
            může být uchován nejvýše sedm dní po potvrzení a je určen
            k automatickému odstranění zásadou Firestore TTL. K fyzickému
            odstranění může dojít s určitým zpožděním. Token ukládáme pouze
            v podobě hashe.
          </p>
          <h2>Aplikace Bacha!</h2>
          <p>
            Aplikace nečte vaši SMS schránku ani kontakty, nesleduje polohu a
            nesbírá historii prohlížení. Obsah, který sami odešlete k prověření,
            může být zpracován pouze za účelem provedení požadované kontroly.
          </p>
          <h2>Hloubková AI analýza</h2>
          <p>
            Po výslovném spuštění hloubkové kontroly přihlášeným uživatelem
            odešle server zadaný text, odkaz, dekódovaný obsah QR kódu nebo
            vybraný obrázek poskytovateli OpenAI za účelem analýzy možného
            podvodu. Při požadavku používá server parametr store: false,
            který nevytváří uloženou konverzaci pro následné využití API;
            tím však nejsou vyloučeny další doby zpracování a uchování podle
            platných podmínek poskytovatele. Základní lokální kontrola
            může běžet bez přihlášení a bez odeslání obsahu do OpenAI.
          </p>
          <h2>Kontakt</h2>
          <p>
            S dotazy k soukromí můžete napsat na{" "}
            <Link href="mailto:kontakt@petrvurm.cz">kontakt@petrvurm.cz</Link>.
          </p>
        </div>
      </div>
    </section>
  );
}
