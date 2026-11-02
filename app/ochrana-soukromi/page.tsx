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
            adresu, kterou sami zadáte. Tato adresa slouží pouze k tomu, abychom
            vás mohli kontaktovat ohledně testování aplikace Bacha!.
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
            požadavků podle IP adresy. Pro rate limit se ukládá pouze HMAC hash
            IP adresy, nikoli IP adresa v otevřeném tvaru. Na Vercelu je
            aktuálně limit sdílený jen v rámci jedné instance; pro trvalou
            ochranu napříč instancemi je potřeba externí KV úložiště.
          </p>
          <h2>Odesílání e-mailů</h2>
          <p>
            Notifikaci o zájmu o testování odesílá služba Resend. Zadaný e-mail
            je součástí této notifikace a je doručen na kontaktní adresu
            provozovatele.
          </p>
          <h2>Aplikace Bacha!</h2>
          <p>
            Aplikace nečte vaši SMS schránku ani kontakty, nesleduje polohu a
            nesbírá historii prohlížení. Obsah, který sami odešlete k prověření,
            může být zpracován pouze za účelem provedení požadované kontroly.
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
