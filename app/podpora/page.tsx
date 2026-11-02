import type { Metadata } from "next";
import Link from "next/link";
export const metadata: Metadata = {
  alternates: { canonical: "/podpora" },
  openGraph: {
    type: "website",
    locale: "cs_CZ",
    siteName: "Bacha!",
    url: "/podpora",
    title: "Podpora – Bacha!",
    description: "Podpora pro aplikaci Bacha!.",
    images: ["/og-image?theme=light"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Podpora – Bacha!",
    description: "Podpora pro aplikaci Bacha!.",
    images: ["/og-image?theme=light"],
  },
  title: "Podpora – Bacha!",
  description: "Podpora pro aplikaci Bacha!.",
};

export default function SupportPage() {
  return (
    <section className="page-main">
      <div className="container">
        <h1 className="mb-4">Podpora Bacha!</h1>
        <div className="content">
          <p className="lead-text">
            Narazili jste na chybu, něco se nechová správně nebo potřebujete
            pomoct s aplikací Bacha!? Napište mi.
          </p>
          <div className="info-box">
            <strong>E-mail podpory:</strong>&nbsp;
            <Link href="mailto:kontakt@petrvurm.cz?subject=Bacha!%20-%20podpora">
              kontakt@petrvurm.cz
            </Link>
          </div>
          <h2>Co je dobré poslat</h2>
          <ul>
            <li>stručný popis problému,</li>
            <li>co jste v aplikaci dělali těsně před chybou,</li>
            <li>model telefonu a verzi Androidu,</li>
            <li>screenshot chyby, pokud je k dispozici.</li>
          </ul>
          <h2>Uzavřené testování</h2>
          <p>
            Pokud se chcete teprve přihlásit do uzavřeného testování, použijte
            formulář na hlavní stránce Bacha!.
          </p>
        </div>
      </div>
    </section>
  );
}
