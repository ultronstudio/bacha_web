import type { Metadata } from "next";
import Link from "next/link";
export const metadata: Metadata = {
  alternates: { canonical: "/smazat-ucet" },
  openGraph: {
    type: "website",
    locale: "cs_CZ",
    siteName: "Bacha!",
    url: "/smazat-ucet",
    title: "Smazání účtu – Bacha!",
    description: "Informace k odstranění účtu a dat aplikace Bacha!.",
    images: ["/og-image?theme=light"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Smazání účtu – Bacha!",
    description: "Informace k odstranění účtu a dat aplikace Bacha!.",
    images: ["/og-image?theme=light"],
  },
  title: "Smazání účtu – Bacha!",
  description: "Informace k odstranění účtu a dat aplikace Bacha!.",
};

export default function DeleteAccountPage() {
  return (
    <section className="page-main">
      <div className="container">
        <h1 className="mb-4">Smazání účtu a dat</h1>
        <div className="content">
          <p className="lead-text">
            Pokud chcete požádat o odstranění účtu Bacha! nebo údajů spojených s
            vaším účtem, můžete žádost poslat e-mailem.
          </p>
          <div className="info-box">
            <strong>Žádost pošlete na:</strong>
            <br />
            <Link href="mailto:kontakt@petrvurm.cz?subject=Bacha!%20-%20smaz%C3%A1n%C3%AD%20%C3%BA%C4%8Dtu">
              kontakt@petrvurm.cz
            </Link>
          </div>
          <h2>Co do žádosti uvést</h2>
          <p>
            Použijte pokud možno stejnou e-mailovou adresu, kterou používáte v
            aplikaci Bacha!. Do předmětu můžete uvést „Bacha! – smazání účtu“.
          </p>
          <h2>Lokální data v telefonu</h2>
          <p>
            Data uložená pouze lokálně v zařízení můžete odstranit také
            odinstalováním aplikace nebo vymazáním jejích dat v nastavení
            Androidu.
          </p>
          <h2>Potřebujete místo toho pomoc?</h2>
          <p>
            Pokud nechcete účet odstranit a pouze řešíte problém s aplikací,
            přejděte na stránku <Link href="/podpora">Podpora</Link>.
          </p>
        </div>
      </div>
    </section>
  );
}
