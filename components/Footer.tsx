import Link from "next/link";
import Image from "next/image";

export default function Footer() {
  return (
    <footer>
      <div className="container">
        <div className="d-flex align-items-center flex-wrap gap-3 gap-md-4">
          <Link
            className="navbar-brand d-flex align-items-center gap-2 me-md-auto"
            href="/"
            aria-label="Bacha! – domů"
          >
            <span className="app-logo" aria-hidden="true">
              <Image src="/assets/images/bacha-logo.svg" alt="" width={56} height={60} />
            </span>
            Bacha!
          </Link>
          <Link href="/ochrana-soukromi">Ochrana soukromí</Link>
          <Link href="/smazat-ucet">Smazání účtu</Link>
          <Link href="/podpora">Podpora</Link>
          <div className="copyright">
            © {new Date().getFullYear()}{" "}
            <Link
              href="https://petrvurm.cz?utm_source=bacha_web&amp;utm_medium=website&amp;utm_campaign=footer_credit"
              target="_blank"
              rel="noopener noreferrer"
            >
              Petr Vurm
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
