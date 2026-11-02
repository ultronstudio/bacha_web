import { Icon } from "./Icon";
import ThemeToggle from "./ThemeToggle";
import Link from "next/link";
import Image from "next/image";
import SectionJump from "./SectionJump";

export default function Header() {
  return (
    <header className="site-header sticky-top">
      <nav className="navbar navbar-expand-md py-0">
        <div className="container d-flex align-items-center gap-3">
          <Link
            className="navbar-brand d-flex align-items-center gap-2 me-auto"
            href="/"
            aria-label="Bacha! – domů"
          >
            <span className="app-logo" aria-hidden="true">
            <Image src="/assets/images/bacha-logo.svg" alt="" width={56} height={60} />
            </span>
            Bacha!
          </Link>
          <div className="collapse navbar-collapse order-md-2" id="mainNav">
            <ul className="navbar-nav ms-auto me-md-3 align-items-md-center gap-md-2">
              <li className="nav-item">
                <SectionJump className="nav-link" target="funkce">
                  Co umí
                </SectionJump>
              </li>
              <li className="nav-item">
                <SectionJump className="nav-link" target="soukromi">
                  Soukromí
                </SectionJump>
              </li>
              <li className="nav-item">
                <Link className="nav-link" href="/podpora">
                  Podpora
                </Link>
              </li>
            </ul>
          </div>
          <ThemeToggle />
          <button
            className="navbar-toggler border-0 shadow-none p-2 order-md-4"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#mainNav"
            aria-controls="mainNav"
            aria-expanded="false"
            aria-label="Otevřít navigaci"
          >
            <Icon name="list" className="fs-4-icon" />
          </button>
        </div>
      </nav>
    </header>
  );
}
