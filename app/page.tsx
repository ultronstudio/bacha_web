import { Icon } from "@/components/Icon";
import TestingModal from "@/components/TestingModal";
import Link from "next/link";
import Image from "next/image";
import SectionJump from "@/components/SectionJump";

export default function HomePage() {
  const recaptchaSiteKey =
    process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY ||
    process.env.RECAPTCHA_SITE_KEY ||
    "";

  return (
    <>
      <section className="hero">
        <div className="container position-relative">
          <div className="row align-items-center g-5">
            <div className="col-lg-6 hero-copy">
              <Image
                className="hero-mark"
                src="/assets/images/bacha-logo.svg"
                alt=""
                width={92}
                height={92}
              />
              <h1>
                Než klikneš,
                <br />
                zkontroluj
              </h1>
              <p>
                Osobní asistent proti podvodům. Prověřte zprávy, odkazy, QR kódy
                a screenshoty.
              </p>
              <div className="hero-actions d-grid gap-3">
                <button
                  className="btn btn-bacha-primary d-flex align-items-center justify-content-center gap-2"
                  type="button"
                  data-bs-toggle="modal"
                  data-bs-target="#testingModal"
                >
                  <Icon name="shield-check" />
                  Chci do testování
                </button>
                <SectionJump
                  className="btn btn-bacha-secondary d-flex align-items-center justify-content-center gap-2"
                  target="funkce"
                >
                  Jak Bacha! pomáhá
                </SectionJump>
              </div>
              <div className="hero-note">
                Uzavřené testování je momentálně dostupné na pozvání.
              </div>
            </div>
            <div className="col-lg-6 hero-visual d-flex align-items-center">
              <div className="action-stack">
                <div className="action-row d-flex align-items-center gap-3">
                  <span className="action-icon action-link">
                    <Icon name="link-45deg" />
                  </span>
                  <span className="action-title flex-grow-1">
                    Text nebo odkaz
                  </span>
                  <span className="chevron">
                    <Icon name="chevron-right" />
                  </span>
                </div>
                <div className="action-row d-flex align-items-center gap-3">
                  <span className="action-icon action-shot">
                    <Icon name="image" />
                  </span>
                  <span className="action-title flex-grow-1">Screenshot</span>
                  <span className="chevron">
                    <Icon name="chevron-right" />
                  </span>
                </div>
                <div className="action-row d-flex align-items-center gap-3">
                  <span className="action-icon action-qr">
                    <Icon name="qr-code-scan" />
                  </span>
                  <span className="action-title flex-grow-1">QR kód</span>
                  <span className="chevron">
                    <Icon name="chevron-right" />
                  </span>
                </div>
                <div className="action-row d-flex align-items-center gap-3">
                  <span className="action-icon action-phone">
                    <Icon name="telephone" />
                  </span>
                  <span className="action-title flex-grow-1">
                    Telefonní číslo
                  </span>
                  <span className="chevron">
                    <Icon name="chevron-right" />
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Feature icon="link-45deg" tone="link" title="Prověření textu a odkazů">
        Vložte zprávu, e-mail nebo URL adresu. Bacha! hledá skryté IP adresy,
        maskované znaky, nátlakový jazyk a další konkrétní varovné znaky.
      </Feature>
      <Feature icon="image" tone="shot" title="Analýza screenshotů" reverse>
        Vyfoťte obrazovku s podezřelým chatem nebo e-mailem a nechte Bacha!
        vyhledat nebezpečné prvky bez ručního přepisování.
      </Feature>
      <Feature icon="qr-code-scan" tone="qr" title="Bezpečný QR skener">
        Naskenujte QR kód fotoaparátem. Bacha! odkaz neotevře automaticky, ale
        nejprve prověří jeho bezpečnost.
      </Feature>
      <Feature icon="telephone" tone="phone" title="Telefonní čísla" reverse>
        Ověřte si, co vám volající tvrdil, a zjistěte souvislosti dřív, než
        zavoláte zpět nebo někomu předáte citlivé údaje.
      </Feature>

      <section className="incident">
        <div className="container">
          <div className="row align-items-center justify-content-center g-4">
            <div className="col-auto">
              <div className="incident-icon">
                <Icon name="exclamation-triangle" />
              </div>
            </div>
            <div className="col-lg-8">
              <h2 className="mb-2">Něco už se stalo?</h2>
              <p className="mb-4">V pohodě. Projdeme spolu, co teď udělat.</p>
              <button
                className="btn btn-bacha-secondary d-inline-flex align-items-center justify-content-center"
                type="button"
                data-bs-toggle="modal"
                data-bs-target="#testingModal"
              >
                Krizový režim v aplikaci
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="privacy" id="soukromi">
        <div className="container">
          <div className="privacy-mark">
            <Icon name="lock" />
          </div>
          <h2 className="mb-0">Soukromí na prvním místě</h2>
          <p className="privacy-intro">
            Bacha! je bezpečnostní pomocník pro běžné lidi. Nemá důvod sledovat,
            co děláte mimo kontrolu, kterou sami spustíte.
          </p>
          <div className="privacy-points d-grid gap-3">
            <PrivacyPoint>Nečteme vaše SMS schránky ani kontakty.</PrivacyPoint>
            <PrivacyPoint>
              Nesledujeme polohu ani historii prohlížení.
            </PrivacyPoint>
            <PrivacyPoint>Žádné reklamy.</PrivacyPoint>
          </div>
          <div className="privacy-links d-flex justify-content-center flex-wrap gap-4">
            <Link href="/ochrana-soukromi">Zásady ochrany soukromí</Link>
            <Link href="/smazat-ucet">Smazání účtu</Link>
          </div>
        </div>
      </section>

      <section className="download">
        <div className="container">
          <Image
            className="hero-mark"
            src="/assets/images/bacha-logo.svg"
            alt=""
            width={92}
            height={92}
          />
          <h2>Chcete Bacha! vyzkoušet?</h2>
          <p>
            Přihlaste se do uzavřeného testování. Stačí e-mail, který používáte
            pro svůj Google účet a Google Play. Pokud bude možné vás přidat,
            ozvu se s dalšími kroky.
          </p>
          <button
            className="btn btn-bacha-primary play-button d-inline-flex align-items-center justify-content-center gap-2"
            type="button"
            data-bs-toggle="modal"
            data-bs-target="#testingModal"
          >
            Mám zájem o testování
          </button>
        </div>
      </section>
      <TestingModal siteKey={recaptchaSiteKey} />
    </>
  );
}

function Feature({
  icon,
  tone,
  title,
  reverse,
  children,
}: {
  icon: "link-45deg" | "image" | "qr-code-scan" | "telephone";
  tone: string;
  title: string;
  reverse?: boolean;
  children: React.ReactNode;
}) {
  return (
    <section
      className="feature"
      id={title.startsWith("Prověření") ? "funkce" : undefined}
    >
      <div className="container">
        <div className="row align-items-center g-5">
          <div
            className={`col-lg-6 ${reverse ? "order-1 order-lg-2" : ""} feature-art d-grid text-center`}
          >
            <div className={`big-symbol ${tone} mx-auto`}>
              <Icon name={icon} />
            </div>
          </div>
          <div
            className={`col-lg-6 ${reverse ? "order-2 order-lg-1" : ""} feature-copy`}
          >
            <h2>{title}</h2>
            <p>{children}</p>
          </div>
        </div>
      </div>
    </section>
  );
}

function PrivacyPoint({ children }: { children: React.ReactNode }) {
  return (
    <div className="privacy-point d-flex align-items-center gap-3">
      <Icon name="check-lg" />
      <span>{children}</span>
    </div>
  );
}
