<?php
declare(strict_types=1);

function renderHome(): void
{
?>
<section class="hero">
    <div class="container position-relative">
      <div class="row align-items-center g-5">
        <div class="col-lg-6 hero-visual d-flex align-items-center">
          <div class="action-stack">
            <div class="action-row d-flex align-items-center gap-3">
              <span class="action-icon action-link">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/link-45deg.svg#icon"></use></svg>
              </span>
              <span class="action-title flex-grow-1">Text nebo odkaz</span>
              <span class="chevron">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/chevron-right.svg#icon"></use></svg>
              </span>
            </div>

            <div class="action-row d-flex align-items-center gap-3">
              <span class="action-icon action-shot">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/image.svg#icon"></use></svg>
              </span>
              <span class="action-title flex-grow-1">Screenshot</span>
              <span class="chevron">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/chevron-right.svg#icon"></use></svg>
              </span>
            </div>

            <div class="action-row d-flex align-items-center gap-3">
              <span class="action-icon action-qr">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/qr-code-scan.svg#icon"></use></svg>
              </span>
              <span class="action-title flex-grow-1">QR kód</span>
              <span class="chevron">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/chevron-right.svg#icon"></use></svg>
              </span>
            </div>

            <div class="action-row d-flex align-items-center gap-3">
              <span class="action-icon action-phone">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/telephone.svg#icon"></use></svg>
              </span>
              <span class="action-title flex-grow-1">Telefonní číslo</span>
              <span class="chevron">
                <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/chevron-right.svg#icon"></use></svg>
              </span>
            </div>
          </div>
        </div>

        <div class="col-lg-6 hero-copy">
          <img class="hero-mark" src="/assets/images/bacha-logo.svg" alt="">

          <h1>Než klikneš,<br>zkontroluj.</h1>

          <p>
            Osobní asistent proti podvodům. Prověřte zprávy, odkazy,
            QR kódy a screenshoty.
          </p>

          <div class="hero-actions d-grid gap-3">
            <a class="btn btn-bacha-primary d-flex align-items-center justify-content-center gap-2" href="#testovani">
              <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/shield-check.svg#icon"></use></svg>
              Chci do testování
            </a>

            <a class="btn btn-bacha-secondary d-flex align-items-center justify-content-center gap-2" href="#funkce">
              Jak Bacha! pomáhá
            </a>
          </div>

          <div class="hero-note">Uzavřené testování je momentálně dostupné na pozvání.</div>
        </div>
      </div>
    </div>
  </section>

  <section class="feature" id="funkce">
    <div class="container">
      <div class="row align-items-center g-5">
        <div class="col-lg-6 feature-art d-grid place-items-center text-center">
          <div class="big-symbol link mx-auto">
            <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/link-45deg.svg#icon"></use></svg>
          </div>
        </div>

        <div class="col-lg-6 feature-copy">
          <h2>Prověření textu a odkazů</h2>
          <p>
            Vložte zprávu, e-mail nebo URL adresu. Bacha! hledá skryté IP adresy,
            maskované znaky, nátlakový jazyk a další konkrétní varovné znaky.
          </p>
        </div>
      </div>
    </div>
  </section>

  <section class="feature">
    <div class="container">
      <div class="row align-items-center g-5">
        <div class="col-lg-6 order-1 order-lg-2 feature-art d-grid text-center">
          <div class="big-symbol shot mx-auto">
            <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/image.svg#icon"></use></svg>
          </div>
        </div>

        <div class="col-lg-6 order-2 order-lg-1 feature-copy">
          <h2>Analýza screenshotů</h2>
          <p>
            Vyfoťte obrazovku s podezřelým chatem nebo e-mailem a nechte
            Bacha! vyhledat nebezpečné prvky bez ručního přepisování.
          </p>
        </div>
      </div>
    </div>
  </section>

  <section class="feature">
    <div class="container">
      <div class="row align-items-center g-5">
        <div class="col-lg-6 feature-art d-grid text-center">
          <div class="big-symbol qr mx-auto">
            <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/qr-code-scan.svg#icon"></use></svg>
          </div>
        </div>

        <div class="col-lg-6 feature-copy">
          <h2>Bezpečný QR skener</h2>
          <p>
            Naskenujte QR kód fotoaparátem. Bacha! odkaz neotevře automaticky,
            ale nejprve prověří jeho bezpečnost.
          </p>
        </div>
      </div>
    </div>
  </section>

  <section class="feature">
    <div class="container">
      <div class="row align-items-center g-5">
        <div class="col-lg-6 order-1 order-lg-2 feature-art d-grid text-center">
          <div class="big-symbol phone mx-auto">
            <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/telephone.svg#icon"></use></svg>
          </div>
        </div>

        <div class="col-lg-6 order-2 order-lg-1 feature-copy">
          <h2>Telefonní čísla</h2>
          <p>
            Ověřte si, co vám volající tvrdil, a zjistěte souvislosti dřív,
            než zavoláte zpět nebo někomu předáte citlivé údaje.
          </p>
        </div>
      </div>
    </div>
  </section>

  <section class="incident">
    <div class="container">
      <div class="row align-items-center justify-content-center g-4">
        <div class="col-auto">
          <div class="incident-icon">
            <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/exclamation-triangle.svg#icon"></use></svg>
          </div>
        </div>

        <div class="col-lg-8">
          <h2 class="mb-2">Něco už se stalo?</h2>
          <p class="mb-4">V pohodě. Projdeme spolu, co teď udělat.</p>

          <a class="btn btn-bacha-secondary d-inline-flex align-items-center justify-content-center" href="#stahnout">
            Krizový režim v aplikaci
          </a>
        </div>
      </div>
    </div>
  </section>

  <section class="privacy" id="soukromi">
    <div class="container">
      <div class="privacy-mark">
        <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/lock.svg#icon"></use></svg>
      </div>

      <h2 class="mb-0">Soukromí na prvním místě</h2>

      <p class="privacy-intro">
        Bacha! je bezpečnostní pomocník pro běžné lidi. Nemá důvod sledovat,
        co děláte mimo kontrolu, kterou sami spustíte.
      </p>

      <div class="privacy-points d-grid gap-3">
        <div class="privacy-point d-flex align-items-center gap-3">
          <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/check-lg.svg#icon"></use></svg>
          <span>Nečteme vaše SMS schránky ani kontakty.</span>
        </div>

        <div class="privacy-point d-flex align-items-center gap-3">
          <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/check-lg.svg#icon"></use></svg>
          <span>Nesledujeme polohu ani historii prohlížení.</span>
        </div>

        <div class="privacy-point d-flex align-items-center gap-3">
          <svg class="bs-icon" aria-hidden="true"><use href="/assets/images/check-lg.svg#icon"></use></svg>
          <span>Žádné reklamy.</span>
        </div>
      </div>

      <div class="privacy-links d-flex justify-content-center flex-wrap gap-4">
        <a href="/ochrana-soukromi">Zásady ochrany soukromí</a>
        <a href="/smazat-ucet">Smazání účtu</a>
      </div>
    </div>
  </section>

  <section class="download" id="testovani">
    <div class="container">
      <img class="hero-mark" src="/assets/images/bacha-logo.svg" alt="">

      <h2>Chcete Bacha! vyzkoušet?</h2>

      <p>
        Přihlaste se do uzavřeného testování. Stačí e-mail, který používáte
        pro svůj Google účet a Google Play. Pokud bude možné vás přidat,
        ozvu se s dalšími kroky.
      </p>

      <button class="btn btn-bacha-primary play-button d-inline-flex align-items-center justify-content-center gap-2"
              type="button" data-bs-toggle="modal" data-bs-target="#testingModal">
        Mám zájem o testování
      </button>
    </div>
  </section>

<!-- Zájem o uzavřené testování -->
<div class="modal fade" id="testingModal" tabindex="-1" aria-labelledby="testingModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header px-4 pt-4">
        <div>
          <h2 class="modal-title fs-4 mb-1" id="testingModalLabel">Zájem o uzavřené testování</h2>
          <p class="testing-help small mb-0">Stačí e-mail používaný pro váš Google účet / Google Play.</p>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Zavřít"></button>
      </div>

      <form id="testing-interest-form" action="/api.php?akce=odeslat" method="post" novalidate>
        <div class="modal-body px-4 py-4">
          <div class="mb-3">
            <label for="testing-email" class="form-label">E-mail pro Google účet</label>
            <input type="email"
                   class="form-control"
                   id="testing-email"
                   name="mail"
                   maxlength="254"
                   autocomplete="email"
                   inputmode="email"
                   placeholder="jmeno@example.cz"
                   required>
            <div class="invalid-feedback">Zadejte platnou e-mailovou adresu.</div>
          </div>

          <div class="hp-field" aria-hidden="true">
            <label for="website">Web</label>
            <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
          </div>

          <div class="captcha-wrap mb-3">
            <div id="recaptcha-widget"></div>
          </div>

          <p class="captcha-note small mb-3">
            Formulář používá Google reCAPTCHA jako ochranu proti spamu.
            Odesláním předáte svůj e-mail pouze pro účely kontaktování ohledně testování Bacha!.
          </p>

          <div class="form-status" id="testing-form-status" role="status" aria-live="polite"></div>
        </div>

        <div class="modal-footer px-4 pb-4 pt-0 border-0">
          <button class="btn btn-bacha-secondary" type="button" data-bs-dismiss="modal">Zrušit</button>
          <button class="btn btn-bacha-primary px-4" id="testing-submit" type="submit">
            Odeslat zájem
          </button>
        </div>
      </form>
    </div>
  </div>
</div>
<?php
}
