<?php
declare(strict_types=1);

date_default_timezone_set('Europe/Prague');

require_once __DIR__ . '/pages/home.php';
require_once __DIR__ . '/pages/privacy.php';
require_once __DIR__ . '/pages/delete-account.php';
require_once __DIR__ . '/pages/support.php';
require_once __DIR__ . '/pages/not-found.php';

$requestPath = parse_url(
    (string)($_SERVER['REQUEST_URI'] ?? '/'),
    PHP_URL_PATH
) ?: '/';

$route = '/' . trim($requestPath, '/');

if ($route === '//') {
    $route = '/';
}

$pageTitle = 'Bacha!';
$pageDescription = 'Bacha! – osobní asistent proti podvodům.';
$renderer = 'renderNotFound';

switch ($route) {
    case '/':
        $pageTitle = 'Bacha! – Než klikneš, zkontroluj.';
        $pageDescription = 'Bacha! – osobní asistent proti podvodům. Prověřte zprávy, odkazy, QR kódy a screenshoty.';
        $renderer = 'renderHome';
        break;

    case '/ochrana-soukromi':
        $pageTitle = 'Ochrana soukromí – Bacha!';
        $pageDescription = 'Informace o ochraně soukromí na webu a v aplikaci Bacha!.';
        $renderer = 'renderPrivacy';
        break;

    case '/smazat-ucet':
        $pageTitle = 'Smazání účtu – Bacha!';
        $pageDescription = 'Informace k odstranění účtu a dat aplikace Bacha!.';
        $renderer = 'renderDeleteAccount';
        break;

    case '/podpora':
        $pageTitle = 'Podpora – Bacha!';
        $pageDescription = 'Podpora pro aplikaci Bacha!.';
        $renderer = 'renderSupport';
        break;

    default:
        http_response_code(404);
        $pageTitle = 'Stránka nenalezena – Bacha!';
        $pageDescription = 'Požadovaná stránka nebyla nalezena.';
        $renderer = 'renderNotFound';
        break;
}

$recaptchaSiteKey = trim(
    (string)getenv('RECAPTCHA_SITE_KEY')
);
?>

<!doctype html>
<html lang="cs" data-bs-theme="light" data-recaptcha-site-key="<?= htmlspecialchars(
    $recaptchaSiteKey,
    ENT_QUOTES | ENT_SUBSTITUTE,
    'UTF-8'
) ?>">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#FAFAF7" id="theme-color">
  <meta name="description" content="<?= htmlspecialchars($pageDescription, ENT_QUOTES, 'UTF-8') ?>">
  <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title>

  <script src="/assets/theme.js"></script>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">

  <link rel="stylesheet" href="/assets/app.css">

</head>

<body>



<header class="site-header sticky-top">
  <nav class="navbar navbar-expand-md py-0">
    <div class="container d-flex align-items-center gap-3">
      <a class="navbar-brand d-flex align-items-center gap-2 me-auto" href="#top" aria-label="Bacha! – domů">
        <span class="app-logo" aria-hidden="true">
          <img src="/assets/images/bacha-logo.svg" alt="">
        </span>
        Bacha!
      </a>

      <div class="collapse navbar-collapse order-md-2" id="mainNav">
        <ul class="navbar-nav ms-auto me-md-3 align-items-md-center gap-md-2">
          <li class="nav-item"><a class="nav-link" href="#funkce">Co umí</a></li>
          <li class="nav-item"><a class="nav-link" href="#soukromi">Soukromí</a></li>
          <li class="nav-item"><a class="nav-link" href="/podpora">Podpora</a></li>
        </ul>
      </div>

      <button class="btn theme-toggle p-0 order-md-3" id="theme-toggle" type="button" aria-label="Přepnout barevný režim">
        <svg class="bs-icon theme-icon-light" aria-hidden="true"><use href="/assets/images/moon-stars.svg#icon"></use></svg>
        <svg class="bs-icon theme-icon-dark" aria-hidden="true"><use href="/assets/images/sun.svg#icon"></use></svg>
      </button>

      <button class="navbar-toggler border-0 shadow-none p-2 order-md-4" type="button"
              data-bs-toggle="collapse" data-bs-target="#mainNav"
              aria-controls="mainNav" aria-expanded="false" aria-label="Otevřít navigaci">
        <svg class="bs-icon fs-4-icon" aria-hidden="true"><use href="/assets/images/list.svg#icon"></use></svg>
      </button>
    </div>
  </nav>
</header>

<main id="top">
<?php $renderer(); ?>
</main>

<footer>
  <div class="container">
    <div class="d-flex align-items-center flex-wrap gap-3 gap-md-4">
      <a class="navbar-brand d-flex align-items-center gap-2 me-md-auto" href="#top">
        <span class="app-logo" aria-hidden="true">
          <img src="/assets/images/bacha-logo.svg" alt="">
        </span>
        Bacha!
      </a>

      <a href="/ochrana-soukromi">Ochrana soukromí</a>
      <a href="/smazat-ucet">Smazání účtu</a>
      <a href="/podpora">Podpora</a>

      <div class="copyright">
        © <?= date('Y') ?> <a href="https://petrvurm.cz?utm_source=bacha_web&utm_medium=website&utm_campaign=footer_credit" target="_blank" rel="noopener noreferrer">Petr Vurm</a>
      </div>
    </div>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

<script src="/assets/app.js" defer></script>

<script src="https://www.google.com/recaptcha/api.js?onload=onRecaptchaLoad&render=explicit" async defer></script>
</body>
</html>
