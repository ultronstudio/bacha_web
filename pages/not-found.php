<?php
declare(strict_types=1);

function renderNotFound(): void
{
?>
<section class="page-main d-grid align-items-center">
  <div class="container">
    <div class="error-wrap mx-auto">
<div class="mb-3 fs-5 fw-bold">Bacha!</div>
    <h1 class="mb-3">404</h1>
    <p class="mb-4">Tahle stránka tu není.</p>
    <a class="btn btn-bacha d-inline-flex align-items-center justify-content-center" href="/">
      Zpět na hlavní stránku
    </a>
    </div>
  </div>
</section>
<?php
}
