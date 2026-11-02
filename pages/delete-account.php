<?php
declare(strict_types=1);

function renderDeleteAccount(): void
{
?>
<section class="page-main">
<div class="container">
    <h1 class="mb-4">Smazání účtu a dat</h1>
    <div class="content">
      
<p class="lead-text">
  Pokud chcete požádat o odstranění účtu Bacha! nebo údajů spojených
  s vaším účtem, můžete žádost poslat e-mailem.
</p>

<div class="info-box">
  <strong>Žádost pošlete na:</strong><br>
  <a href="mailto:kontakt@petrvurm.cz?subject=Bacha!%20-%20smaz%C3%A1n%C3%AD%20%C3%BA%C4%8Dtu">
    kontakt@petrvurm.cz
  </a>
</div>

<h2>Co do žádosti uvést</h2>
<p>
  Použijte pokud možno stejnou e-mailovou adresu, kterou používáte
  v aplikaci Bacha!. Do předmětu můžete uvést „Bacha! – smazání účtu“.
</p>

<h2>Lokální data v telefonu</h2>
<p>
  Data uložená pouze lokálně v zařízení můžete odstranit také odinstalováním
  aplikace nebo vymazáním jejích dat v nastavení Androidu.
</p>

<h2>Potřebujete místo toho pomoc?</h2>
<p>
  Pokud nechcete účet odstranit a pouze řešíte problém s aplikací,
  přejděte na stránku <a href="/podpora">Podpora</a>.
</p>

    </div>
  </div>
</section>
<?php
}
