(() => {
    const root = document.documentElement;
    const toggle = document.getElementById("theme-toggle");
    const themeColor = document.getElementById("theme-color");
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)");

    function currentTheme() {
      return root.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
    }

    function syncThemeUi() {
      const dark = currentTheme() === "dark";
      toggle.setAttribute(
        "aria-label",
        dark ? "Přepnout na světlý režim" : "Přepnout na tmavý režim"
      );
      themeColor.setAttribute("content", dark ? "#131311" : "#FAFAF7");
    }

    toggle.addEventListener("click", () => {
      const next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-bs-theme", next);

      try {
        localStorage.setItem("bacha-theme", next);
      } catch (_) {}

      syncThemeUi();
    });

    systemDark.addEventListener?.("change", event => {
      try {
        if (!localStorage.getItem("bacha-theme")) {
          root.setAttribute("data-bs-theme", event.matches ? "dark" : "light");
          syncThemeUi();
        }
      } catch (_) {}
    });

    document.getElementById("year").textContent = new Date().getFullYear();
    syncThemeUi();
  
  // --- Uzavřené testování / reCAPTCHA ---
  const RECAPTCHA_SITE_KEY = document.documentElement.dataset.recaptchaSiteKey || "";
  let recaptchaWidgetId = null;
  let recaptchaRenderedTheme = null;

  window.onRecaptchaLoad = function () {
    // Widget se vykreslí až při otevření formuláře, aby odpovídal aktuálnímu light/dark režimu.
  };

  function renderTestingRecaptcha() {
    if (!window.grecaptcha || !RECAPTCHA_SITE_KEY) {
      return;
    }

    const theme = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
    const holder = document.getElementById("recaptcha-widget");
    if (!holder) return;

    if (recaptchaWidgetId !== null && recaptchaRenderedTheme === theme) {
      grecaptcha.reset(recaptchaWidgetId);
      return;
    }

    holder.innerHTML = "";
    const node = document.createElement("div");
    holder.appendChild(node);

    recaptchaWidgetId = grecaptcha.render(node, {
      sitekey: RECAPTCHA_SITE_KEY,
      theme,
      size: "normal"
    });
    recaptchaRenderedTheme = theme;
  }

  document.getElementById("testingModal")?.addEventListener("shown.bs.modal", () => {
    renderTestingRecaptcha();
    document.getElementById("testing-email")?.focus();
  });

  const testingForm = document.getElementById("testing-interest-form");
  const testingStatus = document.getElementById("testing-form-status");
  const testingSubmit = document.getElementById("testing-submit");

  function setTestingStatus(type, message) {
    testingStatus.className = "form-status " + (type === "success" ? "is-success" : "is-error");
    testingStatus.textContent = message;
  }

  testingForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    testingStatus.className = "form-status";
    testingStatus.textContent = "";

    if (!testingForm.checkValidity()) {
      testingForm.classList.add("was-validated");
      return;
    }

    if (!RECAPTCHA_SITE_KEY) {
      setTestingStatus("error", "Formulář ještě nemá nastavený reCAPTCHA site key.");
      return;
    }

    if (recaptchaWidgetId === null || !grecaptcha.getResponse(recaptchaWidgetId)) {
      setTestingStatus("error", "Potvrďte prosím reCAPTCHA.");
      return;
    }

    testingSubmit.disabled = true;
    testingSubmit.textContent = "Odesílám…";

    try {
      const response = await fetch(testingForm.action, {
        method: "POST",
        body: new FormData(testingForm),
        headers: {
          "Accept": "application/json"
        }
      });

      const payload = await response.json().catch(() => ({}));

      if (!response.ok || !payload.ok) {
        throw new Error(payload.message || "Odeslání se nepodařilo. Zkuste to prosím znovu.");
      }

      setTestingStatus("success", payload.message || "Díky. Zájem o testování byl odeslán.");
      testingForm.reset();
      testingForm.classList.remove("was-validated");
      if (recaptchaWidgetId !== null) {
        grecaptcha.reset(recaptchaWidgetId);
      }
    } catch (error) {
      setTestingStatus("error", error.message || "Odeslání se nepodařilo. Zkuste to prosím znovu.");
      if (recaptchaWidgetId !== null) {
        grecaptcha.reset(recaptchaWidgetId);
      }
    } finally {
      testingSubmit.disabled = false;
      testingSubmit.textContent = "Odeslat zájem";
    }
  });

})();
