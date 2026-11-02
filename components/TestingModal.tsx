"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import Script from "next/script";

declare global {
  interface Window {
    grecaptcha?: {
      render: (
        container: HTMLElement,
        options: { sitekey: string; theme: string; size: string },
      ) => number;
      getResponse: (id: number) => string;
      reset: (id?: number) => void;
    };
  }
}

export default function TestingModal({ siteKey }: { siteKey: string }) {
  const formRef = useRef<HTMLFormElement>(null);
  const widgetRef = useRef<HTMLDivElement>(null);
  const widgetId = useRef<number | null>(null);
  const renderedTheme = useRef<string | null>(null);
  const renderCaptchaRef = useRef<() => void>(() => {});
  const [captchaReady, setCaptchaReady] = useState(false);
  const [status, setStatus] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [sending, setSending] = useState(false);

  useEffect(() => {
    const modal = document.getElementById("testingModal");
    const renderCaptcha = () => {
      if (!window.grecaptcha || !siteKey || !widgetRef.current) return;
      const theme =
        document.documentElement.getAttribute("data-bs-theme") === "dark"
          ? "dark"
          : "light";
      if (widgetId.current !== null && renderedTheme.current === theme) {
        window.grecaptcha.reset(widgetId.current);
        return;
      }
      widgetRef.current.replaceChildren();
      try {
        widgetId.current = window.grecaptcha.render(widgetRef.current, {
          sitekey: siteKey,
          theme,
          size: "normal",
        });
        renderedTheme.current = theme;
        setCaptchaReady(true);
      } catch {
        widgetRef.current.replaceChildren();
        widgetId.current = null;
        renderedTheme.current = null;
        setCaptchaReady(false);
      }
    };
    renderCaptchaRef.current = renderCaptcha;
    const onShown = () => {
      renderCaptcha();
      document.getElementById("testing-email")?.focus();
    };
    modal?.addEventListener("shown.bs.modal", onShown);
    return () => modal?.removeEventListener("shown.bs.modal", onShown);
  }, [siteKey]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus(null);
    const form = formRef.current;
    if (!form) return;
    if (!form.reportValidity()) {
      form.classList.add("was-validated");
      return;
    }
    if (!siteKey) {
      setStatus({
        type: "error",
        message: "Formulář ještě nemá nastavený reCAPTCHA site key.",
      });
      return;
    }
    if (
      widgetId.current === null ||
      !window.grecaptcha?.getResponse(widgetId.current)
    ) {
      setStatus({ type: "error", message: "Potvrďte prosím reCAPTCHA." });
      return;
    }
    setSending(true);
    try {
      const response = await fetch("/api/interest", {
        method: "POST",
        body: new FormData(form),
        headers: { Accept: "application/json" },
      });
      const payload = (await response.json().catch(() => ({}))) as {
        ok?: boolean;
        message?: string;
      };
      if (!response.ok || !payload.ok)
        throw new Error(
          payload.message || "Odeslání se nepodařilo. Zkuste to prosím znovu.",
        );
      setStatus({
        type: "success",
        message: payload.message || "Díky. Zájem o testování byl odeslán.",
      });
      form.reset();
      form.classList.remove("was-validated");
      if (widgetId.current !== null) window.grecaptcha?.reset(widgetId.current);
    } catch (error) {
      setStatus({
        type: "error",
        message:
          error instanceof Error
            ? error.message
            : "Odeslání se nepodařilo. Zkuste to prosím znovu.",
      });
      if (widgetId.current !== null) window.grecaptcha?.reset(widgetId.current);
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      {siteKey && (
        <Script
          src="https://www.google.com/recaptcha/api.js?render=explicit"
          strategy="afterInteractive"
          onLoad={() => {
            if (document.getElementById("testingModal")?.classList.contains("show")) {
              renderCaptchaRef.current();
            }
          }}
        />
      )}
      <div
        className="modal fade"
        id="testingModal"
        tabIndex={-1}
        aria-labelledby="testingModalLabel"
        aria-hidden="true"
      >
        <div className="modal-dialog modal-dialog-centered">
          <div className="modal-content">
            <div className="modal-header px-4 pt-4">
              <div>
                <h2 className="modal-title fs-4 mb-1" id="testingModalLabel">
                  Zájem o uzavřené testování
                </h2>
              </div>
              <button
                type="button"
                className="btn-close"
                data-bs-dismiss="modal"
                aria-label="Zavřít"
              />
            </div>
            <form ref={formRef} onSubmit={submit} noValidate>
              <div className="modal-body px-4 py-4">
                <div className="mb-3">
                  <label htmlFor="testing-email" className="form-label">
                    E-mail pro Google účet
                  </label>
                  <input
                    type="email"
                    className="form-control"
                    id="testing-email"
                    name="mail"
                    maxLength={254}
                    autoComplete="email"
                    inputMode="email"
                    placeholder="jmeno@example.cz"
                    required
                  />
                  <div className="invalid-feedback">
                    Zadejte platnou e-mailovou adresu.
                  </div>
                </div>
                <div className="hp-field" aria-hidden="true">
                  <label htmlFor="website">Web</label>
                  <input
                    type="text"
                    id="website"
                    name="website"
                    tabIndex={-1}
                    autoComplete="off"
                  />
                </div>
                <div className={`captcha-wrap${captchaReady ? " is-ready mb-3" : ""}`}>
                  <div ref={widgetRef} id="recaptcha-widget" />
                </div>
                <p className="captcha-note small mb-3">
                  Odesláním předáte svůj e-mail pouze pro účely kontaktování
                  ohledně testování <b>Bacha!</b>.
                </p>
                <div
                  className={`form-status${status ? ` ${status.type === "success" ? "is-success" : "is-error"}` : ""}`}
                  role="status"
                  aria-live="polite"
                >
                  {status?.message}
                </div>
              </div>
              <div className="modal-footer px-4 pb-4 pt-0 border-0">
                <button
                  className="btn btn-bacha-secondary"
                  type="button"
                  data-bs-dismiss="modal"
                >
                  Zrušit
                </button>
                <button
                  className="btn btn-bacha-primary px-4"
                  id="testing-submit"
                  type="submit"
                  disabled={sending}
                >
                  {sending ? "Odesílám…" : "Odeslat zájem"}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}
