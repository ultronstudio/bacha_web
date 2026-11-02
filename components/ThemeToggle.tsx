"use client";

import { useEffect } from "react";
import { Icon } from "./Icon";

export default function ThemeToggle() {
  useEffect(() => {
    const root = document.documentElement;
    const button = document.getElementById("theme-toggle");
    const themeColor = document.getElementById("theme-color");
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
    const applyTheme = (theme: "light" | "dark") => {
      root.setAttribute("data-theme-changing", "");
      root.setAttribute("data-bs-theme", theme);
      window.requestAnimationFrame(() => {
        window.requestAnimationFrame(() => root.removeAttribute("data-theme-changing"));
      });
    };
    const sync = () => {
      const dark = root.getAttribute("data-bs-theme") === "dark";
      button?.setAttribute(
        "aria-label",
        dark ? "Přepnout na světlý režim" : "Přepnout na tmavý režim",
      );
      themeColor?.setAttribute("content", dark ? "#131311" : "#FAFAF7");
    };
    const toggle = () => {
      const next =
        root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      try {
        localStorage.setItem("bacha-theme", next);
      } catch {
        /* storage may be disabled */
      }
      sync();
    };
    const onSystemChange = (event: MediaQueryListEvent) => {
      try {
        if (!localStorage.getItem("bacha-theme")) {
          applyTheme(event.matches ? "dark" : "light");
          sync();
        }
      } catch {
        /* storage may be disabled */
      }
    };
    button?.addEventListener("click", toggle);
    systemDark.addEventListener("change", onSystemChange);
    sync();
    return () => {
      button?.removeEventListener("click", toggle);
      systemDark.removeEventListener("change", onSystemChange);
    };
  }, []);

  return (
    <button
      className="btn theme-toggle p-0 order-md-3"
      id="theme-toggle"
      type="button"
      aria-label="Přepnout barevný režim"
    >
      <Icon name="moon-stars" className="theme-icon-light" />
      <Icon name="sun" className="theme-icon-dark" />
    </button>
  );
}
