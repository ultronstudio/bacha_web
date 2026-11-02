(() => {
      try {
        const savedTheme = localStorage.getItem("bacha-theme");
        const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        document.documentElement.setAttribute(
          "data-bs-theme",
          savedTheme === "light" || savedTheme === "dark"
            ? savedTheme
            : (systemDark ? "dark" : "light")
        );
      } catch (_) {}
    })();
