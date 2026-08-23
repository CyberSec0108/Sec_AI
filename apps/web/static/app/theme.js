(function () {
  "use strict";

  const button = document.getElementById("theme-toggle");
  const label = document.getElementById("theme-toggle-label");
  if (!button) {
    return;
  }

  const storageKey = "secai_theme";
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");

  function storedTheme() {
    try {
      const value = window.localStorage.getItem(storageKey);
      return value === "light" || value === "dark" ? value : null;
    } catch (_error) {
      return null;
    }
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const dark = theme === "dark";
    const actionLabel = dark ? "밝은 화면으로 전환" : "어두운 화면으로 전환";
    button.setAttribute("aria-pressed", String(dark));
    button.setAttribute("aria-label", actionLabel);
    button.setAttribute("title", actionLabel);
    button.dataset.themeState = theme;
    if (label) {
      label.textContent = actionLabel;
    }
  }

  applyTheme(storedTheme() || (prefersDark.matches ? "dark" : "light"));

  button.addEventListener("click", function () {
    const next = document.documentElement.dataset.theme === "dark"
      ? "light"
      : "dark";
    try {
      window.localStorage.setItem(storageKey, next);
    } catch (_error) {
      // 저장이 제한된 브라우저에서도 현재 화면 전환은 계속 제공합니다.
    }
    applyTheme(next);
  });
}());
