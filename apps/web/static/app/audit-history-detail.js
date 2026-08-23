(function () {
  "use strict";

  const platform = document.querySelector(
    'meta[name="audit-history-platform"]'
  )?.content || "";
  const entryId = document.querySelector(
    'meta[name="audit-history-entry-id"]'
  )?.content || "";
  const panel = document.getElementById("audit-history-ai-screen");
  const summary = document.getElementById("audit-history-ai-summary");
  const controls = document.getElementById("audit-history-ai-controls");
  const markdown = window.SecAIRestrictedMarkdown;
  if (!platform || !entryId || !panel || !summary || !controls) {
    return;
  }

  function renderMarkdown(container, source) {
    if (markdown && typeof markdown.render === "function") {
      markdown.render(container, source || "", {
        allowedOrigins: [window.location.origin]
      });
      return;
    }
    container.textContent = source || "저장된 설명이 없습니다.";
  }

  function renderScreen(screen) {
    if (
      !screen ||
      typeof screen.summary_source !== "string" ||
      !Array.isArray(screen.controls)
    ) {
      return;
    }
    renderMarkdown(summary, screen.summary_source);
    const fragment = document.createDocumentFragment();
    screen.controls.forEach(function (item) {
      if (!item || typeof item.control_id !== "string") {
        return;
      }
      const row = document.createElement("li");
      const title = document.createElement("h3");
      const content = document.createElement("div");
      title.textContent = item.control_id + " AI 설명";
      content.className = "ai-markdown";
      renderMarkdown(content, typeof item.source === "string" ? item.source : "");
      row.append(title, content);
      fragment.appendChild(row);
    });
    controls.replaceChildren(fragment);
    panel.hidden = false;
  }

  void window.fetch(
    "/api/v1/audit-history/" + encodeURIComponent(platform) + "/" +
      encodeURIComponent(entryId),
    {method: "GET", cache: "no-store"}
  ).then(function (response) {
    if (!response.ok) {
      return null;
    }
    return response.json();
  }).then(function (detail) {
    if (detail && detail.ai_screen) {
      renderScreen(detail.ai_screen);
    }
  }).catch(function () {
    // AI 화면 복원 실패가 불변 점검 결과 표시를 가리지 않게 합니다.
  });
}());
