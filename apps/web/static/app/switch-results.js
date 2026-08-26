(function () {
  "use strict";

  const runId = document.querySelector('meta[name="switch-run-id"]')?.content || "";
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const integrated = document.getElementById("switch-integrated-results");
  const aiSummaryPanel = document.getElementById("switch-ai-summary-panel");
  const aiSummaryTitle = document.getElementById("switch-ai-summary-title");
  const aiSummary = document.getElementById("switch-ai-summary");
  const aiStatus = document.getElementById("switch-ai-status");
  const aiProgress = document.getElementById("switch-ai-progress");
  const aiCount = document.getElementById("switch-ai-count");
  const startButton = document.getElementById("switch-ai-start");
  const stopButton = document.getElementById("switch-ai-stop");
  const markdown = window.SecAIRestrictedMarkdown;
  if (!runId || !integrated || !aiSummaryPanel || !startButton || !stopButton || !markdown) return;

  const cards = new Map();
  const renderers = new Map();
  let summaryRenderer = null;
  let controller = null;
  let runState = "idle";

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function citationDomId(controlId, citationId) {
    return "switch-integrated-source-" + String(controlId).toLowerCase() + "-" +
      String(citationId).replace(/[^0-9]/g, "");
  }

  function activateCitation(controlId, citationId) {
    const target = document.getElementById(citationDomId(controlId, citationId));
    if (!target) return;
    const details = target.closest("details");
    if (details) details.open = true;
    target.scrollIntoView({behavior: "smooth", block: "center"});
    target.setAttribute("tabindex", "-1");
    target.focus({preventScroll: true});
    target.classList.add("ai-source-highlight");
    window.setTimeout(function () {
      target.classList.remove("ai-source-highlight");
    }, 1400);
  }

  function normalizeIncompleteParagraphs(value) {
    return String(value || "").replace(
      /([^\n])\n{2,}(?=[^\n])/g,
      function (matched, lastCharacter, offset, source) {
        const next = source.slice(offset + matched.length);
        const startsBlock = /^(#{2,6}\s|[-+*]\s|\d+[.)]\s|\|)/.test(next);
        const completed = /[.!?。！？:：)]/.test(lastCharacter);
        return startsBlock || completed ? matched : lastCharacter + " ";
      }
    );
  }

  function moveLeadingCitationsToEnd(value) {
    return String(value || "").replace(
      /(^|\n)(\s*(?:[-+*]\s+|\d+[.)]\s+)?)(\[(?:1|2|3)\](?:\s*\[(?:1|2|3)\])*)\s+([^\n]+)/g,
      function (_match, lineStart, prefix, citations, sentence) {
        return lineStart + prefix + sentence.trimEnd() + citations;
      }
    );
  }

  function normalizeSectionHeadings(value) {
    return String(value || "")
      .replace(/^##\s*(?:\d+\.\s*)?왜 중요한가요\??\s*$/gim, "## 1. 왜 중요한가요?")
      .replace(/^##\s*(?:\d+\.\s*)?이 스위치 결과의 의미\s*$/gim, "## 2. 이 스위치 결과의 의미")
      .replace(/^##\s*(?:\d+\.\s*)?다음에 할 일\s*$/gim, "## 3. 다음에 할 일")
      .replace(/^##\s*(?:\d+\.\s*)?용어(?: 간단)? 설명\s*$/gim, "## 4. 용어 간단 설명");
  }

  function createRenderer(container, controlId, sources) {
    return markdown.createStreamingRenderer(container, {
      throttleMs: 60,
      allowedOrigins: [window.location.origin],
      allowedCitationIds: sources.map(function (item) { return item.citation_id; }),
      onCitationActivate: function (citationId) {
        activateCitation(controlId, citationId);
      },
      sourceTransform: function (source) {
        return moveLeadingCitationsToEnd(
          normalizeSectionHeadings(normalizeIncompleteParagraphs(source))
        );
      }
    });
  }

  function createSources(control) {
    const details = element("details", "integrated-sources switch-ai-sources");
    details.append(element("summary", "", "출처 보기"));
    const sourceList = element("ol", "ai-source-list");
    (control.knowledge_sources || []).forEach(function (source) {
      const item = element("li", "ai-source-item");
      item.id = citationDomId(control.control_id, source.citation_id);
      const heading = element("div", "ai-source-item-heading");
      heading.append(
        element("span", "ai-source-number", source.citation_id),
        element("strong", "", source.display_label || "점검 근거"),
        element("span", "ai-source-grade", source.grade_label || "출처")
      );
      item.append(heading, element("p", "ai-source-limit", source.limitation || ""));
      sourceList.append(item);
    });
    details.append(sourceList);
    return details;
  }

  document.querySelectorAll("[data-control-id]").forEach(function (article) {
    const controlId = article.dataset.controlId;
    const status = article.querySelector(".integrated-card-ai-status");
    const text = article.querySelector(".integrated-ai-text");
    if (!controlId || !status || !text) return;
    cards.set(controlId, {
      article: article,
      status: status,
      text: text,
      sourceDetails: null
    });
  });

  function applyStatusFilter(value) {
    const selected = ["ALL", "PASS", "FAIL", "ERROR", "N/A"].includes(value)
      ? value
      : "ALL";
    integrated.dataset.resultStatus = selected;
    cards.forEach(function (card) {
      card.article.hidden = selected !== "ALL" && card.article.dataset.status !== selected;
    });
    document.querySelectorAll("button[data-switch-result-status]").forEach(function (button) {
      const active = button.dataset.switchResultStatus === selected;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function applyView(value) {
    const selected = ["combined", "results", "ai"].includes(value) ? value : "combined";
    integrated.dataset.resultView = selected;
    aiSummaryPanel.hidden = selected === "results";
    document.querySelectorAll("[data-result-view-button]").forEach(function (button) {
      button.setAttribute(
        "aria-pressed",
        button.dataset.resultViewButton === selected ? "true" : "false"
      );
    });
  }

  function prepareControl(control) {
    const card = cards.get(control.control_id);
    if (!card) return;
    card.article.dataset.aiState = "running";
    card.text.replaceChildren();
    card.text.classList.add("ai-stream-caret");
    card.status.hidden = false;
    card.status.textContent = "설명을 생성하고 있습니다.";
    const sources = Array.isArray(control.knowledge_sources) ? control.knowledge_sources : [];
    if (card.sourceDetails) card.sourceDetails.remove();
    card.sourceDetails = createSources(control);
    card.article.append(card.sourceDetails);
    renderers.set(control.control_id, createRenderer(card.text, control.control_id, sources));
  }

  async function restoreAISnapshot() {
    try {
      const response = await fetch(`/api/v1/switch/audits/${runId}/ai/snapshot`, {
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error("저장된 AI 설명을 불러오지 못했습니다.");
      }
      const snapshot = await response.json();
      if (snapshot.cache_read_error === true) {
        throw new Error("저장된 AI 설명을 확인하지 못했습니다. 다시 확인해 주세요.");
      }
      if (snapshot.available !== true) {
        return false;
      }
      if (
        typeof snapshot.summary !== "string" ||
        !Array.isArray(snapshot.controls) ||
        snapshot.controls.length !== cards.size
      ) {
        throw new Error("저장된 AI 설명의 형식이 올바르지 않습니다.");
      }
      aiSummary.replaceChildren();
      summaryRenderer = createRenderer(aiSummary, "summary", []);
      summaryRenderer.append(snapshot.summary);
      summaryRenderer.complete();
      aiSummaryTitle.textContent = "AI 종합 설명";
      snapshot.controls.forEach(function (entry) {
        if (!entry || !entry.control || typeof entry.content !== "string") {
          throw new Error("저장된 AI 항목 설명의 형식이 올바르지 않습니다.");
        }
        prepareControl(entry.control);
        const renderer = renderers.get(entry.control.control_id);
        const card = cards.get(entry.control.control_id);
        if (!renderer || !card) {
          throw new Error("저장된 AI 항목 설명을 현재 결과와 연결하지 못했습니다.");
        }
        renderer.append(entry.content);
        renderer.complete();
        card.text.classList.remove("ai-stream-caret");
        card.article.setAttribute("aria-busy", "false");
        card.article.dataset.aiState = "completed";
        card.status.hidden = true;
      });
      runState = "completed";
      aiSummaryPanel.setAttribute("aria-busy", "false");
      aiProgress.value = snapshot.total_controls;
      aiProgress.textContent = `${snapshot.total_controls} / ${snapshot.total_controls}`;
      aiCount.textContent = `${snapshot.total_controls} / ${snapshot.total_controls}`;
      aiStatus.textContent = "이 점검에서 이미 생성한 AI 설명을 그대로 불러왔습니다.";
      startButton.hidden = false;
      startButton.textContent = "AI 설명 재생성";
      stopButton.hidden = true;
      return true;
    } catch (reason) {
      runState = "failed";
      aiStatus.textContent = reason.message || "저장된 AI 설명을 확인하지 못했습니다.";
      aiStatus.classList.add("error-text");
      startButton.hidden = false;
      startButton.textContent = "저장된 설명 다시 확인";
      return false;
    }
  }

  function completeVisibleRenderers(stopped) {
    cards.forEach(function (card, controlId) {
      const renderer = renderers.get(controlId);
      if (renderer) renderer.complete();
      card.text.classList.remove("ai-stream-caret");
      card.article.setAttribute("aria-busy", "false");
      if (stopped && card.article.dataset.aiState === "running") {
        card.status.hidden = false;
        card.status.textContent = "설명 생성을 중지했습니다.";
      } else if (!stopped && card.article.dataset.aiState === "completed") {
        card.status.hidden = true;
      }
    });
    if (summaryRenderer) summaryRenderer.complete();
    aiSummary.classList.remove("ai-stream-caret");
    aiSummaryPanel.setAttribute("aria-busy", "false");
  }

  function handle(type, data) {
    if (type === "ANALYSIS_STARTED") {
      aiStatus.textContent = "전체 스위치 점검 결과의 종합 설명을 준비하고 있습니다.";
    } else if (type === "SUMMARY_STARTED") {
      aiSummaryTitle.textContent = "전체 점검 결과를 종합하고 있습니다";
      aiSummary.textContent = "";
      aiSummary.classList.add("ai-stream-caret");
      summaryRenderer = createRenderer(aiSummary, "summary", []);
    } else if (type === "SUMMARY_DELTA" && summaryRenderer) {
      summaryRenderer.append(data.delta);
    } else if (type === "SUMMARY_COMPLETED") {
      if (summaryRenderer) summaryRenderer.complete();
      aiSummary.classList.remove("ai-stream-caret");
      aiSummaryTitle.textContent = "AI 종합 설명";
      aiStatus.textContent = "N-01부터 항목별 상세 설명을 이어서 생성합니다.";
    } else if (type === "SUMMARY_FAILED") {
      if (summaryRenderer) summaryRenderer.complete();
      aiSummary.classList.remove("ai-stream-caret");
      aiSummaryTitle.textContent = aiSummary.textContent.trim()
        ? "AI 종합 설명"
        : "상태별 점검 결과를 기준으로 항목 설명을 계속합니다";
      if (!aiSummary.textContent.trim()) {
        aiSummary.textContent = data.message || "N-01부터 항목별 설명을 계속합니다.";
      }
      aiStatus.textContent = "종합 설명 요청과 별개로 항목별 설명을 생성하고 있습니다.";
    } else if (type === "CONTROL_STARTED") {
      prepareControl(data.control);
      aiStatus.textContent = `${data.control.control_id} 설명을 생성하고 있습니다.`;
    } else if (type === "CONTROL_DELTA") {
      const renderer = renderers.get(data.control_id);
      if (renderer) renderer.append(data.delta);
    } else if (type === "CONTROL_COMPLETED") {
      const renderer = renderers.get(data.control_id);
      const card = cards.get(data.control_id);
      if (renderer) renderer.complete();
      if (card) {
        card.text.classList.remove("ai-stream-caret");
        card.article.setAttribute("aria-busy", "false");
        card.article.dataset.aiState = "completed";
        card.status.hidden = true;
      }
      aiProgress.value = data.completed_controls;
      aiProgress.textContent = `${data.completed_controls} / ${data.total_controls}`;
      aiCount.textContent = `${data.completed_controls} / ${data.total_controls}`;
    } else if (type === "CONTROL_FAILED") {
      const renderer = renderers.get(data.control_id);
      const card = cards.get(data.control_id);
      if (renderer) renderer.complete();
      if (card) {
        card.text.classList.remove("ai-stream-caret");
        card.article.setAttribute("aria-busy", "false");
        card.article.dataset.aiState = "failed";
        card.status.hidden = false;
        card.status.textContent = data.message || "이 항목의 AI 설명을 만들지 못했습니다.";
      }
      aiProgress.value = data.completed_controls;
      aiProgress.textContent = `${data.completed_controls} / ${data.total_controls}`;
      aiCount.textContent = `${data.completed_controls} / ${data.total_controls}`;
    } else if (type === "ANALYSIS_COMPLETED") {
      runState = "completed";
      completeVisibleRenderers(false);
      aiStatus.textContent = data.failed_controls
        ? `항목별 설명 ${data.successful_controls}개를 확인할 수 있고, ${data.failed_controls}개는 다시 시도할 수 있습니다.`
        : `전체 상태와 ${data.total_controls || cards.size}개 항목별 설명을 확인할 수 있습니다.`;
      stopButton.hidden = true;
      startButton.hidden = false;
      startButton.textContent = "AI 설명 재생성";
    } else if (type === "ANALYSIS_CANCELLED") {
      runState = "stopped";
      completeVisibleRenderers(true);
      aiStatus.textContent = "AI 설명 생성을 중단했습니다. 완료된 설명은 그대로 남아 있습니다.";
      stopButton.hidden = true;
      startButton.hidden = false;
      startButton.textContent = "AI 설명 다시 생성하기";
    } else if (type === "FAILED") {
      runState = "failed";
      completeVisibleRenderers(false);
      aiStatus.textContent = data.message || "AI 설명을 완료하지 못했습니다.";
      aiStatus.classList.add("error-text");
      stopButton.hidden = true;
      startButton.hidden = false;
      startButton.textContent = "AI 설명 다시 생성하기";
    }
  }

  async function readStream(response) {
    if (!response.ok || !response.body) {
      throw new Error("AI 설명 연결을 시작하지 못했습니다.");
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    while (true) {
      const chunk = await reader.read();
      buffer += decoder.decode(chunk.value || new Uint8Array(), {stream: !chunk.done});
      const blocks = buffer.replace(/\r\n/g, "\n").split("\n\n");
      buffer = blocks.pop() || "";
      blocks.forEach(function (block) {
        let type = "message";
        const lines = [];
        block.split("\n").forEach(function (line) {
          if (line.startsWith("event: ")) type = line.slice(7);
          if (line.startsWith("data: ")) lines.push(line.slice(6));
        });
        if (lines.length) handle(type, JSON.parse(lines.join("\n")));
      });
      if (chunk.done) break;
    }
    if (runState === "running") {
      throw new Error("AI 설명 연결이 예정보다 일찍 종료되었습니다. 완료된 내용은 그대로 남아 있습니다.");
    }
  }

  async function startAI() {
    runState = "running";
    controller = new AbortController();
    aiSummaryPanel.setAttribute("aria-busy", "true");
    aiStatus.classList.remove("error-text");
    startButton.hidden = true;
    stopButton.disabled = false;
    stopButton.hidden = false;
    try {
      const response = await fetch(`/api/v1/switch/audits/${runId}/ai/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "text/event-stream",
          "X-CSRF-Token": csrf
        },
        body: JSON.stringify({
          profile: "FAST",
          result_context_processing_approved: true
        }),
        signal: controller.signal,
        cache: "no-store"
      });
      await readStream(response);
    } catch (reason) {
      if (reason.name !== "AbortError") {
        handle("FAILED", {message: reason.message});
      }
    }
  }

  document.querySelectorAll("button[data-switch-result-status]").forEach(function (button) {
    button.addEventListener("click", function () {
      applyStatusFilter(button.dataset.switchResultStatus);
    });
  });
  document.querySelectorAll("[data-result-view-button]").forEach(function (button) {
    button.addEventListener("click", function () {
      applyView(button.dataset.resultViewButton);
    });
  });
  startButton.addEventListener("click", function () {
    if (runState === "running") return;
    void startAI();
  });
  stopButton.addEventListener("click", async function () {
    if (runState !== "running") return;
    await fetch(`/api/v1/switch/audits/${runId}/ai/cancel`, {
      method: "POST",
      headers: {"X-CSRF-Token": csrf},
      cache: "no-store"
    });
    runState = "stopped";
    if (controller) controller.abort();
    completeVisibleRenderers(true);
    aiStatus.textContent = "AI 설명 생성을 중단했습니다. 완료된 설명은 그대로 남아 있습니다.";
    stopButton.hidden = true;
    startButton.hidden = false;
    startButton.textContent = "AI 설명 다시 생성하기";
  });

  applyStatusFilter("ALL");
  applyView("combined");
  // Linux 결과 화면과 동일하게, 저장된 설명이 없으면 버튼 없이 바로 생성합니다.
  restoreAISnapshot()
    .then(function (restored) {
      if (!restored) {
        void startAI();
      }
    })
    .catch(function (reason) {
      runState = "failed";
      aiStatus.textContent = reason.message;
      aiStatus.classList.add("error-text");
      stopButton.hidden = false;
      stopButton.textContent = "저장된 설명 다시 확인";
    });
}());
