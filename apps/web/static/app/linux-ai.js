(function () {
  "use strict";

  const runId = document.querySelector('meta[name="linux-run-id"]')?.content || "";
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const status = document.getElementById("linux-ai-status");
  if (!runId || !status) return;

  const controlsTarget = document.getElementById("linux-ai-controls");
  const summaryTarget = document.getElementById("linux-ai-summary");
  const progress = document.getElementById("linux-ai-progress");
  const count = document.getElementById("linux-ai-count");
  const stopButton = document.getElementById("linux-ai-stop");
  const markdown = window.SecAIRestrictedMarkdown;
  const state = new Map();
  const citationIds = ["[1]", "[2]", "[3]"];
  let controller = null;

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function statusLabel(value) {
    return {
      PASS: "양호",
      FAIL: "취약",
      ERROR: "확인 필요",
      REVIEW: "확인 필요",
      "N/A": "해당 없음"
    }[value] || "판정 확인 필요";
  }

  function scrollBehavior() {
    return window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto"
      : "smooth";
  }

  function citationDomId(controlId, citationId) {
    return "linux-ai-source-" + String(controlId).toLowerCase() + "-" +
      String(citationId).replace(/[^0-9]/g, "");
  }

  function activateCitation(controlId, citationId) {
    const target = document.getElementById(citationDomId(controlId, citationId));
    if (!target) return;
    const panel = target.closest("details");
    if (panel) panel.open = true;
    target.scrollIntoView({behavior: scrollBehavior(), block: "center"});
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
      .replace(/^##\s*(?:\d+\.\s*)?이 서버 결과의 의미\s*$/gim, "## 2. 이 서버 결과의 의미")
      .replace(/^##\s*(?:\d+\.\s*)?다음에 할 일\s*$/gim, "## 3. 다음에 할 일")
      .replace(/^##\s*(?:\d+\.\s*)?용어(?: 간단)? 설명\s*$/gim, "## 4. 용어 간단 설명");
  }

  function createLiveRenderer(container, controlId) {
    return markdown.createStreamingRenderer(container, {
      throttleMs: 60,
      allowedOrigins: [window.location.origin],
      allowedCitationIds: citationIds,
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

  function sourcePanel(control) {
    const box = element("details", "linux-ai-sources");
    box.append(element("summary", "", "출처 보기"));
    const list = element("ol", "ai-source-list");
    (control.knowledge_sources || []).forEach(function (source) {
      const item = element("li", "ai-source-item");
      item.id = citationDomId(control.control_id, source.citation_id);
      const heading = element("div", "ai-source-item-heading");
      heading.append(
        element("span", "ai-source-number", source.citation_id),
        element("strong", "", source.display_label),
        element("span", "ai-source-grade", source.grade_label)
      );
      item.append(heading, element("p", "ai-source-limit", source.limitation));
      list.append(item);
    });
    box.append(list);
    return box;
  }

  function createControl(data) {
    const control = data.control;
    const card = element("article", "panel linux-ai-control");
    card.dataset.controlId = control.control_id;
    const header = element("div", "linux-control-heading");
    header.append(
      element("h2", "", `${control.control_id} · ${control.title}`),
      element(
        "span",
        `status-badge status-${String(control.rule_status).toLowerCase()}`,
        statusLabel(control.rule_status)
      )
    );
    const text = element(
      "div",
      "ai-markdown linux-ai-control-text ai-stream-caret",
      "설명을 생성하고 있습니다."
    );
    text.setAttribute("role", "document");
    text.setAttribute("tabindex", "0");
    card.append(header, text, sourcePanel(control));
    controlsTarget.append(card);
    state.set(control.control_id, {
      text: text,
      renderer: createLiveRenderer(text, control.control_id)
    });
    card.scrollIntoView({behavior: scrollBehavior(), block: "nearest"});
  }

  const summaryRenderer = createLiveRenderer(summaryTarget, "summary");

  function handle(type, data) {
    if (type === "ANALYSIS_STARTED") {
      status.textContent = "전체 점검 결과의 종합 설명을 준비하고 있습니다.";
    } else if (type === "CONTROL_STARTED") {
      status.textContent = `${data.control.control_id} 설명을 생성하고 있습니다.`;
      if (!state.has(data.control.control_id)) createControl(data);
    } else if (type === "CONTROL_DELTA") {
      const record = state.get(data.control_id);
      if (record) record.renderer.append(data.delta);
    } else if (type === "CONTROL_COMPLETED") {
      const record = state.get(data.control_id);
      if (record) {
        record.renderer.complete();
        record.text.classList.remove("ai-stream-caret");
      }
      progress.value = data.completed_controls;
      count.textContent = `${data.completed_controls} / ${data.total_controls}`;
    } else if (type === "SUMMARY_STARTED") {
      summaryTarget.textContent = "전체 상태와 조치 우선순위를 생성하고 있습니다.";
      status.textContent = "67개 점검 결과의 전체 상태와 우선 조치를 종합하고 있습니다.";
      summaryTarget.scrollIntoView({behavior: scrollBehavior(), block: "center"});
    } else if (type === "SUMMARY_DELTA") {
      summaryRenderer.append(data.delta);
    } else if (type === "SUMMARY_COMPLETED") {
      summaryRenderer.complete();
      summaryTarget.classList.remove("ai-stream-caret");
      status.textContent = "전체 종합 설명을 완료했습니다. U-01부터 상세 설명을 시작합니다.";
    } else if (type === "ANALYSIS_COMPLETED") {
      summaryRenderer.complete();
      summaryTarget.classList.remove("ai-stream-caret");
      state.forEach(function (record) {
        record.text.classList.remove("ai-stream-caret");
      });
      status.textContent = "전체 종합 설명과 67개 항목별 상세 설명을 완료했습니다.";
      stopButton.disabled = true;
    } else if (type === "ANALYSIS_CANCELLED") {
      summaryTarget.classList.remove("ai-stream-caret");
      state.forEach(function (record) {
        record.text.classList.remove("ai-stream-caret");
      });
      status.textContent = "AI 설명 생성을 중단했습니다. 완료된 설명은 그대로 남아 있습니다.";
      stopButton.textContent = "설명 다시 시작";
    } else if (type === "FAILED") {
      summaryTarget.classList.remove("ai-stream-caret");
      state.forEach(function (record) {
        record.text.classList.remove("ai-stream-caret");
      });
      status.textContent = data.message || "AI 설명을 완료하지 못했습니다.";
      status.classList.add("error-text");
      stopButton.textContent = "설명 다시 시작";
    }
  }

  async function readStream(response, callback) {
    if (!response.ok || !response.body) {
      throw new Error("스트림 연결을 시작하지 못했습니다.");
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
        if (lines.length) callback(type, JSON.parse(lines.join("\n")));
      });
      if (chunk.done) break;
    }
  }

  async function start() {
    controller = new AbortController();
    status.classList.remove("error-text");
    stopButton.textContent = "설명 생성 멈추기";
    stopButton.disabled = false;
    try {
      const response = await fetch(`/api/v1/linux/audits/${runId}/ai/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "text/event-stream",
          "X-CSRF-Token": csrf
        },
        body: JSON.stringify({profile: "FAST"}),
        signal: controller.signal,
        cache: "no-store"
      });
      await readStream(response, handle);
    } catch (reason) {
      if (reason.name !== "AbortError") {
        status.textContent = reason.message;
        status.classList.add("error-text");
      }
    }
  }

  stopButton.addEventListener("click", async function () {
    if (stopButton.textContent.includes("다시")) {
      window.location.reload();
      return;
    }
    await fetch(`/api/v1/linux/audits/${runId}/ai/cancel`, {
      method: "POST",
      headers: {"X-CSRF-Token": csrf},
      cache: "no-store"
    });
    if (controller) controller.abort();
    status.textContent = "설명 생성을 중단했습니다. 완료된 항목은 다시 생성하지 않습니다.";
    stopButton.textContent = "설명 다시 시작";
  });

  document.getElementById("linux-follow-up-send").addEventListener("click", async function () {
    const question = document.getElementById("linux-follow-up-question").value.trim();
    const answer = document.getElementById("linux-follow-up-answer");
    if (!question) return;
    const followUpRenderer = createLiveRenderer(answer, "follow-up");
    answer.textContent = "답변을 준비하고 있습니다.";
    const response = await fetch(`/api/v1/linux/audits/${runId}/follow-up/stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({question: question}),
      cache: "no-store"
    });
    await readStream(response, function (type, data) {
      if (type === "DELTA") followUpRenderer.append(data.delta);
      if (type === "COMPLETED") followUpRenderer.complete();
      if (type === "FAILED") answer.textContent = "후속 답변을 생성하지 못했습니다.";
    });
  });

  start();
}());
