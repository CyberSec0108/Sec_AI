(function () {
  "use strict";

  const payloadKey = "secai_ai_analysis_payload";
  const csrfToken = document.querySelector('meta[name="csrf-token"]');
  const status = document.getElementById("ai-stream-status");
  const count = document.getElementById("ai-stream-count");
  const progress = document.getElementById("ai-stream-progress");
  const stopButton = document.getElementById("ai-stream-stop");
  const controls = document.getElementById("ai-control-stream");
  const summaryTitle = document.getElementById("ai-summary-title");
  const summaryText = document.getElementById("ai-summary-text");
  const summaryPanel = document.getElementById("ai-summary-panel");
  const markdown = window.SecAIRestrictedMarkdown;
  const cards = new Map();
  let summaryRenderer = null;
  let activeController = null;
  let activeReader = null;
  let runState = "idle";

  function element(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    if (typeof text === "string") {
      node.textContent = text;
    }
    return node;
  }

  function statusLabel(value) {
    return {
      PASS: "양호",
      FAIL: "취약",
      ERROR: "수집 오류",
      REVIEW: "기준 확인 필요",
      "N/A": "해당 없음"
    }[value] || "판정 확인 필요";
  }

  function citationLabel(citation) {
    if (!citation || !Number.isInteger(citation.pdf_page_number)) {
      return "KISA 근거 위치를 추가로 확인해야 합니다.";
    }
    return "KISA " + citation.pdf_page_number + "쪽 · " +
      (citation.section_label || "PC 보안 점검 기준");
  }

  function citationDomId(controlId, citationId) {
    return "ai-source-" + String(controlId).toLowerCase() + "-" +
      String(citationId).replace(/[^0-9]/g, "");
  }

  function activateCitation(controlId, citationId) {
    const target = document.getElementById(citationDomId(controlId, citationId));
    if (!target) {
      return;
    }
    target.scrollIntoView({behavior: scrollBehavior(), block: "center"});
    target.setAttribute("tabindex", "-1");
    target.focus({preventScroll: true});
    target.classList.add("ai-source-highlight");
    window.setTimeout(function () {
      target.classList.remove("ai-source-highlight");
    }, 1400);
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
      .replace(/^##\s*(?:\d+\.\s*)?내 PC 결과의 의미\s*$/gim, "## 2. 내 PC 결과의 의미")
      .replace(/^##\s*(?:\d+\.\s*)?다음에 할 일\s*$/gim, "## 3. 다음에 할 일")
      .replace(/^##\s*(?:\d+\.\s*)?용어(?: 간단)? 설명\s*$/gim, "## 4. 용어 간단 설명");
  }

  function createMarkdownRenderer(container, controlId, sources) {
    return markdown.createStreamingRenderer(container, {
      allowedOrigins: [window.location.origin],
      allowedCitationIds: sources.map(function (item) {
        return item.citation_id;
      }),
      onCitationActivate: function (citationId) {
        activateCitation(controlId, citationId);
      },
      sourceTransform: function (source) {
        return moveLeadingCitationsToEnd(normalizeSectionHeadings(source));
      }
    });
  }

  function createSourceList(control) {
    const section = element("section", "ai-source-section");
    section.setAttribute("aria-label", control.control_id + " 설명 출처");
    section.appendChild(element("h3", "ai-source-title", "출처"));
    const intro = element(
      "p",
      "ai-source-intro",
      "본문 문장 뒤의 출처 번호를 선택하면 해당 근거를 확인할 수 있습니다."
    );
    section.appendChild(intro);
    const list = element("ol", "ai-source-list");
    (control.knowledge_sources || []).forEach(function (source) {
      const item = element("li", "ai-source-item");
      item.id = citationDomId(control.control_id, source.citation_id);
      const heading = element("div", "ai-source-item-heading");
      heading.appendChild(
        element("span", "ai-source-number", source.citation_id)
      );
      heading.appendChild(
        element("strong", "", source.display_label || source.title_ko)
      );
      heading.appendChild(
        element("span", "ai-source-grade", source.grade_label || "출처")
      );
      item.appendChild(heading);
      item.appendChild(
        element("p", "ai-source-limit", source.limitation || "")
      );
      list.appendChild(item);
    });
    section.appendChild(list);
    return section;
  }

  function scrollBehavior() {
    return window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? "auto"
      : "smooth";
  }

  function createControlCard(control, index) {
    const sources = Array.isArray(control.knowledge_sources)
      ? control.knowledge_sources
      : [];
    const article = element("article", "panel ai-control-stream-card");
    article.dataset.controlId = control.control_id;
    article.setAttribute("aria-busy", "true");
    const heading = element("div", "ai-control-stream-heading");
    const copy = element("div", "");
    copy.appendChild(
      element("p", "section-label", "항목 " + index + " / 18")
    );
    copy.appendChild(
      element("h2", "", control.control_id + " · " + control.title)
    );
    heading.appendChild(copy);
    heading.appendChild(
      element(
        "span",
        "status status-" + String(control.rule_status).toLowerCase(),
        statusLabel(control.rule_status)
      )
    );
    article.appendChild(heading);

    const facts = element("dl", "ai-control-facts");
    [
      ["공식 판정", statusLabel(control.rule_status) + " (규칙 엔진)"],
      ["무엇을 확인했나요", control.what_was_checked],
      ["내 PC에서 확인한 값", control.observed_summary],
      ["판정 기준", control.expected_summary],
      ["KISA 근거", sources[2] ? sources[2].display_label : citationLabel(control.citation)]
    ].forEach(function (entry) {
      const row = element("div", "");
      row.appendChild(element("dt", "", entry[0]));
      row.appendChild(element("dd", "", entry[1] || "확인 중"));
      facts.appendChild(row);
    });
    article.appendChild(facts);
    article.appendChild(element("h3", "ai-stream-answer-title", "상세 설명 생성 중"));
    const answer = element(
      "div",
      "ai-stream-text ai-markdown ai-stream-caret",
      ""
    );
    answer.setAttribute("role", "document");
    answer.setAttribute("aria-label", control.control_id + " 상세 설명 내용");
    answer.setAttribute("aria-live", "off");
    answer.setAttribute("tabindex", "0");
    article.appendChild(answer);
    article.appendChild(createSourceList(control));
    controls.appendChild(article);
    cards.set(control.control_id, {
      article: article,
      answer: answer,
      renderer: createMarkdownRenderer(answer, control.control_id, sources)
    });
    article.scrollIntoView({behavior: scrollBehavior(), block: "center"});
  }

  function handleEvent(event) {
    if (event.stage === "ANALYSIS_STARTED") {
      status.textContent = "전체 점검 결과의 종합 설명을 준비하고 있습니다.";
      return;
    }
    if (event.stage === "SEARCHING_KISA_EVIDENCE") {
      status.textContent = "종합 설명과 항목별 설명에 필요한 KISA 근거를 찾고 있습니다.";
      return;
    }
    if (event.stage === "CONTROL_STARTED") {
      createControlCard(event.control, event.control_index);
      status.textContent = event.control.control_id + " 설명을 생성하고 있습니다.";
      return;
    }
    if (event.stage === "CONTROL_DELTA") {
      const card = cards.get(event.control_id);
      if (card && typeof event.delta === "string") {
        card.renderer.append(event.delta);
      }
      return;
    }
    if (event.stage === "CONTROL_COMPLETED") {
      const card = cards.get(event.control_id);
      if (card) {
        card.renderer.complete();
        card.article.setAttribute("aria-busy", "false");
        card.answer.classList.remove("ai-stream-caret");
        const heading = card.article.querySelector(".ai-stream-answer-title");
        if (heading) {
          heading.textContent = "상세 설명";
        }
      }
      progress.value = event.completed_controls;
      progress.textContent = event.completed_controls + " / 18";
      count.textContent = event.completed_controls + " / 18";
      status.textContent = event.completed_controls < 18
        ? "다음 항목을 순서대로 준비하고 있습니다. " +
          event.completed_controls + " / 18"
        : "";
      return;
    }
    if (event.stage === "SUMMARY_STARTED") {
      summaryTitle.textContent = "전체 점검 결과를 종합하고 있습니다";
      summaryText.textContent = "";
      summaryRenderer = createMarkdownRenderer(summaryText, "summary", []);
      summaryText.classList.add("ai-stream-caret");
      summaryPanel.setAttribute("aria-busy", "true");
      status.textContent = "18개 항목의 관계와 우선 조치를 종합하고 있습니다.";
      summaryPanel.scrollIntoView({
        behavior: scrollBehavior(),
        block: "center"
      });
      return;
    }
    if (event.stage === "SUMMARY_DELTA" && typeof event.delta === "string") {
      if (summaryRenderer) {
        summaryRenderer.append(event.delta);
      }
      return;
    }
    if (event.stage === "SUMMARY_COMPLETED") {
      if (summaryRenderer) {
        summaryRenderer.complete();
      }
      summaryTitle.textContent = "AI 종합 설명";
      summaryText.classList.remove("ai-stream-caret");
      summaryPanel.setAttribute("aria-busy", "false");
      status.textContent = "PC-01부터 상세 설명을 순서대로 생성합니다.";
      return;
    }
    if (event.stage === "ANALYSIS_COMPLETED") {
      runState = "completed";
      status.textContent = "";
      status.hidden = true;
      status.classList.remove("error-text");
      if (stopButton) {
        stopButton.hidden = true;
        stopButton.disabled = true;
      }
      return;
    }
    if (event.stage === "FAILED") {
      const detail = event.detail || {};
      throw new Error(
        detail.message || "AI 설명을 생성하지 못했습니다. 공식 점검 결과는 그대로입니다."
      );
    }
  }

  function completeVisibleRenderers() {
    cards.forEach(function (card) {
      card.renderer.complete();
      card.article.setAttribute("aria-busy", "false");
      card.answer.classList.remove("ai-stream-caret");
      const heading = card.article.querySelector(".ai-stream-answer-title");
      if (heading && heading.textContent === "상세 설명 생성 중") {
        heading.textContent = "상세 설명 (생성 중지)";
      }
    });
    if (summaryRenderer) {
      summaryRenderer.complete();
      summaryText.classList.remove("ai-stream-caret");
      summaryPanel.setAttribute("aria-busy", "false");
    }
  }

  function stopStream() {
    if (runState !== "running") {
      return;
    }
    runState = "stopped";
    if (activeReader) {
      void activeReader.cancel().catch(function () {});
    }
    if (activeController) {
      activeController.abort();
    }
    completeVisibleRenderers();
    status.classList.remove("error-text");
    status.textContent =
      "AI 상세 설명 생성을 멈췄습니다. 이미 생성된 설명은 그대로 확인할 수 있습니다.";
    if (stopButton) {
      stopButton.textContent = "설명 다시 시작";
      stopButton.disabled = false;
    }
  }

  if (stopButton) {
    stopButton.addEventListener("click", function () {
      if (runState === "running") {
        stopStream();
        return;
      }
      if (runState === "stopped" || runState === "failed") {
        window.location.reload();
      }
    });
  }

  async function start() {
    let payload;
    try {
      payload = JSON.parse(window.sessionStorage.getItem(payloadKey) || "null");
    } catch (_error) {
      payload = null;
    }
    if (!payload || !Array.isArray(payload.explanation_inputs)) {
      status.textContent = "설명할 점검 결과가 없습니다. 먼저 원클릭 점검을 실행해 주세요.";
      if (stopButton) {
        stopButton.disabled = true;
      }
      return;
    }
    runState = "running";
    activeController = new AbortController();
    status.classList.remove("error-text");
    status.hidden = false;
    if (stopButton) {
      stopButton.textContent = "설명 생성 멈추기";
      stopButton.hidden = false;
      stopButton.disabled = false;
    }
    try {
      const response = await window.fetch(
        "/api/v1/result-explanations/from-scan/token-stream",
        {
          method: "POST",
          headers: {
            Accept: "text/event-stream",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken ? csrfToken.content : ""
          },
          body: JSON.stringify({
            explanation_inputs: payload.explanation_inputs,
            administrator_results: payload.administrator_results || [],
            profile: "FAST",
            test_environment_result: true
          }),
          cache: "no-store",
          signal: activeController.signal
        }
      );
      if (!response.ok || !response.body) {
        throw new Error("AI 설명 연결을 시작하지 못했습니다.");
      }
      const reader = response.body.getReader();
      activeReader = reader;
      const decoder = new TextDecoder("utf-8");
      let buffer = "";
      while (true) {
        const chunk = await reader.read();
        buffer += decoder.decode(chunk.value || new Uint8Array(), {
          stream: !chunk.done
        });
        const blocks = buffer.replace(/\r\n/g, "\n").split("\n\n");
        buffer = blocks.pop() || "";
        blocks.forEach(function (block) {
          const data = block.split("\n").filter(function (line) {
            return line.startsWith("data: ");
          }).map(function (line) {
            return line.slice(6);
          }).join("\n");
          if (data) {
            handleEvent(JSON.parse(data));
          }
        });
        if (chunk.done) {
          break;
        }
      }
      if (runState === "running") {
        throw new Error(
          "AI 설명 연결이 완료 신호 없이 종료되었습니다. 생성된 내용은 그대로 확인할 수 있습니다."
        );
      }
    } catch (streamError) {
      if (runState === "stopped" || streamError.name === "AbortError") {
        return;
      }
      runState = "failed";
      completeVisibleRenderers();
      status.textContent = streamError.message ||
        "AI 설명 연결이 중단되었습니다. 상세 점검 결과는 그대로 확인할 수 있습니다.";
      status.classList.add("error-text");
      if (stopButton) {
        stopButton.textContent = "설명 다시 시작";
        stopButton.disabled = false;
      }
    } finally {
      activeReader = null;
      activeController = null;
    }
  }

  void start();
}());
