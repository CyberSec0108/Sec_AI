(function () {
  "use strict";

  const panel = document.getElementById("integrated-results-panel");
  const list = document.getElementById("control-results");
  const summary = document.getElementById("ai-integrated-summary");
  const summaryTitle = document.getElementById("ai-integrated-summary-title");
  const summaryStatus = document.getElementById("ai-integrated-status");
  const summaryProgress = document.getElementById("ai-integrated-progress");
  const summaryText = document.getElementById("ai-integrated-summary-text");
  const stopButton = document.getElementById("ai-integrated-stop");
  const csrfToken = document.querySelector('meta[name="csrf-token"]');
  const markdown = window.SecAIRestrictedMarkdown;
  const completedSnapshotPrefix = "secai_result_ai_screen_v1:";
  const cards = new Map();
  const renderers = new Map();
  const controlSources = new Map();
  const controlMetadata = new Map();
  const termDefinitions = Object.freeze({
    NTFS: "Windows에서 파일별 접근 권한과 암호화 기능을 지원하는 파일 시스템입니다.",
    FAT32: "오래된 호환 중심 파일 시스템으로, NTFS의 세밀한 접근 권한 기능을 지원하지 않습니다.",
    AutoAdminLogon: "Windows가 비밀번호 입력 없이 지정된 계정으로 자동 로그인하는 설정입니다.",
    BitLocker: "저장 장치를 암호화해 분실이나 탈취 때 자료가 바로 노출되지 않도록 돕는 기능입니다.",
    UAC: "관리자 권한이 필요한 작업 전에 Windows가 사용자에게 승인을 요청하는 보호 기능입니다."
  });
  let latest = null;
  let activeController = null;
  let activeReader = null;
  let runState = "idle";
  let generationKey = "";
  let summaryRenderer = null;
  let summarySource = "";

  if (!panel || !list || !summary || !stopButton) {
    return;
  }

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

  function normalizeStatus(value) {
    return value || "ERROR";
  }

  function statusLabel(value) {
    return {
      PASS: "양호",
      FAIL: "취약",
      ERROR: "수집 오류",
      REVIEW: "기준 확인 필요",
      "N/A": "해당 없음"
    }[normalizeStatus(value)] || "확인 필요";
  }

  function statusClass(value) {
    const status = normalizeStatus(value);
    return "integrated-status-" + status.toLowerCase();
  }

  function asText(value, fallback) {
    if (Array.isArray(value)) {
      return value.filter(Boolean).join(" · ") || fallback;
    }
    return typeof value === "string" && value.trim() ? value.trim() : fallback;
  }

  function buildGenerationKey(detail) {
    const administratorResults = (detail.administrator_results || []).slice().sort(
      function (left, right) {
        return String(left.control_id || "").localeCompare(
          String(right.control_id || ""),
          "en",
          {numeric: true}
        );
      }
    );
    return String(detail.result_id) + ":" + String(detail.result_version) + ":" +
      administratorResults.map(function (item) {
        return item.control_id + ":" +
          (item.collection_status || "") + ":" +
          (item.assessment_status || item.display_status || "");
      }).join(",");
  }

  function completedSnapshotStorageKey(key) {
    return completedSnapshotPrefix + encodeURIComponent(key);
  }

  function validatedCompletedSnapshot(snapshot, key) {
    if (
      !snapshot ||
      snapshot.version !== 1 ||
      snapshot.generation_key !== key ||
      typeof snapshot.summary_source !== "string" ||
      !snapshot.summary_source.trim() ||
      snapshot.summary_source.length > 100000 ||
      !Array.isArray(snapshot.controls) ||
      snapshot.controls.length !== 18
    ) {
      return null;
    }
    const controlIds = new Set();
    const valid = snapshot.controls.every(function (control) {
      if (
        !control ||
        typeof control.control_id !== "string" ||
        typeof control.source !== "string" ||
        !control.source.trim() ||
        control.source.length > 100000 ||
        !Array.isArray(control.knowledge_sources)
      ) {
        return false;
      }
      controlIds.add(control.control_id);
      return true;
    });
    return valid && controlIds.size === 18 &&
      Array.from(controlIds).every(function (controlId) {
        return cards.has(controlId);
      })
      ? snapshot
      : null;
  }

  function readCompletedSnapshot(key) {
    const storageKey = completedSnapshotStorageKey(key);
    try {
      const snapshot = JSON.parse(window.localStorage.getItem(storageKey) || "null");
      return validatedCompletedSnapshot(snapshot, key);
    } catch (_error) {
      try {
        window.localStorage.removeItem(storageKey);
      } catch (_storageError) {
        // 저장소가 차단된 경우 잘못된 항목을 무시합니다.
      }
      return null;
    }
  }

  function saveCompletedSnapshot() {
    if (!generationKey || !summarySource.trim() || controlSources.size !== 18) {
      return;
    }
    const controls = Array.from(controlSources.keys()).sort(function (left, right) {
      return left.localeCompare(right, "en", {numeric: true});
    }).map(function (controlId) {
      const metadata = controlMetadata.get(controlId) || {};
      return {
        control_id: controlId,
        source: controlSources.get(controlId) || "",
        knowledge_sources: Array.isArray(metadata.knowledge_sources)
          ? metadata.knowledge_sources
          : []
      };
    });
    const snapshot = {
      version: 1,
      generation_key: generationKey,
      summary_source: summarySource,
      controls: controls
    };
    try {
      window.localStorage.setItem(
        completedSnapshotStorageKey(generationKey),
        JSON.stringify(snapshot)
      );
    } catch (_error) {
      // 브라우저 저장 공간을 사용할 수 없으면 현재 화면만 유지합니다.
    }
    if (latest) {
      window.dispatchEvent(new CustomEvent(
        "secai:windows-ai-snapshot-completed",
        {
          detail: {
            result_id: latest.result_id,
            result_version: latest.result_version,
            ai_screen: snapshot
          }
        }
      ));
    }
  }

  function explanationMap(items) {
    return new Map((items || []).map(function (item) {
      return [item.control_id, item];
    }));
  }

  function sortControlsById(items) {
    return (items || []).slice().sort(function (left, right) {
      return String(left.control_id || "").localeCompare(
        String(right.control_id || ""),
        "en",
        {numeric: true}
      );
    });
  }

  function addFact(listNode, label, value) {
    const row = element("div", "integrated-fact");
    row.appendChild(element("dt", "", label));
    row.appendChild(element("dd", "", value));
    listNode.appendChild(row);
  }

  function findTerms(values) {
    const joined = values.filter(Boolean).join(" ");
    return Object.keys(termDefinitions).filter(function (term) {
      return joined.includes(term);
    });
  }

  function createTerms(values) {
    const terms = findTerms(values);
    if (!terms.length) {
      return null;
    }
    const details = element("details", "integrated-term-details");
    details.appendChild(element("summary", "", "용어 간단 설명"));
    const definitions = element("dl", "integrated-term-list");
    terms.forEach(function (term) {
      definitions.appendChild(element("dt", "term-token", term));
      definitions.appendChild(element("dd", "", termDefinitions[term]));
    });
    details.appendChild(definitions);
    return details;
  }

  function sourceDomId(controlId, citationId) {
    return "integrated-source-" + String(controlId).toLowerCase() + "-" +
      String(citationId).replace(/[^0-9]/g, "");
  }

  function activateCitation(controlId, citationId) {
    const source = document.getElementById(sourceDomId(controlId, citationId));
    if (!source) {
      return;
    }
    const details = source.closest("details");
    if (details) {
      details.open = true;
    }
    source.setAttribute("tabindex", "-1");
    source.scrollIntoView({behavior: "smooth", block: "center"});
    source.focus({preventScroll: true});
    source.classList.add("ai-source-highlight");
    window.setTimeout(function () {
      source.classList.remove("ai-source-highlight");
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

  function createRenderer(container, controlId, sources) {
    return markdown.createStreamingRenderer(container, {
      throttleMs: 60,
      allowedOrigins: [window.location.origin],
      allowedCitationIds: sources.map(function (source) {
        return source.citation_id;
      }),
      onCitationActivate: function (citationId) {
        activateCitation(controlId, citationId);
      },
      sourceTransform: function (source) {
        return moveLeadingCitationsToEnd(normalizeSectionHeadings(source));
      }
    });
  }

  function createSources(control) {
    const details = element("details", "integrated-sources");
    details.appendChild(element("summary", "", "출처 보기"));
    const listNode = element("ol", "ai-source-list");
    (control.knowledge_sources || []).forEach(function (source) {
      const item = element("li", "ai-source-item");
      item.id = sourceDomId(control.control_id, source.citation_id);
      const heading = element("div", "ai-source-item-heading");
      heading.appendChild(element("span", "ai-source-number", source.citation_id));
      heading.appendChild(element(
        "strong",
        "",
        source.display_label || source.title_ko || "점검 근거"
      ));
      heading.appendChild(element("span", "ai-source-grade", source.grade_label || "출처"));
      item.appendChild(heading);
      if (source.limitation) {
        item.appendChild(element("p", "ai-source-limit", source.limitation));
      }
      listNode.appendChild(item);
    });
    details.appendChild(listNode);
    return details;
  }

  function createCard(item, explanation, index) {
    const status = normalizeStatus(item.assessment_status || item.display_status);
    const article = element("article", "integrated-control-card " + statusClass(status));
    article.dataset.controlId = item.control_id;
    article.dataset.status = status;
    const heading = element("header", "integrated-control-heading");
    const copy = element("div", "");
    copy.appendChild(element("p", "section-label", "항목 " + index + " / 18"));
    copy.appendChild(element("h3", "", item.control_id + " · " + item.title));
    heading.appendChild(copy);
    heading.appendChild(element("span", "status " + statusClass(status), statusLabel(status)));
    article.appendChild(heading);

    const resultSection = element("section", "integrated-result-section");
    resultSection.setAttribute("aria-label", item.control_id + " 점검 결과");
    const facts = element("dl", "integrated-facts");
    const administratorVerified = item.administrator_verified === true;
    const checked = administratorVerified
      ? asText(
        item.checked_summary,
        asText(
          explanation && explanation.what_was_checked,
          "확인한 항목을 불러오지 못했습니다."
        )
      )
      : asText(
        explanation && explanation.what_was_checked,
        asText(item.checked_summary, "확인한 항목을 불러오지 못했습니다.")
      );
    const observed = administratorVerified
      ? asText(
        item.actual,
        asText(
          item.collected_summary,
          asText(
            explanation && explanation.observed_summary,
            "확인값을 불러오지 못했습니다."
          )
        )
      )
      : asText(
        explanation && explanation.observed_summary,
        asText(item.actual, "확인값을 불러오지 못했습니다.")
      );
    const expected = administratorVerified
      ? asText(
        item.expected,
        asText(explanation && explanation.expected_summary, "KISA 기본 기준")
      )
      : asText(
        explanation && explanation.expected_summary,
        asText(item.expected, "KISA 기본 기준")
      );
    const judgement = administratorVerified
      ? asText(
        item.judgement_explanation,
        asText(
          explanation && explanation.judgement_explanation,
          statusLabel(status) + "로 판정했습니다."
        )
      )
      : asText(
        explanation && explanation.judgement_explanation,
        asText(item.judgement_explanation, statusLabel(status) + "로 판정했습니다.")
      );
    addFact(facts, "무엇을 확인했나요", checked);
    addFact(facts, "내 PC에서 확인한 값", observed);
    addFact(facts, "KISA 권고 기준", expected);
    addFact(facts, "판정 이유", judgement);
    resultSection.appendChild(facts);
    const terms = createTerms([checked, observed, expected, judgement]);
    if (terms) {
      resultSection.appendChild(terms);
    }
    article.appendChild(resultSection);

    const aiSection = element("section", "integrated-ai-section");
    aiSection.setAttribute("aria-label", item.control_id + " AI 상세 설명");
    aiSection.appendChild(element("h4", "integrated-ai-title", "AI 상세 설명"));
    const aiStatus = element("p", "integrated-card-ai-status", "AI 설명을 준비하고 있습니다.");
    const aiText = element("div", "integrated-ai-text ai-markdown", "");
    aiText.setAttribute("role", "document");
    aiSection.appendChild(aiStatus);
    aiSection.appendChild(aiText);
    article.appendChild(aiSection);
    list.appendChild(article);
    cards.set(item.control_id, {
      article: article,
      status: aiStatus,
      text: aiText,
      sourceDetails: null
    });
  }

  function renderCards(detail) {
    list.replaceChildren();
    cards.clear();
    renderers.clear();
    const explanations = explanationMap(detail.explanations);
    const sortedItems = sortControlsById(detail.items);
    sortedItems.forEach(function (item, index) {
      createCard(item, explanations.get(item.control_id), index + 1);
    });
    const count = sortedItems.reduce(function (result, item) {
      const status = normalizeStatus(item.assessment_status || item.display_status);
      result.ALL += 1;
      result[status] = (result[status] || 0) + 1;
      return result;
    }, {ALL: 0, PASS: 0, FAIL: 0, ERROR: 0, REVIEW: 0});
    const ids = {
      ALL: "count-total",
      PASS: "count-pass",
      FAIL: "count-fail",
      ERROR: "count-error",
      REVIEW: "count-review"
    };
    Object.keys(ids).forEach(function (key) {
      const target = document.getElementById(ids[key]);
      if (target) {
        target.textContent = String(count[key] || 0);
      }
    });
    applyFilter(panel.dataset.resultStatus || "ALL");
  }

  function applyView(value) {
    const selected = ["combined", "results", "ai"].includes(value) ? value : "combined";
    panel.dataset.resultView = selected;
    document.querySelectorAll("[data-result-view-button]").forEach(function (button) {
      button.setAttribute(
        "aria-pressed",
        button.dataset.resultViewButton === selected ? "true" : "false"
      );
    });
  }

  function applyFilter(value) {
    const selected = ["ALL", "PASS", "FAIL", "ERROR", "REVIEW"].includes(value)
      ? value
      : "ALL";
    panel.dataset.resultStatus = selected;
    cards.forEach(function (card) {
      card.article.hidden = selected !== "ALL" && card.article.dataset.status !== selected;
    });
    document.querySelectorAll("button[data-result-status]").forEach(function (button) {
      const active = button.dataset.resultStatus === selected;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function prepareControl(control) {
    const card = cards.get(control.control_id);
    if (!card) {
      return;
    }
    card.text.replaceChildren();
    card.status.hidden = false;
    card.status.textContent = "설명을 생성하고 있습니다.";
    const sources = Array.isArray(control.knowledge_sources)
      ? control.knowledge_sources
      : [];
    const sourceDetails = createSources(control);
    card.sourceDetails = sourceDetails;
    card.article.appendChild(sourceDetails);
    renderers.set(
      control.control_id,
      createRenderer(card.text, control.control_id, sources)
    );
  }

  async function loadServerCompletedSnapshot(detail) {
    const nextKey = buildGenerationKey(detail);
    try {
      const query = new URLSearchParams({
        result_id: detail.result_id,
        result_version: String(detail.result_version)
      });
      const response = await window.fetch(
        "/api/v1/audit-history/windows/presentation?" + query.toString(),
        {method: "GET", cache: "no-store"}
      );
      if (!response.ok) {
        return null;
      }
      const payload = await response.json();
      return validatedCompletedSnapshot(payload.ai_screen, nextKey);
    } catch (_error) {
      return null;
    }
  }

  function restoreCompletedSnapshot(detail, preferredSnapshot) {
    const nextKey = buildGenerationKey(detail);
    const snapshot = preferredSnapshot
      ? validatedCompletedSnapshot(preferredSnapshot, nextKey)
      : readCompletedSnapshot(nextKey);
    if (!snapshot) {
      return false;
    }
    generationKey = nextKey;
    runState = "completed";
    summarySource = snapshot.summary_source;
    controlSources.clear();
    controlMetadata.clear();
    summary.hidden = false;
    summaryTitle.textContent = "AI 종합 설명";
    summaryText.replaceChildren();
    summaryRenderer = createRenderer(summaryText, "summary", []);
    summaryRenderer.append(summarySource);
    summaryRenderer.complete();
    snapshot.controls.forEach(function (control) {
      controlMetadata.set(control.control_id, control);
      controlSources.set(control.control_id, control.source);
      prepareControl(control);
      const renderer = renderers.get(control.control_id);
      const card = cards.get(control.control_id);
      if (renderer) {
        renderer.append(control.source);
        renderer.complete();
      }
      if (card) {
        card.status.textContent = "";
        card.status.hidden = true;
      }
    });
    summaryProgress.value = 18;
    summaryProgress.textContent = "18 / 18";
    summaryStatus.textContent = "";
    summaryStatus.hidden = true;
    stopButton.textContent = "AI 설명 재생성";
    stopButton.hidden = false;
    stopButton.disabled = false;
    return true;
  }

  async function restoreAvailableCompletedSnapshot(detail) {
    const expectedKey = buildGenerationKey(detail);
    const serverSnapshot = await loadServerCompletedSnapshot(detail);
    if (latest !== detail || buildGenerationKey(latest) !== expectedKey) {
      return false;
    }
    if (serverSnapshot && restoreCompletedSnapshot(detail, serverSnapshot)) {
      return true;
    }
    if (restoreCompletedSnapshot(detail)) {
      return true;
    }
    return false;
  }

  function completeRenderers(stopped) {
    renderers.forEach(function (renderer, controlId) {
      renderer.complete();
      const card = cards.get(controlId);
      if (card && stopped && !card.status.hidden) {
        card.status.textContent = "설명 생성을 중지했습니다.";
      }
    });
    if (summaryRenderer) {
      summaryRenderer.complete();
    }
  }

  function handleEvent(event) {
    if (event.stage === "ANALYSIS_STARTED") {
      summary.hidden = false;
      summaryStatus.textContent = "점검 결과와 KISA 근거를 정리하고 있습니다.";
    } else if (event.stage === "SEARCHING_KISA_EVIDENCE") {
      summaryStatus.textContent = "각 항목에 맞는 KISA 근거를 찾고 있습니다.";
    } else if (event.stage === "SUMMARY_STARTED") {
      summaryTitle.textContent = "전체 점검 결과를 종합하고 있습니다";
      summaryText.replaceChildren();
      summarySource = "";
      summaryRenderer = createRenderer(summaryText, "summary", []);
    } else if (event.stage === "SUMMARY_DELTA" && summaryRenderer) {
      const delta = event.delta || "";
      summarySource += delta;
      summaryRenderer.append(delta);
    } else if (event.stage === "SUMMARY_COMPLETED") {
      if (summaryRenderer) {
        summaryRenderer.complete();
      }
      summaryTitle.textContent = "AI 종합 설명";
      summaryStatus.textContent = "PC-01부터 항목별 설명을 순서대로 생성합니다.";
    } else if (event.stage === "CONTROL_STARTED") {
      controlMetadata.set(event.control.control_id, {
        control_id: event.control.control_id,
        knowledge_sources: Array.isArray(event.control.knowledge_sources)
          ? event.control.knowledge_sources
          : []
      });
      controlSources.set(event.control.control_id, "");
      prepareControl(event.control);
      summaryStatus.textContent = event.control.control_id + " 설명을 생성하고 있습니다.";
    } else if (event.stage === "CONTROL_DELTA") {
      const renderer = renderers.get(event.control_id);
      const delta = event.delta || "";
      controlSources.set(
        event.control_id,
        (controlSources.get(event.control_id) || "") + delta
      );
      if (renderer) {
        renderer.append(delta);
      }
    } else if (event.stage === "CONTROL_COMPLETED") {
      const renderer = renderers.get(event.control_id);
      const card = cards.get(event.control_id);
      if (renderer) {
        renderer.complete();
      }
      if (card) {
        card.status.textContent = "";
        card.status.hidden = true;
      }
      summaryProgress.value = event.completed_controls || 0;
      summaryProgress.textContent = (event.completed_controls || 0) + " / 18";
    } else if (event.stage === "ANALYSIS_COMPLETED") {
      runState = "completed";
      saveCompletedSnapshot();
      summaryStatus.textContent = "";
      summaryStatus.hidden = true;
      stopButton.textContent = "AI 설명 재생성";
      stopButton.hidden = false;
      stopButton.disabled = false;
    } else if (event.stage === "FAILED") {
      const detail = event.detail || {};
      throw new Error(detail.message || "AI 설명을 생성하지 못했습니다.");
    }
  }

  async function startStream(detail) {
    if (!detail || !Array.isArray(detail.explanation_inputs) || detail.explanation_inputs.length !== 18) {
      summary.hidden = false;
      summaryStatus.textContent = "AI 설명에 필요한 18개 점검 결과를 준비하지 못했습니다.";
      return;
    }
    const nextKey = buildGenerationKey(detail);
    if (runState === "running" && nextKey === generationKey) {
      return;
    }
    if (activeController) {
      activeController.abort();
    }
    generationKey = nextKey;
    runState = "running";
    summarySource = "";
    controlSources.clear();
    controlMetadata.clear();
    activeController = new AbortController();
    summary.hidden = false;
    summaryProgress.value = 0;
    summaryProgress.textContent = "0 / 18";
    summaryStatus.textContent = "AI 설명 연결을 시작하고 있습니다.";
    summaryStatus.hidden = false;
    stopButton.textContent = "설명 생성 멈추기";
    stopButton.hidden = false;
    stopButton.disabled = false;
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
            explanation_inputs: detail.explanation_inputs,
            administrator_results: detail.administrator_results || [],
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
        buffer += decoder.decode(chunk.value || new Uint8Array(), {stream: !chunk.done});
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
        throw new Error("AI 설명 연결이 완료 신호 없이 종료되었습니다.");
      }
    } catch (error) {
      if (error.name === "AbortError" || runState === "stopped") {
        return;
      }
      runState = "failed";
      completeRenderers(false);
      summaryStatus.textContent = error.message || "AI 설명 연결이 중단되었습니다.";
      stopButton.textContent = "설명 다시 시작";
      stopButton.disabled = false;
    } finally {
      activeReader = null;
      activeController = null;
    }
  }

  async function accept(detail) {
    latest = detail;
    const nextKey = buildGenerationKey(detail);
    if (runState === "running" && nextKey === generationKey) {
      return;
    }
    renderCards(detail);
    const restored = await restoreAvailableCompletedSnapshot(detail);
    if (latest !== detail) {
      return;
    }
    if (restored) {
      return;
    }
    if (detail.ai_ready) {
      void startStream(detail);
    }
  }

  document.querySelectorAll("[data-result-view-button]").forEach(function (button) {
    button.addEventListener("click", function () {
      applyView(button.dataset.resultViewButton);
    });
  });
  document.querySelectorAll("button[data-result-status]").forEach(function (button) {
    button.addEventListener("click", function () {
      applyFilter(button.dataset.resultStatus);
    });
  });
  stopButton.addEventListener("click", function () {
    if (runState === "running") {
      runState = "stopped";
      if (activeReader) {
        void activeReader.cancel().catch(function () {});
      }
      if (activeController) {
        activeController.abort();
      }
      completeRenderers(true);
      summaryStatus.textContent = "AI 설명 생성을 멈췄습니다. 생성된 내용은 그대로 확인할 수 있습니다.";
      stopButton.textContent = "설명 다시 시작";
    } else if (runState === "completed" && latest) {
      renderCards(latest);
      summaryText.replaceChildren();
      summaryRenderer = null;
      void startStream(latest);
    } else if ((runState === "stopped" || runState === "failed") && latest) {
      void startStream(latest);
    }
  });
  window.addEventListener("secai:product-results", function (event) {
    void accept(event.detail);
  });
  applyView("combined");
  applyFilter("ALL");
  if (window.SecAIProductResultsState) {
    void accept(window.SecAIProductResultsState);
  }
}());
