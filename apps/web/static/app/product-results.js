(function () {
  "use strict";

  const bridgeUrl = "http://127.0.0.1:18481";
  const administratorBridgeUrl = "http://127.0.0.1:18482";
  function captureAdministratorToken() {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const received = hash.get("admin_launcher_token");
    if (received && /^[A-Za-z0-9_-]{43}$/.test(received)) {
      window.sessionStorage.setItem(
        "secai_administrator_launcher_token",
        received
      );
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.search
      );
      return received;
    }
    return null;
  }
  captureAdministratorToken();
  const launcherContinuationKey = "secai_launcher_continuation";

  function takeLauncherContinuation() {
    let received = null;
    try {
      const continuation = JSON.parse(
        window.localStorage.getItem(launcherContinuationKey) || "null"
      );
      if (
        continuation &&
        /^[A-Za-z0-9_-]{43}$/.test(continuation.token) &&
        Number.isInteger(continuation.expires_at) &&
        continuation.expires_at >= Date.now()
      ) {
        received = continuation.token;
      }
    } catch (_error) {
      // 손상된 연결 정보는 아래에서 폐기합니다.
    }
    try {
      window.localStorage.removeItem(launcherContinuationKey);
    } catch (_error) {
      // sessionStorage token만으로 현재 탭 연결을 계속합니다.
    }
    return received;
  }

  let token = window.sessionStorage.getItem("secai_launcher_token");
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    token = takeLauncherContinuation();
    if (token) {
      window.sessionStorage.setItem("secai_launcher_token", token);
    }
  }
  let administratorToken = window.sessionStorage.getItem(
    "secai_administrator_launcher_token"
  );
  const pendingScanConsentKey = "secai_pending_standard_scan_consent";
  const pendingAdministratorConsentKey =
    "secai_pending_administrator_scan_consent";
  const aiAnalysisPendingKey = "secai_ai_analysis_pending";
  const aiAnalysisPayloadKey = "secai_ai_analysis_payload";
  const selectedCriteriaStorageKey = "secai_selected_criteria_profile";
  const scanStartWasRequested = new URLSearchParams(
    window.location.search
  ).get("start_scan") === "1";
  const connection = document.getElementById("result-connection");
  const title = document.getElementById("result-state-title");
  const message = document.getElementById("result-state-message");
  const progress = document.getElementById("result-progress");
  const launcherRecovery = document.getElementById("launcher-recovery");
  const launcherOpenHelp = document.getElementById("launcher-open-help");
  const launcherOpenHelpPanel = document.getElementById(
    "launcher-open-help-panel"
  );
  const launcherRetryConnection = document.getElementById(
    "launcher-retry-connection"
  );
  const launcherRecoveryStatus = document.getElementById(
    "launcher-recovery-status"
  );
  const scanControlProgress = document.getElementById(
    "scan-control-progress"
  );
  const scanControlProgressSummary = document.getElementById(
    "scan-control-progress-summary"
  );
  const scanControlProgressList = document.getElementById(
    "scan-control-progress-list"
  );
  const content = document.getElementById("result-content");
  const appliedCriteriaStatus = document.getElementById(
    "applied-criteria-status"
  );
  const resultOrganizationCriteria = document.getElementById(
    "result-organization-criteria"
  );
  const resultPersonalCriteria = document.getElementById(
    "result-personal-criteria"
  );
  const resultCriteriaSha256 = document.getElementById(
    "result-criteria-sha256"
  );
  const pass = document.getElementById("count-pass");
  const fail = document.getElementById("count-fail");
  const error = document.getElementById("count-error");
  const review = document.getElementById("count-review");
  const notEvaluated = document.getElementById("count-not-evaluated");
  const observedAt = document.getElementById("result-observed-at");
  const persistenceStatus = document.getElementById("result-persistence-status");
  const comparison = document.getElementById("result-comparison");
  const controls = document.getElementById("control-results");
  const history = document.getElementById("result-history");
  const recheck = document.getElementById("recheck-standard-scan");
  const openRecheckControls = document.getElementById("open-recheck-controls");
  const recheckControlsPanel = document.getElementById("recheck-controls-panel");
  const openAIAnalysis = document.getElementById("open-ai-analysis");
  const userReportButton = document.getElementById("download-user-report");
  const technicalReportButton = document.getElementById(
    "download-technical-report"
  );
  const resultReportStatus = document.getElementById("result-report-status");
  const resultReportHistory = document.getElementById("result-report-history");
  const recheckComparisonPanel = document.getElementById(
    "recheck-comparison-panel"
  );
  const comparisonImproved = document.getElementById("comparison-improved");
  const comparisonWorsened = document.getElementById("comparison-worsened");
  const comparisonUnchanged = document.getElementById("comparison-unchanged");
  const comparisonRemainingRisk = document.getElementById(
    "comparison-remaining-risk"
  );
  const comparisonChangeList = document.getElementById(
    "comparison-change-list"
  );
  const aiComparisonStatus = document.getElementById("ai-comparison-status");
  const aiComparisonContent = document.getElementById(
    "ai-comparison-content"
  );
  const aiComparisonOverall = document.getElementById("ai-comparison-overall");
  const aiComparisonImproved = document.getElementById(
    "ai-comparison-improved"
  );
  const aiComparisonWorsened = document.getElementById(
    "ai-comparison-worsened"
  );
  const aiComparisonRemaining = document.getElementById(
    "ai-comparison-remaining"
  );
  const aiComparisonActions = document.getElementById("ai-comparison-actions");
  const aiComparisonUnchangedSummary = document.getElementById(
    "ai-comparison-unchanged-summary"
  );
  const aiComparisonLimitations = document.getElementById(
    "ai-comparison-limitations"
  );
  const aiComparisonCitations = document.getElementById(
    "ai-comparison-citations"
  );
  const csrfToken = document.querySelector('meta[name="csrf-token"]');
  const persistedResultKeys = new Set();
  const persistedResultRequests = new Map();
  const aiExplanationStatus = document.getElementById(
    "ai-explanation-status"
  );
  const aiExplanationContent = document.getElementById(
    "ai-explanation-content"
  );
  const aiOverallState = document.getElementById("ai-overall-state");
  const aiPriorityResults = document.getElementById("ai-priority-results");
  const aiRelatedRisks = document.getElementById("ai-related-risks");
  const aiUserActions = document.getElementById("ai-user-actions");
  const aiAdministratorActions = document.getElementById(
    "ai-administrator-actions"
  );
  const aiLimitations = document.getElementById("ai-limitations");
  const aiPreviewItems = document.getElementById("ai-preview-items");
  const resultFollowUpPanel = document.getElementById(
    "result-follow-up-panel"
  );
  const resultFollowUpContext = document.getElementById(
    "result-follow-up-context"
  );
  const resultFollowUpClose = document.getElementById(
    "result-follow-up-close"
  );
  const resultFollowUpForm = document.getElementById(
    "result-follow-up-form"
  );
  const resultFollowUpQuestion = document.getElementById(
    "result-follow-up-question"
  );
  const resultFollowUpSubmit = document.getElementById(
    "result-follow-up-submit"
  );
  const resultFollowUpStatus = document.getElementById(
    "result-follow-up-status"
  );
  const resultFollowUpAnswer = document.getElementById(
    "result-follow-up-answer"
  );
  const resultFollowUpAnswerSummary = document.getElementById(
    "result-follow-up-answer-summary"
  );
  const resultFollowUpRisks = document.getElementById(
    "result-follow-up-risks"
  );
  const resultFollowUpCautions = document.getElementById(
    "result-follow-up-cautions"
  );
  const resultFollowUpPriority = document.getElementById(
    "result-follow-up-priority"
  );
  const resultFollowUpLimitations = document.getElementById(
    "result-follow-up-limitations"
  );
  const resultFollowUpSuggestions = document.getElementById(
    "result-follow-up-suggestions"
  );
  const resultFollowUpCitations = document.getElementById(
    "result-follow-up-citations"
  );
  const administratorOptions = document.querySelectorAll(
    'input[name="administrator-probe"]'
  );
  const administratorConsent = document.getElementById(
    "administrator-consent"
  );
  const administratorButton = document.getElementById(
    "start-administrator-scan"
  );
  const administratorStatus = document.getElementById(
    "administrator-status"
  );
  const administratorScanPanel = document.getElementById(
    "administrator-scan"
  );
  const administratorOptionsPanel = document.getElementById(
    "administrator-options-panel"
  );
  const administratorConsentPanel = document.getElementById(
    "administrator-consent-panel"
  );
  let pollTimer = null;
  let administratorReport = null;
  let standardControlItems = [];
  let administratorLoadAttempt = 0;
  let automaticAdministratorLaunchInFlight = false;
  let officialExplanationItems = new Map();
  let aiExplanationInputItems = new Map();
  let currentResultId = null;
  let currentResultVersion = null;
  let currentResultSnapshot = null;
  let technicalReportAllowed = false;
  let selectedFollowUpContext = null;
  const aiExplanationCache = new Map();
  const administratorControlIds = new Set([
    "PC-02", "PC-04", "PC-06", "PC-08", "PC-10"
  ]);
  const standardBatchControlIds = new Set([
    "PC-01", "PC-03", "PC-05", "PC-09", "PC-11", "PC-12",
    "PC-13", "PC-14", "PC-15", "PC-16", "PC-17", "PC-18"
  ]);
  const scanControlCatalog = [
    ["PC-01", "비밀번호의 주기적 변경", "비밀번호 최대 사용 기간과 정책 출처"],
    ["PC-02", "비밀번호 관리정책 설정", "최소 길이·복잡성·재사용 정책"],
    ["PC-03", "복구 콘솔 자동 로그온 금지", "복구 콘솔의 자동 관리자 로그온 정책"],
    ["PC-04", "불필요한 공유 폴더 제거", "공유 폴더와 접근 권한"],
    ["PC-05", "불필요한 서비스 제거", "Windows 서비스의 시작 유형과 실행 상태"],
    ["PC-06", "비인가 메신저 사용 금지", "설치·실행 중인 메신저 제품"],
    ["PC-07", "파일시스템을 NTFS 형식으로 설정", "디스크·파티션·고정 볼륨의 파일시스템"],
    ["PC-08", "Windows 외 다른 OS 부팅 제한", "Windows 부팅 구성 항목"],
    ["PC-09", "브라우저 종료 시 임시 파일 삭제", "종료 시 브라우저 캐시 삭제 정책"],
    ["PC-10", "보안 패치와 권고사항 적용", "Windows 업데이트 정책과 설치 이력"],
    ["PC-11", "지원이 종료되지 않은 Windows 사용", "Windows 제품·버전·빌드 정보"],
    ["PC-12", "Windows 자동 로그온 제거", "자동 관리자 로그온 사용 여부"],
    ["PC-13", "백신 설치와 주기적 업데이트", "백신 활성 상태와 정의 업데이트 상태"],
    ["PC-14", "백신 실시간 감시 활성화", "실시간 보호와 서비스 상태"],
    ["PC-15", "침입차단 기능 활성화", "Windows 방화벽 프로필 활성 상태"],
    ["PC-16", "화면보호기 대기 시간과 암호 보호", "대기 시간과 다시 시작할 때 암호 보호 정책"],
    ["PC-17", "이동식 미디어 자동실행 방지", "AutoRun·AutoPlay 차단 정책"],
    ["PC-18", "원격지원 금지 정책 설정", "요청·제안형 원격지원 정책"],
  ];

  if (!connection || !title || !message || !progress || !content ||
      !launcherRecovery || !launcherOpenHelp || !launcherOpenHelpPanel ||
      !launcherRetryConnection || !launcherRecoveryStatus ||
      !scanControlProgress || !scanControlProgressSummary ||
      !scanControlProgressList ||
      !pass || !fail || !error || !review || !notEvaluated ||
      !observedAt || !comparison ||
      !controls || !history || !recheck || !openRecheckControls ||
      !recheckControlsPanel || !openAIAnalysis ||
      !administratorConsent ||
      !userReportButton || !technicalReportButton ||
      !resultReportStatus || !resultReportHistory ||
      !recheckComparisonPanel || !comparisonImproved ||
      !comparisonWorsened || !comparisonUnchanged ||
      !comparisonRemainingRisk || !comparisonChangeList ||
      !aiComparisonStatus || !aiComparisonContent ||
      !aiComparisonOverall || !aiComparisonImproved ||
      !aiComparisonWorsened || !aiComparisonRemaining ||
      !aiComparisonActions || !aiComparisonUnchangedSummary ||
      !aiComparisonLimitations || !aiComparisonCitations ||
      !administratorButton || !administratorStatus ||
      !administratorScanPanel || !administratorOptionsPanel ||
      !administratorConsentPanel || !csrfToken ||
      !resultFollowUpPanel ||
      !resultFollowUpContext || !resultFollowUpClose || !resultFollowUpForm ||
      !resultFollowUpQuestion || !resultFollowUpSubmit ||
      !resultFollowUpStatus || !resultFollowUpAnswer ||
      !resultFollowUpAnswerSummary || !resultFollowUpRisks ||
      !resultFollowUpCautions || !resultFollowUpPriority ||
      !resultFollowUpLimitations || !resultFollowUpSuggestions ||
      !resultFollowUpCitations) {
      return;
  }

  function showLauncherRecovery(statusMessage) {
    launcherRecovery.hidden = false;
    launcherRecoveryStatus.textContent = statusMessage ||
      "실행 파일 연결을 기다리고 있습니다.";
  }

  function hideLauncherRecovery() {
    launcherRecovery.hidden = true;
  }

  function refreshLauncherToken() {
    const stored = window.sessionStorage.getItem("secai_launcher_token");
    const continued = takeLauncherContinuation();
    const received = continued || (
      stored && /^[A-Za-z0-9_-]{43}$/.test(stored) ? stored : null
    );
    if (!received) {
      token = null;
      return false;
    }
    token = received;
    window.sessionStorage.setItem("secai_launcher_token", received);
    return true;
  }

  function controlProgressState(
    item,
    report,
    completedControlIds,
    administratorPlanned
  ) {
    const controlId = item[0];
    if (completedControlIds.has(controlId)) {
      return ["complete", "확인 완료"];
    }
    if (administratorControlIds.has(controlId)) {
      if (administratorPlanned) {
        return ["planned", "일반 점검 후 실행 예정"];
      }
      return ["administrator", "관리자 확인"];
    }
    if (
      report.current_control_id === controlId ||
      (report.current_step === "ACCOUNT_AND_PROTECTION" &&
        standardBatchControlIds.has(controlId)) ||
      (report.current_step === "STORAGE" && controlId === "PC-07")
    ) {
      return ["active", "확인 중"];
    }
    return ["waiting", "대기"];
  }

  function renderScanControlProgress(report) {
    const completedControlIds = new Set(
      Array.isArray(report.completed_control_ids)
        ? report.completed_control_ids
        : []
    );
    scanControlProgressList.replaceChildren();
    let activeCount = 0;
    let waitingCount = 0;
    const administratorPlanned = Boolean(readPendingAdministratorConsent());
    scanControlCatalog.forEach(function (item) {
      const state = controlProgressState(
        item,
        report,
        completedControlIds,
        administratorPlanned
      );
      if (state[0] === "active") {
        activeCount += 1;
      } else if (state[0] === "waiting") {
        waitingCount += 1;
      }
      const row = document.createElement("li");
      row.className = "scan-control-progress-item scan-control-progress-" + state[0];
      const marker = document.createElement("span");
      marker.className = "scan-control-progress-marker";
      marker.setAttribute("aria-hidden", "true");
      const copy = document.createElement("span");
      const heading = document.createElement("strong");
      heading.textContent = item[0] + " · " + item[1];
      const description = document.createElement("small");
      description.textContent = item[2];
      copy.append(heading, description);
      const statusText = document.createElement("span");
      statusText.className = "scan-control-progress-status";
      statusText.textContent = state[1];
      row.append(marker, copy, statusText);
      scanControlProgressList.append(row);
    });
    const completedCount = completedControlIds.size;
    scanControlProgressSummary.textContent =
      "확인 완료 " + completedCount + "개 · 확인 중 " + activeCount +
      "개 · " +
      (administratorPlanned
        ? "관리자 점검 예정 5개"
        : "관리자 확인 5개") +
      " · 대기 " + waitingCount + "개";
    scanControlProgress.hidden = false;
  }

  function hideScanControlProgress() {
    scanControlProgress.hidden = true;
  }

  function stopPolling() {
    if (pollTimer !== null) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function schedulePoll() {
    stopPolling();
    pollTimer = window.setTimeout(loadResult, 500);
  }

  function element(name, className, text) {
    const node = document.createElement(name);
    if (className) {
      node.className = className;
    }
    if (typeof text === "string") {
      node.textContent = text;
    }
    return node;
  }

  function statusClass(value) {
    value = normalizeProductStatus(value);
    if (value === "PASS" || value === "EVIDENCE_COLLECTED") {
      return "control-result-collected";
    }
    if (value === "FAIL") {
      return "control-result-fail";
    }
    if (value === "ADMIN_REQUIRED") {
      return "control-result-admin";
    }
    return "control-result-review";
  }

  function normalizeProductStatus(value) {
    return value;
  }

  function normalizeProductControl(item) {
    const normalized = Object.assign({}, item);
    const normalizedStatus = normalizeProductStatus(
      normalized.assessment_status || normalized.display_status
    );
    if (normalizedStatus === "ERROR") {
      normalized.assessment_status = "ERROR";
      normalized.display_status = "ERROR";
      normalized.assessment_label = "수집 오류 (ERROR)";
      normalized.status_label = "수집 오류 (ERROR)";
    } else if (normalizedStatus === "REVIEW") {
      normalized.assessment_status = "REVIEW";
      normalized.display_status = "REVIEW";
      normalized.assessment_label = "기준 확인 필요 (REVIEW)";
      normalized.status_label = "기준 확인 필요 (REVIEW)";
    }
    return normalized;
  }

  function collectionStatusLabel(value) {
    return {
      COLLECTED: "자료 수집 완료",
      ERROR: "자료 수집 오류",
      UNSUPPORTED: "자료 수집 미지원"
    }[value] || "수집 상태 확인 필요";
  }

  function checkLevelLabel(item) {
    if (!item.administrator_verified) {
      return "일반 사용자 권한으로 확인";
    }
    return "관리자 권한 · " + collectionStatusLabel(item.collection_status);
  }

  function addDefinition(list, term, value) {
    list.appendChild(element("dt", "", term));
    list.appendChild(
      element(
        "dd",
        "",
        Array.isArray(value) ? value.join(" · ") : String(value || "확인되지 않음")
      )
    );
  }

  function kisaSourceText(source) {
    if (!source) {
      return "KISA 근거를 확인하지 못했습니다.";
    }
    return [
      source.guide_version + " KISA 07. PC",
      source.page_label,
      source.section_label
    ].filter(Boolean).join(" · ");
  }

  function renderOfficialExplanation(definitions, explanation, item) {
    if (item.administrator_verified === true || !explanation) {
      addDefinition(
        definitions,
        "무엇을 확인했나요",
        item.collected_summary || item.checked_summary ||
          (explanation && explanation.what_was_checked)
      );
      addDefinition(
        definitions,
        "내 PC에서 확인한 내용",
        item.actual || item.judgement_explanation ||
          (explanation && explanation.observed_summary)
      );
      addDefinition(
        definitions,
        "KISA 권고 기준",
        item.expected || (explanation && explanation.expected_summary)
      );
      addDefinition(
        definitions,
        "판정 이유",
        item.judgement_explanation || item.checked_summary ||
          (explanation && explanation.judgement_explanation)
      );
      addDefinition(
        definitions,
        "다음 행동",
        item.action_guidance || (explanation && explanation.allowed_actions)
      );
      addDefinition(
        definitions,
        "확인 수준",
        checkLevelLabel(item)
      );
      return;
    }
    addDefinition(
      definitions,
      "무엇을 확인했나요",
      explanation.what_was_checked
    );
    addDefinition(
      definitions,
      "내 PC에서 확인한 내용",
      explanation.observed_summary
    );
    addDefinition(
      definitions,
      "KISA 권고 기준",
      explanation.expected_summary
    );
    addDefinition(
      definitions,
      "판정 이유",
      explanation.judgement_explanation
    );
    addDefinition(
      definitions,
      "다음 행동",
      explanation.allowed_actions
    );
    addDefinition(
      definitions,
      "확인 수준",
      checkLevelLabel(item)
    );
  }

  function renderTechnicalExplanation(parent, explanation, item) {
    const technical = document.createElement("details");
    technical.className = "technical-evidence";
    technical.appendChild(
      element("summary", "", "확인 방법과 기술 정보")
    );
    const definitions = element("dl", "control-result-details");
    if (explanation) {
      addDefinition(definitions, "확인 방법", explanation.collection_methods);
      addDefinition(definitions, "확인 도구", explanation.execution_tools);
      addDefinition(definitions, "확인 위치", explanation.source_locations);
      addDefinition(
        definitions,
        "근거와 출처",
        kisaSourceText(explanation.kisa_source)
      );
      if (
        item.administrator_verified !== true &&
        explanation.collection_limitations.length > 0
      ) {
        addDefinition(
          definitions,
          "확인하지 못한 내용",
          explanation.collection_limitations
        );
      }
    } else {
      addDefinition(definitions, "근거와 출처", item.source);
    }
    if (item.administrator_verified === true) {
      addDefinition(
        definitions,
        "관리자 수집 상태",
        collectionStatusLabel(item.collection_status)
      );
      if (item.collection_status !== "COLLECTED") {
        addDefinition(
          definitions,
          "확인하지 못한 내용",
          item.judgement_explanation
        );
      }
    }
    technical.appendChild(definitions);
    parent.appendChild(technical);
  }

  function renderAdditionalCriteria(definitions, item) {
    const additional = item.additional_criteria;
    if (!additional) {
      return;
    }
    const source = {
        KISA_DEFAULT: "KISA·제품 기본값",
        ORGANIZATION: "관리자 조직 기본값",
        PERSONAL: "내 개인 기준"
      }[additional.source] || "선택 기준";
    addDefinition(
      definitions,
      "적용한 추가 기준",
      [
        additional.status_label,
        additional.actual,
        additional.expected,
        source
      ].filter(Boolean).join(" · ")
    );
  }

  function renderControls(items) {
    controls.replaceChildren();
    items.map(normalizeProductControl).forEach(function (item) {
      const shownStatus = item.assessment_status || item.display_status;
      const card = element("article", "control-result " + statusClass(shownStatus));
      card.dataset.controlId = item.control_id;
      const heading = element("div", "control-result-heading");
      const headingCopy = element("div", "");
      headingCopy.appendChild(
        element("span", "control-id", item.control_id + " · 중요도 " + item.importance)
      );
      headingCopy.appendChild(element("h3", "", item.title));
      heading.appendChild(headingCopy);
      heading.appendChild(
        element(
          "span",
          "status",
          item.assessment_label || item.status_label
        )
      );
      card.appendChild(heading);
      card.appendChild(element("p", "control-result-summary", item.checked_summary));

      const detail = document.createElement("details");
      detail.className = "official-explanation";
      detail.appendChild(
        element("summary", "official-explanation-title", "확인 방법과 판정 근거 보기")
      );
      const definitions = element(
        "dl",
        "control-result-details official-explanation-details"
      );
      renderOfficialExplanation(
        definitions,
        officialExplanationItems.get(item.control_id),
        item
      );
      renderAdditionalCriteria(definitions, item);
      detail.appendChild(definitions);
      renderTechnicalExplanation(
        detail,
        officialExplanationItems.get(item.control_id),
        item
      );
      const guideQuestion = element(
        "button",
        "control-guide-question",
        "이 결과를 AI에게 질문"
      );
      guideQuestion.type = "button";
      guideQuestion.addEventListener("click", function () {
        openResultFollowUp(item);
      });
      detail.appendChild(guideQuestion);
      card.appendChild(detail);
      controls.appendChild(card);
    });
  }

  function appendList(list, values, emptyMessage) {
    list.replaceChildren();
    const items = Array.isArray(values) && values.length > 0
      ? values
      : [emptyMessage];
    items.forEach(function (value) {
      list.appendChild(element("li", "", String(value)));
    });
  }

  function priorityLabel(value) {
    return {
      URGENT: "즉시 확인",
      HIGH: "우선 확인",
      NORMAL: "일반 확인",
      OBSERVE: "지켜보기"
    }[value] || "확인 필요";
  }

  function officialStatusLabel(value) {
    return {
      PASS: "양호",
      FAIL: "취약",
      ERROR: "수집 오류",
      REVIEW: "기준 확인 필요",
      "N/A": "해당 없음"
    }[value] || "판정 전";
  }

  function renderAIExplanationItem(item) {
    const card = element("article", "ai-preview-item");
    card.dataset.controlId = item.control_id;
    const heading = element("div", "ai-preview-item-heading");
    const copy = element("div", "");
    copy.appendChild(element("span", "control-id", item.control_id));
    copy.appendChild(element("h4", "", "AI 해석·권장"));
    heading.appendChild(copy);
    heading.appendChild(
      element(
        "span",
        "ai-priority-badge",
        priorityLabel(item.ai_priority)
      )
    );
    card.appendChild(heading);
    card.appendChild(
      element(
        "p",
        "ai-official-state",
        "공식 판정 · " + officialStatusLabel(item.rule_status)
      )
    );
    const definitions = element("dl", "ai-preview-item-details");
    addDefinition(definitions, "무엇을 확인했나요", item.what_was_checked);
    addDefinition(
      definitions,
      "내 PC에서 확인한 내용",
      item.observed_summary
    );
    addDefinition(definitions, "KISA 권고 기준", item.expected_summary);
    addDefinition(
      definitions,
      "왜 이런 결과가 나왔나요",
      item.judgement_explanation
    );
    addDefinition(definitions, "어떤 위험이 있나요", item.risk_explanation);
    addDefinition(definitions, "왜 먼저 확인하나요", item.priority_reason);
    addDefinition(definitions, "사용자가 할 수 있는 일", item.user_actions);
    addDefinition(
      definitions,
      "관리자에게 요청할 일",
      item.administrator_actions
    );
    if (item.limitations.length > 0) {
      addDefinition(definitions, "확인하지 못한 내용", item.limitations);
    }
    addDefinition(definitions, "근거와 출처", item.kisa_basis_summary);
    card.appendChild(definitions);
    return card;
  }

  function aiExplanationFailureMessage(result) {
    const reasonCode = result && result.reason_code;
    if (reasonCode === "OUTPUT_TOKEN_LIMIT_REACHED") {
      return "AI 답변이 길어 생성이 중단되었습니다. 공식 판정 결과는 그대로이며 다시 시도할 수 있습니다.";
    }
    const messages = {
      NO_EVIDENCE:
        "설명에 필요한 KISA 근거가 부족해 AI 설명을 만들지 않았습니다.",
      DOCUMENT_CONFLICT:
        "KISA 근거가 서로 달라 AI 설명 생성을 안전하게 중단했습니다.",
      MODEL_UNAVAILABLE:
        "AI 연결을 일시적으로 사용할 수 없습니다. 공식 판정 결과는 그대로입니다.",
      GENERATION_FAILED:
        "AI 설명을 완성하지 못했습니다. 공식 판정 결과는 그대로입니다.",
      SECURITY_BLOCKED:
        "안전한 출력 조건을 충족하지 못해 AI 설명을 표시하지 않았습니다."
    };
    return messages[result && result.status] ||
      "AI 설명을 만들지 못했습니다. 공식 판정 결과는 그대로 확인할 수 있습니다.";
  }

  function renderAIExplanation(result) {
    if (result.status !== "GENERATED" || !result.summary) {
      aiExplanationContent.hidden = true;
      aiExplanationStatus.textContent = aiExplanationFailureMessage(result);
      return false;
    }
    aiOverallState.textContent = result.summary.overall_state;
    const priorityOrder = {URGENT: 0, HIGH: 1, NORMAL: 2, OBSERVE: 3};
    const priorityItems = result.items.slice().sort(function (left, right) {
      return (priorityOrder[left.ai_priority] ?? 9) -
        (priorityOrder[right.ai_priority] ?? 9);
    }).slice(0, 3);
    aiPriorityResults.replaceChildren();
    priorityItems.forEach(function (item) {
      const row = element("li", "");
      row.appendChild(
        element(
          "strong",
          "",
          item.control_id + " · " + priorityLabel(item.ai_priority)
        )
      );
      row.appendChild(element("span", "", item.priority_reason));
      aiPriorityResults.appendChild(row);
    });
    appendList(
      aiRelatedRisks,
      result.summary.related_risks,
      "추가로 연결된 위험이 없습니다."
    );
    appendList(
      aiUserActions,
      result.summary.user_actions,
      "사용자가 바로 할 수 있는 조치가 없습니다."
    );
    appendList(
      aiAdministratorActions,
      result.summary.administrator_actions,
      "관리자에게 요청할 추가 조치가 없습니다."
    );
    appendList(
      aiLimitations,
      result.summary.limitations,
      "별도로 확인하지 못한 범위가 없습니다."
    );
    aiPreviewItems.replaceChildren();
    result.items.forEach(function (item) {
      aiPreviewItems.appendChild(renderAIExplanationItem(item));
    });
    aiExplanationContent.hidden = false;
    aiExplanationStatus.textContent =
      "AI 설명이 준비되었습니다. 공식 판정은 규칙 엔진 결과와 같습니다.";
    return true;
  }

  function renderAIExplanationBatch(result, completedControls, totalControls) {
    if (!result || result.status !== "GENERATED" ||
        !Array.isArray(result.items)) {
      return;
    }
    if (aiExplanationContent.hidden) {
      aiPreviewItems.replaceChildren();
      aiOverallState.textContent =
        "항목별 설명을 순서대로 준비하고 있습니다. 전체 종합은 마지막에 표시됩니다.";
      aiPriorityResults.replaceChildren();
      appendList(aiRelatedRisks, [], "전체 종합을 준비하고 있습니다.");
      appendList(aiUserActions, [], "전체 종합을 준비하고 있습니다.");
      appendList(aiAdministratorActions, [], "전체 종합을 준비하고 있습니다.");
      appendList(aiLimitations, [], "전체 종합을 준비하고 있습니다.");
      aiExplanationContent.hidden = false;
    }
    result.items.forEach(function (item) {
      const existing = Array.from(aiPreviewItems.children).find(
        function (card) {
          return card.dataset.controlId === item.control_id;
        }
      );
      if (!existing) {
        aiPreviewItems.appendChild(renderAIExplanationItem(item));
      }
    });
    aiExplanationStatus.textContent =
      totalControls + "개 중 " + completedControls +
      "개 설명을 화면에 표시했습니다.";
  }

  function updateAIExplanationStage(stage) {
    const messages = {
      VALIDATING_SCAN_RESULT: "공식 판정과 전송 범위를 확인하고 있습니다.",
      SEARCHING_KISA_EVIDENCE: "KISA 근거를 찾고 있습니다.",
      GENERATING_AI_EXPLANATION:
        "AI가 위험과 조치 방법을 정리하고 있습니다."
    };
    if (messages[stage]) {
      aiExplanationStatus.textContent = messages[stage];
    }
  }

  function comparisonChangeLabel(value) {
    return {
      IMPROVED: "개선",
      WORSENED: "악화",
      UNCHANGED: "위험도 변화 없음"
    }[value] || "확인 필요";
  }

  function renderRecheckComparison(comparisonValue) {
    const summary = comparisonValue.summary || {};
    comparisonImproved.textContent = String(summary.improved || 0);
    comparisonWorsened.textContent = String(summary.worsened || 0);
    comparisonUnchanged.textContent = String(summary.unchanged || 0);
    comparisonRemainingRisk.textContent = String(summary.remaining_risk || 0);
    comparisonChangeList.replaceChildren();
    (comparisonValue.changes || []).forEach(function (item) {
      const row = element(
        "article",
        "comparison-change comparison-change-" +
          String(item.change || "").toLowerCase()
      );
      const copy = element("div", "");
      copy.appendChild(
        element("strong", "", item.control_id + " · " + item.title)
      );
      const statusDescription = item.previous_status === item.current_status
        ? officialStatusLabel(item.current_status) + " 상태가 유지되었습니다."
        : item.change === "UNCHANGED"
        ? officialStatusLabel(item.previous_status) + "에서 " +
          officialStatusLabel(item.current_status) +
          "로 바뀌었지만 위험도 단계는 같습니다."
        : officialStatusLabel(item.previous_status) + "에서 " +
          officialStatusLabel(item.current_status) + "로 바뀌었습니다.";
      copy.appendChild(element("span", "", statusDescription));
      row.appendChild(copy);
      row.appendChild(
        element(
          "span",
          "comparison-change-badge",
          comparisonChangeLabel(item.change)
        )
      );
      comparisonChangeList.appendChild(row);
    });
    recheckComparisonPanel.hidden = false;
  }

  function renderAIComparisonCitations(citations) {
    aiComparisonCitations.replaceChildren();
    const values = Array.isArray(citations) ? citations : [];
    if (values.length === 0) {
      aiComparisonCitations.appendChild(
        element("li", "", "표시할 KISA 출처가 없습니다.")
      );
      return;
    }
    values.forEach(function (citation) {
      aiComparisonCitations.appendChild(
        element(
          "li",
          "",
          [
            "KISA " + citation.guide_version,
            citation.pdf_page_number + "쪽",
            citation.section_label,
            "문단 " + citation.paragraph_ordinal
          ].filter(Boolean).join(" · ")
        )
      );
    });
  }

  function renderAIComparison(result) {
    if (!result || result.status !== "GENERATED") {
      aiComparisonContent.hidden = true;
      aiComparisonStatus.textContent =
        result && result.status === "NO_EVIDENCE"
          ? "변경 항목과 연결된 KISA 근거가 부족해 AI 설명을 만들지 않았습니다."
          : "AI 변화 설명을 만들지 못했습니다. 규칙 엔진의 비교 결과는 그대로 확인할 수 있습니다.";
      return;
    }
    aiComparisonOverall.textContent = result.overall_change;
    appendList(
      aiComparisonImproved,
      result.improved_explanations,
      "이번 재점검에서 개선된 항목은 없습니다."
    );
    appendList(
      aiComparisonWorsened,
      result.worsened_explanations,
      "이번 재점검에서 악화된 항목은 없습니다."
    );
    aiComparisonRemaining.textContent =
      result.remaining_risk_explanation ||
      "현재 남아 있는 위험을 추가로 설명하지 못했습니다.";
    appendList(
      aiComparisonActions,
      result.recommended_next_actions,
      "현재 권장할 추가 행동이 없습니다."
    );
    aiComparisonUnchangedSummary.textContent =
      result.unchanged_summary || "변경 없는 항목을 확인하지 못했습니다.";
    appendList(
      aiComparisonLimitations,
      result.limitations,
      "현재 결과와 승인된 KISA 근거 범위에서 설명했습니다."
    );
    renderAIComparisonCitations(result.citations);
    aiComparisonContent.hidden = false;
    aiComparisonStatus.textContent =
      "AI 변화 설명이 준비되었습니다. 공식 변화 분류는 규칙 엔진 결과와 같습니다.";
  }

  function updateAIComparisonStage(stage) {
    const messages = {
      VALIDATING_RECHECK_LINEAGE:
        "이전 결과와 현재 결과의 연결 관계를 확인하고 있습니다.",
      SEARCHING_CHANGED_KISA_EVIDENCE:
        "변경된 항목과 남아 있는 위험의 KISA 근거를 찾고 있습니다.",
      GENERATING_CHANGE_EXPLANATION:
        "AI가 변화의 의미와 다음 행동을 정리하고 있습니다."
    };
    if (messages[stage]) {
      aiComparisonStatus.textContent = messages[stage];
    }
  }

  function processAIComparisonEvent(payload) {
    updateAIComparisonStage(payload.stage);
    if (payload.stage === "FAILED") {
      const detail = payload.detail || {};
      aiComparisonContent.hidden = true;
      aiComparisonStatus.textContent =
        detail.message ||
        "AI 변화 설명을 만들지 못했습니다. 규칙 엔진의 비교 결과는 그대로 확인할 수 있습니다.";
      return;
    }
    if (payload.stage === "COMPLETED") {
      renderAIComparison(payload.result);
    }
  }

  async function loadAIRecheckComparison(result) {
    const comparisonValue = result.comparison;
    const changes = comparisonValue && Array.isArray(comparisonValue.changes)
      ? comparisonValue.changes
      : [];
    const focusIds = new Set(
      changes
        .filter(function (item) {
          return item.change !== "UNCHANGED" ||
            ["FAIL", "ERROR", "REVIEW"].includes(item.current_status);
        })
        .map(function (item) { return item.control_id; })
    );
    const explanationInputs = (result.ai_explanation_inputs || []).filter(
      function (item) { return focusIds.has(item.control_id); }
    );
    if (!comparisonValue || explanationInputs.length === 0) {
      aiComparisonContent.hidden = true;
      aiComparisonStatus.textContent =
        "비교할 변경 항목이나 KISA 설명 입력이 준비되지 않았습니다.";
      return;
    }
    aiComparisonContent.hidden = true;
    aiComparisonStatus.textContent =
      "이전 결과와 현재 결과의 연결 관계를 확인하고 있습니다.";
    try {
      const response = await window.fetch(
        "/api/v1/result-explanations/comparison/stream",
        {
          method: "POST",
          headers: {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken.content
          },
          body: JSON.stringify({
            comparison: comparisonValue,
            current_explanation_inputs: explanationInputs,
            profile: "FAST",
            test_environment_result: true
          }),
          cache: "no-store"
        }
      );
      if (!response.ok || !response.body) {
        throw new Error("AI comparison stream unavailable");
      }
      const reader = response.body.getReader();
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
          const dataLine = block.split("\n").find(function (line) {
            return line.startsWith("data: ");
          });
          if (dataLine) {
            processAIComparisonEvent(JSON.parse(dataLine.slice(6)));
          }
        });
        if (chunk.done) {
          if (buffer.trim()) {
            const dataLine = buffer.split("\n").find(function (line) {
              return line.startsWith("data: ");
            });
            if (dataLine) {
              processAIComparisonEvent(JSON.parse(dataLine.slice(6)));
            }
          }
          break;
        }
      }
    } catch (_error) {
      aiComparisonContent.hidden = true;
      aiComparisonStatus.textContent =
        "AI 연결을 확인하지 못했습니다. 규칙 엔진의 비교 결과는 그대로 확인할 수 있습니다.";
    }
  }

  function processAIEvent(payload, resultId) {
    updateAIExplanationStage(payload.stage);
    if (payload.stage === "FAILED") {
      const detail = payload.detail || {};
      aiExplanationContent.hidden = true;
      aiExplanationStatus.textContent =
        detail.message ||
        "AI 설명을 만들지 못했습니다. 공식 판정 결과는 그대로 확인할 수 있습니다.";
      return;
    }
    if (payload.stage === "BATCH_COMPLETED" && payload.result) {
      renderAIExplanationBatch(
        payload.result,
        payload.completed_controls,
        payload.total_controls
      );
      return;
    }
    if (payload.stage === "COMPLETED" && payload.result) {
      const rendered = renderAIExplanation(payload.result);
      if (rendered) {
        aiExplanationCache.set(resultId, payload.result);
      }
      if (rendered && currentResultId === resultId) {
        resultReportStatus.textContent =
          "AI 설명이 준비되었습니다. 지금 PDF를 만들면 AI 종합 설명도 함께 저장됩니다.";
      }
    }
  }

  function reportFileName(reportKind) {
    return reportKind === "TECHNICAL"
      ? "SecAI-기술검증용-점검결과.pdf"
      : "SecAI-내PC-점검결과.pdf";
  }

  async function downloadReportFile(metadata) {
    const response = await window.fetch(metadata.download_url, {
      method: "GET",
      cache: "no-store"
    });
    if (!response.ok) {
      throw new Error("report download failed");
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = reportFileName(metadata.report_kind);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  }

  function renderReportHistory(reports) {
    resultReportHistory.replaceChildren();
    if (!Array.isArray(reports) || reports.length === 0) {
      resultReportHistory.appendChild(
        element("li", "", "아직 만든 보고서가 없습니다.")
      );
      return;
    }
    reports.forEach(function (report) {
      const row = element("li", "result-report-history-item");
      const label = report.report_kind === "TECHNICAL"
        ? "기술 검증용"
        : "사용자용";
      row.appendChild(
        element(
          "span",
          "",
          label + " v" + report.report_version +
            " · PDF 확인값 " + report.pdf_sha256.slice(0, 12) + "…"
        )
      );
      const download = element("button", "button-secondary", "다시 받기");
      download.type = "button";
      download.addEventListener("click", async function () {
        try {
          await downloadReportFile(report);
        } catch (_error) {
          resultReportStatus.textContent = "보고서 파일을 받지 못했습니다.";
        }
      });
      row.appendChild(download);
      resultReportHistory.appendChild(row);
    });
  }

  async function loadReportCapabilities() {
    try {
      const response = await window.fetch(
        "/api/v1/result-reports/capabilities",
        {method: "GET", cache: "no-store"}
      );
      if (!response.ok) {
        throw new Error("report capability unavailable");
      }
      const capability = await response.json();
      technicalReportAllowed = capability.technical_report_allowed === true;
      technicalReportButton.disabled = !technicalReportAllowed;
      technicalReportButton.title = technicalReportAllowed
        ? ""
        : "승인된 보안 검증 담당자 권한이 필요합니다.";
    } catch (_error) {
      technicalReportAllowed = false;
      technicalReportButton.disabled = true;
      resultReportStatus.textContent =
        "보고서 권한을 확인하지 못했습니다. 다시 로그인한 뒤 시도해 주세요.";
    }
  }

  async function loadReportHistory() {
    if (!currentResultId || !currentResultVersion) {
      return;
    }
    try {
      const query = new URLSearchParams({
        result_id: currentResultId,
        result_version: String(currentResultVersion)
      });
      const response = await window.fetch(
        "/api/v1/result-reports?" + query.toString(),
        {method: "GET", cache: "no-store"}
      );
      if (!response.ok) {
        throw new Error("report history unavailable");
      }
      const payload = await response.json();
      renderReportHistory(payload.reports);
    } catch (_error) {
      resultReportHistory.replaceChildren(
        element("li", "", "이전에 만든 보고서를 불러오지 못했습니다.")
      );
    }
  }

  async function createReport(reportKind) {
    if (!currentResultSnapshot) {
      return;
    }
    userReportButton.disabled = true;
    technicalReportButton.disabled = true;
    resultReportStatus.textContent =
      reportKind === "TECHNICAL"
        ? "기술 검증용 보고서와 무결성 확인값을 만들고 있습니다."
        : "사용자용 보고서를 만들고 있습니다.";
    try {
      const administratorResults =
        administratorReport &&
        administratorReport.standard_result_id === currentResultSnapshot.result_id &&
        Array.isArray(administratorReport.results)
          ? administratorReport.results
          : [];
      const response = await window.fetch("/api/v1/result-reports", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken.content
        },
        body: JSON.stringify({
          result_id: currentResultSnapshot.result_id,
          result_version: currentResultSnapshot.sequence,
          observed_at_utc: currentResultSnapshot.observed_at_utc,
          explanation_inputs:
            currentResultSnapshot.ai_explanation_inputs || [],
          administrator_results: administratorResults,
          ai_explanation:
            administratorResults.length === 0
              ? aiExplanationCache.get(currentResultSnapshot.result_id) || null
              : null,
          report_kind: reportKind,
          test_environment_result: true
        }),
        cache: "no-store"
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(
          (payload.detail && payload.detail.message) ||
          "report generation failed"
        );
      }
      await downloadReportFile(payload);
      resultReportStatus.textContent =
        "보고서를 만들고 다운로드했습니다. PDF 확인값 " +
        payload.pdf_sha256.slice(0, 12) + "…";
      await loadReportHistory();
    } catch (reportError) {
      resultReportStatus.textContent =
        reportError.message ||
        "보고서를 만들지 못했습니다. 잠시 후 다시 시도해 주세요.";
    } finally {
      userReportButton.disabled = false;
      technicalReportButton.disabled = !technicalReportAllowed;
    }
  }

  async function loadAIExplanation(explanationInputs, resultId) {
    if (!Array.isArray(explanationInputs) || explanationInputs.length === 0) {
      aiExplanationContent.hidden = true;
      aiExplanationStatus.textContent =
        "AI 설명에 필요한 점검 결과가 준비되지 않았습니다.";
      return;
    }
    if (aiExplanationCache.has(resultId)) {
      renderAIExplanation(aiExplanationCache.get(resultId));
      return;
    }
    aiExplanationContent.hidden = true;
    aiExplanationStatus.textContent =
      "공식 판정과 전송 범위를 확인하고 있습니다.";
    try {
      const response = await window.fetch(
        "/api/v1/result-explanations/from-scan/stream",
        {
          method: "POST",
          headers: {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken.content
          },
          body: JSON.stringify({
            explanation_inputs: explanationInputs,
            profile: "FAST",
            test_environment_result: true
          }),
          cache: "no-store"
        }
      );
      if (!response.ok || !response.body) {
        throw new Error("AI explanation stream unavailable");
      }
      const reader = response.body.getReader();
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
          const dataLine = block.split("\n").find(function (line) {
            return line.startsWith("data: ");
          });
          if (dataLine) {
            processAIEvent(JSON.parse(dataLine.slice(6)), resultId);
          }
        });
        if (chunk.done) {
          if (buffer.trim()) {
            const dataLine = buffer.split("\n").find(function (line) {
              return line.startsWith("data: ");
            });
            if (dataLine) {
              processAIEvent(JSON.parse(dataLine.slice(6)), resultId);
            }
          }
          break;
        }
      }
    } catch (_error) {
      aiExplanationContent.hidden = true;
      aiExplanationStatus.textContent =
        "AI 연결을 확인하지 못했습니다. 공식 판정 결과는 그대로 확인할 수 있습니다.";
    }
  }

  function followUpStageMessage(stage) {
    return {
      VALIDATING_RESULT_CONTEXT: "선택한 점검 결과와 질문 범위를 확인하고 있습니다.",
      SEARCHING_SELECTED_KISA_EVIDENCE: "이 결과에 연결된 KISA 근거를 찾고 있습니다.",
      GENERATING_FOLLOW_UP_ANSWER: "AI가 위험과 조치 주의점을 정리하고 있습니다."
    }[stage] || "답변을 준비하고 있습니다.";
  }

  function renderFollowUpCitations(citations) {
    resultFollowUpCitations.replaceChildren();
    const values = Array.isArray(citations) ? citations : [];
    if (values.length === 0) {
      resultFollowUpCitations.appendChild(
        element("li", "", "표시할 KISA 출처가 없습니다.")
      );
      return;
    }
    values.forEach(function (citation) {
      resultFollowUpCitations.appendChild(
        element(
          "li",
          "",
          [
            "KISA " + citation.guide_version,
            citation.pdf_page_number + "쪽",
            citation.section_label,
            "문단 " + citation.paragraph_ordinal
          ].filter(Boolean).join(" · ")
        )
      );
    });
  }

  function renderFollowUpSuggestions(values) {
    resultFollowUpSuggestions.replaceChildren();
    const suggestions = Array.isArray(values) ? values : [];
    suggestions.forEach(function (value) {
      const button = element("button", "secondary-button", String(value));
      button.type = "button";
      button.addEventListener("click", function () {
        resultFollowUpQuestion.value = String(value);
        resultFollowUpQuestion.focus();
      });
      resultFollowUpSuggestions.appendChild(button);
    });
  }

  function renderResultFollowUp(result) {
    if (!result || result.status !== "GENERATED" || !result.answer) {
      resultFollowUpAnswer.hidden = true;
      resultFollowUpStatus.textContent =
        result && result.status === "NO_EVIDENCE"
          ? "선택한 결과와 연결된 KISA 근거가 부족해 답변하지 않았습니다."
          : "안전하게 답변을 만들지 못했습니다. 공식 판정은 그대로입니다.";
      return;
    }
    resultFollowUpAnswerSummary.textContent = result.answer;
    appendList(
      resultFollowUpRisks,
      result.risk_scenarios,
      "추가로 확인된 위험 시나리오가 없습니다."
    );
    appendList(
      resultFollowUpCautions,
      result.action_cautions,
      "추가 조치 전에 조직 담당자와 적용 범위를 확인하세요."
    );
    resultFollowUpPriority.textContent =
      result.priority_reason || "공식 중요도와 현재 판정을 함께 확인하세요.";
    appendList(
      resultFollowUpLimitations,
      result.limitations,
      "현재 선택한 결과와 KISA 근거 범위에서 답변했습니다."
    );
    renderFollowUpSuggestions(result.suggested_questions);
    renderFollowUpCitations(result.citations);
    resultFollowUpAnswer.hidden = false;
    resultFollowUpStatus.textContent =
      "현재 결과에 연결된 AI 답변을 만들었습니다.";
  }

  function processFollowUpEvent(payload) {
    if (payload.stage === "FAILED") {
      const detail = payload.detail || {};
      resultFollowUpAnswer.hidden = true;
      resultFollowUpStatus.textContent =
        detail.message ||
        "AI 답변을 만들지 못했습니다. 공식 판정은 그대로입니다.";
      return;
    }
    if (payload.stage === "COMPLETED") {
      renderResultFollowUp(payload.result);
      return;
    }
    resultFollowUpStatus.textContent = followUpStageMessage(payload.stage);
  }

  function openResultFollowUp(item) {
    const explanationInput = aiExplanationInputItems.get(item.control_id);
    selectedFollowUpContext = explanationInput && currentResultId
      ? {
          resultId: currentResultId,
          resultVersion: currentResultVersion,
          controlId: item.control_id,
          title: item.title,
          officialStatus: item.assessment_status,
          explanationInput: explanationInput
        }
      : null;
    resultFollowUpPanel.hidden = false;
    resultFollowUpAnswer.hidden = true;
    resultFollowUpQuestion.value = "";
    if (!selectedFollowUpContext) {
      resultFollowUpContext.textContent =
        item.control_id + " 결과의 AI 질문 문맥을 준비하지 못했습니다.";
      resultFollowUpStatus.textContent =
        "같은 항목을 다시 점검한 뒤 질문해 주세요.";
      resultFollowUpSubmit.disabled = true;
    } else {
      resultFollowUpContext.textContent = [
        item.control_id + " · " + item.title,
        "공식 판정 " + officialStatusLabel(item.assessment_status),
        "점검 결과 " + currentResultVersion + "회차"
      ].join(" · ");
      resultFollowUpStatus.textContent =
        "선택한 결과 한 건과 해당 KISA 근거만 사용합니다.";
      resultFollowUpSubmit.disabled = false;
      resultFollowUpQuestion.focus();
    }
    resultFollowUpPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function submitResultFollowUp() {
    if (!selectedFollowUpContext) {
      resultFollowUpStatus.textContent =
        "질문할 점검 결과를 다시 선택해 주세요.";
      return;
    }
    const question = resultFollowUpQuestion.value.trim();
    if (!question || question.length > 500) {
      resultFollowUpStatus.textContent =
        "질문을 1자 이상 500자 이하로 입력해 주세요.";
      resultFollowUpQuestion.focus();
      return;
    }
    resultFollowUpSubmit.disabled = true;
    resultFollowUpAnswer.hidden = true;
    resultFollowUpStatus.textContent =
      "선택한 점검 결과와 질문 범위를 확인하고 있습니다.";
    try {
      const response = await window.fetch(
        "/api/v1/result-explanations/follow-up/stream",
        {
          method: "POST",
          headers: {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken.content
          },
          body: JSON.stringify({
            result_id: selectedFollowUpContext.resultId,
            result_version: selectedFollowUpContext.resultVersion,
            selected_control_id: selectedFollowUpContext.controlId,
            question: question,
            explanation_input: selectedFollowUpContext.explanationInput,
            profile: "FAST",
            test_environment_result: true
          }),
          cache: "no-store"
        }
      );
      if (!response.ok || !response.body) {
        throw new Error("Result follow-up stream unavailable");
      }
      const reader = response.body.getReader();
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
          const dataLine = block.split("\n").find(function (line) {
            return line.startsWith("data: ");
          });
          if (dataLine) {
            processFollowUpEvent(JSON.parse(dataLine.slice(6)));
          }
        });
        if (chunk.done) {
          if (buffer.trim()) {
            const dataLine = buffer.split("\n").find(function (line) {
              return line.startsWith("data: ");
            });
            if (dataLine) {
              processFollowUpEvent(JSON.parse(dataLine.slice(6)));
            }
          }
          break;
        }
      }
    } catch (_error) {
      resultFollowUpAnswer.hidden = true;
      resultFollowUpStatus.textContent =
        "AI 연결을 확인하지 못했습니다. 공식 판정은 그대로입니다.";
    } finally {
      resultFollowUpSubmit.disabled = false;
    }
  }

  function renderAssessmentCounts(items) {
    const counts = {
      PASS: 0,
      FAIL: 0,
      ERROR: 0,
      REVIEW: 0,
      "N/A": 0
    };
    items.forEach(function (item) {
      const status = normalizeProductStatus(item.assessment_status);
      if (Object.prototype.hasOwnProperty.call(counts, status)) {
        counts[status] += 1;
      }
    });
    pass.textContent = String(counts.PASS);
    fail.textContent = String(counts.FAIL);
    error.textContent = String(counts.ERROR);
    review.textContent = String(counts.REVIEW);
    notEvaluated.textContent = String(
      items.length -
      counts.PASS -
      counts.FAIL -
      counts.ERROR -
      counts.REVIEW -
      counts["N/A"]
    );
  }

  function renderHistory(items) {
    history.replaceChildren();
    items.slice().reverse().forEach(function (item) {
      const row = element("li", "");
      const copy = element("div", "");
      copy.appendChild(
        element("strong", "", item.sequence + "번째 점검 · 시도 " + item.attempt)
      );
      copy.appendChild(
        element(
          "span",
          "",
          "양호 " + item.assessment_counts.pass +
          " · 취약 " + item.assessment_counts.fail +
          " · 수집 오류 " + item.assessment_counts.error +
          " · 기준 확인 필요 " + (item.assessment_counts.review || 0) +
          " · 판정 전 " + item.assessment_counts.not_evaluated
        )
      );
      row.appendChild(copy);
      row.appendChild(
        element(
          "span",
          "history-change",
          item.sequence === 1
            ? "비교 기준"
            : "직전 점검과 달라진 항목 " + item.changed_control_count + "개"
        )
      );
      history.appendChild(row);
    });
  }

  function formatObservedAt(value) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return "점검 시각을 확인할 수 없습니다.";
    }
    return "점검 시각 " + parsed.toLocaleString("ko-KR");
  }

  async function persistCompletedResult(result) {
    if (!persistenceStatus) {
      return;
    }
    const key = String(result.result_id) + ":" + String(result.sequence);
    if (persistedResultRequests.has(key)) {
      return persistedResultRequests.get(key);
    }
    if (persistedResultKeys.has(key)) {
      return true;
    }
    persistedResultKeys.add(key);
    persistenceStatus.textContent = "점검 결과를 내 이력에 저장하고 있습니다.";
    const request = (async function () {
      try {
        const response = await window.fetch("/api/v1/audit-history/windows", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken.content
          },
          body: JSON.stringify({
            result: result,
            test_environment_result: true
          })
        });
        if (!response.ok) {
          throw new Error("history persistence unavailable");
        }
        const stored = await response.json();
        persistenceStatus.textContent = stored.created
          ? "현재 로그인 아이디의 점검 이력에 저장했습니다."
          : "이미 저장된 동일 점검 결과를 확인했습니다.";
        // 저장된 결과 식별자를 알려주면 AI 설명을 항목 단위로 보관·복원할 수 있습니다.
        if (stored.entry_id) {
          window.dispatchEvent(new CustomEvent("secai:windows-snapshot-ready", {
            detail: {
              result_id: result.result_id,
              result_version: result.sequence,
              snapshot_id: stored.entry_id
            }
          }));
        }
        return true;
      } catch (_error) {
        persistedResultKeys.delete(key);
        persistedResultRequests.delete(key);
        persistenceStatus.textContent =
          "점검 결과를 이력에 저장하지 못했습니다. 결과 화면은 그대로 사용할 수 있습니다.";
        return false;
      }
    }());
    persistedResultRequests.set(key, request);
    return request;
  }

  async function persistWindowsPresentation(kind, administratorResult, aiScreen) {
    if (!currentResultSnapshot || !csrfToken) {
      return false;
    }
    const baseStored = await persistCompletedResult(currentResultSnapshot);
    if (!baseStored) {
      return false;
    }
    try {
      const response = await window.fetch(
        "/api/v1/audit-history/windows/presentation",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken.content
          },
          body: JSON.stringify({
            result_id: currentResultSnapshot.result_id,
            result_version: currentResultSnapshot.sequence,
            presentation_kind: kind,
            administrator_report: administratorResult || null,
            ai_screen: aiScreen || null,
            test_environment_result: true
          }),
          cache: "no-store"
        }
      );
      return response.ok;
    } catch (_error) {
      return false;
    }
  }

  async function loadServerWindowsPresentation(result) {
    try {
      const query = new URLSearchParams({
        result_id: result.result_id,
        result_version: String(result.sequence)
      });
      const response = await window.fetch(
        "/api/v1/audit-history/windows/presentation?" + query.toString(),
        {method: "GET", cache: "no-store"}
      );
      if (!response.ok) {
        return null;
      }
      const payload = await response.json();
      return payload && payload.available ? payload : null;
    } catch (_error) {
      return null;
    }
  }

  function selectedPersonalCriteriaId() {
    try {
      const selected = JSON.parse(
        window.localStorage.getItem(selectedCriteriaStorageKey) || "null"
      );
      return selected && typeof selected.personal_profile_id === "string"
        ? selected.personal_profile_id
        : "";
    } catch (_error) {
      return "";
    }
  }

  function selectedCriteriaContext() {
    try {
      const selected = JSON.parse(
        window.localStorage.getItem(selectedCriteriaStorageKey) || "null"
      );
      return selected && selected.criteria_context
        ? selected.criteria_context
        : null;
    } catch (_error) {
      return null;
    }
  }

  async function renderAppliedCriteria(boundCriteria) {
    if (
      !appliedCriteriaStatus ||
      !resultOrganizationCriteria ||
      !resultPersonalCriteria ||
      !resultCriteriaSha256
    ) {
      return;
    }
    if (boundCriteria && boundCriteria.criteria_sha256) {
      const organization = boundCriteria.organization_profile;
      const personal = boundCriteria.personal_profile;
      resultOrganizationCriteria.textContent = organization
        ? organization.name + " " + organization.version + "판"
        : "추가 기준 없음 · KISA·제품 기본값 자동 적용";
      resultPersonalCriteria.textContent = personal
        ? personal.name + " " + personal.version + "판"
        : "추가 기준 선택 안 함 · KISA·제품 기본값 적용";
      resultCriteriaSha256.textContent = boundCriteria.criteria_sha256;
      appliedCriteriaStatus.textContent = personal
        ? "KISA·제품 기본값에 선택한 조직·개인 추가 기준을 함께 적용했습니다."
        : organization
        ? "KISA·제품 기본값에 저장된 조직 기준을 함께 적용했습니다."
        : "모든 항목에 KISA·제품 기본값을 자동 적용했습니다.";
      return;
    }
    const profileId = selectedPersonalCriteriaId();
    const path = profileId
      ? "/api/v1/criteria/effective?personal_profile_id=" +
        encodeURIComponent(profileId)
      : "/api/v1/criteria/effective";
    try {
      const response = await window.fetch(path, {cache: "no-store"});
      if (!response.ok) {
        throw new Error("criteria unavailable");
      }
      const data = await response.json();
      resultOrganizationCriteria.textContent = data.organization_default
        ? data.organization_default.name + " " +
          data.organization_default.version +
          (data.selected_kind === "KISA_DEFAULT"
            ? "판 · 현재 선택하지 않음"
            : "판 · 이번 점검에 적용")
        : "추가 기준 없음 · KISA·제품 기본값 자동 적용";
      resultPersonalCriteria.textContent = data.selected_personal_profile
        ? data.selected_personal_profile.name + " " +
          data.selected_personal_profile.version + "판"
        : "추가 기준 선택 안 함 · KISA·제품 기본값 적용";
      resultCriteriaSha256.textContent = String(data.effective_sha256 || "");
      appliedCriteriaStatus.textContent = data.selected_personal_profile
        ? "KISA·제품 기본값 위에 선택한 조직·개인 기준을 추가했습니다."
        : data.selected_kind === "ORGANIZATION" && data.organization_default
        ? "KISA·제품 기본값에 저장된 조직 기준을 함께 적용했습니다."
        : "모든 항목에 KISA·제품 기본값을 자동 적용했습니다.";
    } catch (_error) {
      resultOrganizationCriteria.textContent = "확인하지 못함";
      resultPersonalCriteria.textContent = "확인하지 못함";
      resultCriteriaSha256.textContent = "확인하지 못함";
      appliedCriteriaStatus.textContent =
        "점검에 고정된 기준을 확인하지 못했습니다. 새 점검을 시작해 기준을 다시 고정해 주세요.";
    }
  }

  function showAdministratorWaiting() {
    content.hidden = true;
    connection.hidden = false;
    hideLauncherRecovery();
    progress.hidden = false;
    progress.value = 95;
    progress.textContent = "95%";
    title.textContent = "관리자 권한 항목을 확인하고 있습니다";
    message.textContent =
      "Windows 권한 확인이 끝나면 일반 점검과 관리자 점검 결과를 함께 표시합니다.";
    hideScanControlProgress();
  }

  function revealCompletedResults(administratorResults) {
    if (!currentResultSnapshot) {
      return;
    }
    connection.hidden = true;
    hideLauncherRecovery();
    content.hidden = false;
    administratorScanPanel.hidden = false;
    renderControls(standardControlItems);
    renderAssessmentCounts(standardControlItems);
    dispatchIntegratedResults(administratorResults || [], false);
    storeAIAnalysisPayload(administratorResults || []);
    openPendingAIAnalysis(administratorResults || []);
  }

  function renderCompleted(report) {
    const result = report.result;
    const counts = result.counts;
    const assessmentCounts = result.assessment_counts || {
      pass: 0,
      fail: 0,
      error: 0,
      review: 0,
      not_applicable: 0,
      not_evaluated: 18
    };
    standardControlItems = result.controls.map(normalizeProductControl);
    officialExplanationItems = new Map(
      (result.explanations || []).map(function (item) {
        return [item.control_id, item];
      })
    );
    aiExplanationInputItems = new Map(
      (result.ai_explanation_inputs || []).map(function (item) {
        return [item.control_id, item];
      })
    );
    if (currentResultId !== result.result_id) {
      selectedFollowUpContext = null;
      resultFollowUpPanel.hidden = true;
      resultFollowUpAnswer.hidden = true;
    }
    currentResultId = result.result_id;
    currentResultVersion = result.sequence;
    currentResultSnapshot = result;
    if (
      administratorReport &&
      administratorReport.standard_result_id !== result.result_id
    ) {
      administratorReport = null;
      window.sessionStorage.removeItem("secai_last_administrator_result");
    }
    showAdministratorWaiting();
    void renderAppliedCriteria(result.criteria_context);
    pass.textContent = String(assessmentCounts.pass);
    fail.textContent = String(assessmentCounts.fail);
    error.textContent = String(assessmentCounts.error);
    review.textContent = String(assessmentCounts.review);
    notEvaluated.textContent = String(assessmentCounts.not_evaluated);
    observedAt.textContent = formatObservedAt(result.observed_at_utc);
    if (result.comparison) {
      const comparisonSummary = result.comparison.summary || {};
      comparison.textContent =
        "개선 " + (comparisonSummary.improved || 0) +
        " · 악화 " + (comparisonSummary.worsened || 0) +
        " · 변경 없음 " + (comparisonSummary.unchanged || 0) +
        " · 남아 있는 위험 " + (comparisonSummary.remaining_risk || 0);
      renderRecheckComparison(result.comparison);
      loadAIRecheckComparison(result);
    } else {
      comparison.textContent = "첫 점검 결과입니다.";
      recheckComparisonPanel.hidden = true;
      aiComparisonContent.hidden = true;
    }
    recheck.disabled = report.can_recheck !== true;
    renderHistory(report.history || []);
    void persistCompletedResult(result);
    loadReportCapabilities().then(loadReportHistory);
    updateAdministratorButton();
    if (administratorReport) {
      renderAdministratorResult(administratorReport);
    } else {
      void loadServerWindowsPresentation(result).then(function (stored) {
        if (stored && stored.administrator_report) {
          renderAdministratorResult(stored.administrator_report, false);
          return;
        }
        void startConsentedAdministratorScan(report).then(function (started) {
          if (!started) {
            revealCompletedResults([]);
          }
        });
      });
    }
  }

  function renderWaiting(report) {
    content.hidden = true;
    connection.hidden = false;
    hideLauncherRecovery();
    progress.hidden = false;
    progress.value = Number.isInteger(report.progress_percent)
      ? report.progress_percent
      : 0;
    progress.textContent = String(progress.value) + "%";
    title.textContent = report.status === "CANCELLING"
      ? "점검을 안전하게 멈추는 중입니다"
      : "PC 점검을 진행하고 있습니다";
    message.textContent = report.message || "잠시만 기다려 주세요.";
    renderScanControlProgress(report);
    schedulePoll();
  }

  async function request(path, method) {
    const options = {
      method: method,
      headers: {"X-SecAI-Launcher-Token": token || ""},
      cache: "no-store"
    };
    if (
      method === "POST" &&
      ["/v1/scan", "/v1/retry", "/v1/recheck"].includes(path)
    ) {
      const criteriaContext = selectedCriteriaContext();
      if (criteriaContext) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify({criteria_context: criteriaContext});
      }
    }
    const response = await window.fetch(bridgeUrl + path, options);
    const report = await response.json();
    if (!response.ok && response.status !== 409) {
      throw new Error("launcher unavailable");
    }
    return report;
  }

  function pendingStandardScanConsentIsValid() {
    try {
      const consent = JSON.parse(
        window.localStorage.getItem(pendingScanConsentKey) || "null"
      );
      return Boolean(
        consent &&
        Number.isInteger(consent.expires_at) &&
        consent.expires_at >= Date.now()
      );
    } catch (_error) {
      return false;
    }
  }

  function readPendingAdministratorConsent() {
    try {
      const consent = JSON.parse(
        window.localStorage.getItem(pendingAdministratorConsentKey) || "null"
      );
      const allowedProbeIds = Array.from(administratorOptions).map(
        function (option) { return option.value; }
      );
      const valid = Boolean(
        consent &&
        consent.consent === true &&
        consent.consent_version === administratorButton.dataset.consentVersion &&
        Array.isArray(consent.probe_ids) &&
        consent.probe_ids.length === allowedProbeIds.length &&
        consent.probe_ids.every(function (probeId, index) {
          return probeId === allowedProbeIds[index];
        }) &&
        Number.isInteger(consent.expires_at) &&
        consent.expires_at >= Date.now()
      );
      if (valid) {
        return consent;
      }
    } catch (_error) {
      // 손상되거나 만료된 동의는 관리자 실행에 사용하지 않습니다.
    }
    window.localStorage.removeItem(pendingAdministratorConsentKey);
    return null;
  }

  function consumePendingAdministratorConsent() {
    const consent = readPendingAdministratorConsent();
    window.localStorage.removeItem(pendingAdministratorConsentKey);
    return consent;
  }

  function clearPendingStandardScanRequest() {
    window.localStorage.removeItem(pendingScanConsentKey);
    const cleanUrl = new URL(window.location.href);
    cleanUrl.searchParams.delete("start_scan");
    window.history.replaceState(
      null,
      "",
      cleanUrl.pathname + cleanUrl.search + cleanUrl.hash
    );
  }

  async function startRequestedStandardScan() {
    if (!scanStartWasRequested) {
      return false;
    }
    if (!pendingStandardScanConsentIsValid()) {
      clearPendingStandardScanRequest();
      window.localStorage.removeItem(pendingAdministratorConsentKey);
      title.textContent = "점검 동의 시간이 지났습니다";
      message.textContent = "PC 점검 화면에서 안내를 확인하고 다시 동의해 주세요.";
      progress.hidden = true;
      hideScanControlProgress();
      content.hidden = true;
      return true;
    }
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
      title.textContent = "SecAI Windows 실행 파일을 열어 주세요";
      message.textContent = "실행 파일이 연결되면 이 결과 화면에서 점검을 자동으로 시작합니다.";
      progress.hidden = true;
      hideScanControlProgress();
      content.hidden = true;
      showLauncherRecovery(
        "프로그램을 이미 실행했다면 연결 다시 확인을 눌러 주세요."
      );
      return true;
    }

    hideLauncherRecovery();

    try {
      const current = await request("/v1/status", "GET");
      let report = current;
      if (current.status === "READY" && current.scan_available === true) {
        report = await request("/v1/scan", "POST");
      } else if (current.status === "COMPLETED") {
        report = await request("/v1/recheck", "POST");
      } else if (current.status === "CANCELLED" || current.status === "FAILED") {
        report = await request("/v1/retry", "POST");
      }
      clearPendingStandardScanRequest();
      if (report.status === "COMPLETED" && report.result) {
        stopPolling();
        renderCompleted(report);
      } else {
        renderWaiting(report);
      }
    } catch (_error) {
      stopPolling();
      title.textContent = "Windows 실행 파일과 연결되지 않았습니다";
      message.textContent = "SecAI Windows 실행 파일을 다시 열면 이 결과 화면에서 점검을 이어서 시작합니다.";
      progress.hidden = true;
      hideScanControlProgress();
      content.hidden = true;
      showLauncherRecovery(
        "실행 파일을 다시 연 뒤 연결 다시 확인을 눌러 주세요."
      );
    }
    return true;
  }

  function selectedAdministratorProbes() {
    return Array.from(administratorOptions)
      .filter(function (option) { return option.checked; })
      .map(function (option) { return option.value; });
  }

  function updateAdministratorButton() {
    administratorButton.disabled = !(
      content.hidden === false &&
      administratorConsent.checked &&
      selectedAdministratorProbes().length > 0
    );
  }

  function preserveStandardTokenForAdministratorTab() {
    if (!token) {
      return;
    }
    window.localStorage.setItem(
      "secai_launcher_continuation",
      JSON.stringify({
        token: token,
        expires_at: Date.now() + 120000
      })
    );
    window.setTimeout(function () {
      window.localStorage.removeItem("secai_launcher_continuation");
    }, 120000);
  }

  function adoptAdministratorToken(report) {
    const received = report && report.administrator
      ? report.administrator.result_token
      : null;
    if (!received || !/^[A-Za-z0-9_-]{43}$/.test(received)) {
      return false;
    }
    administratorToken = received;
    administratorLoadAttempt = 0;
    window.sessionStorage.setItem(
      "secai_administrator_launcher_token",
      received
    );
    return true;
  }

  function showAdministratorRecheck(messageText) {
    administratorOptions.forEach(function (option) {
      option.disabled = false;
      option.checked = false;
    });
    administratorConsent.disabled = false;
    administratorConsent.checked = false;
    administratorButton.disabled = true;
    administratorButton.hidden = false;
    administratorOptionsPanel.hidden = false;
    administratorConsentPanel.hidden = false;
    administratorScanPanel.hidden = false;
    administratorStatus.textContent = messageText;
  }

  async function launchAdministratorSelection(
    selected,
    consentVersion,
    automatic
  ) {
    administratorButton.disabled = true;
    administratorStatus.textContent =
      automatic
        ? "일반 점검을 완료했습니다. Windows 권한 확인창에서 ‘예’를 선택해 주세요."
        : "Windows 관리자 권한 확인창을 준비하고 있습니다.";
    if (automatic) {
      administratorScanPanel.hidden = true;
    }
    preserveStandardTokenForAdministratorTab();
    try {
      const response = await window.fetch(
        bridgeUrl + "/v1/administrator/launch",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-SecAI-Launcher-Token": token || ""
          },
          body: JSON.stringify({
            consent: true,
            consent_version: consentVersion,
            probe_ids: selected
          }),
          cache: "no-store"
        }
      );
      const report = await response.json();
      const state = report.administrator
        ? report.administrator.status
        : "FAILED";
      if (state === "STARTED") {
        administratorStatus.textContent =
          "Windows 권한이 허용되었습니다. 관리자 5개 항목을 확인하고 있습니다.";
        administratorScanPanel.hidden = true;
        administratorOptions.forEach(function (option) {
          option.disabled = true;
        });
        administratorConsent.disabled = true;
        if (adoptAdministratorToken(report)) {
          window.setTimeout(loadAdministratorResult, 250);
        }
        return true;
      }
      window.localStorage.removeItem("secai_launcher_continuation");
      if (state === "CANCELLED_OR_DENIED") {
        administratorStatus.textContent =
          "Windows 권한 확인창에서 ‘예’를 선택하지 않아 관리자 5개 항목을 확인하지 않았습니다. 일반 점검 결과는 그대로입니다.";
      } else {
        administratorStatus.textContent =
          "관리자 추가 점검을 시작하지 못했습니다. 실행 파일 연결을 확인해 주세요.";
      }
      showAdministratorRecheck(administratorStatus.textContent);
      return false;
    } catch (_error) {
      window.localStorage.removeItem("secai_launcher_continuation");
      administratorStatus.textContent =
        "관리자 추가 점검 요청을 확인하지 못했습니다. 일반 결과는 그대로입니다.";
      showAdministratorRecheck(administratorStatus.textContent);
      return false;
    }
  }

  async function launchAdministrator() {
    await launchAdministratorSelection(
      selectedAdministratorProbes(),
      administratorButton.dataset.consentVersion,
      false
    );
  }

  async function startConsentedAdministratorScan(report) {
    if (
      automaticAdministratorLaunchInFlight ||
      administratorReport ||
      administratorToken
    ) {
      return true;
    }
    const state = report.administrator
      ? report.administrator.status
      : "NOT_REQUESTED";
    if (state === "REQUESTING_UAC" || state === "STARTED") {
      window.localStorage.removeItem(pendingAdministratorConsentKey);
      administratorScanPanel.hidden = true;
      administratorStatus.textContent =
        "Windows 권한 확인 후 관리자 5개 항목을 확인하고 있습니다.";
      if (adoptAdministratorToken(report)) {
        window.setTimeout(loadAdministratorResult, 250);
      }
      return true;
    }
    if (!["NOT_REQUESTED", "CANCELLED_OR_DENIED", "FAILED"].includes(state)) {
      return false;
    }
    const consent = consumePendingAdministratorConsent();
    if (!consent) {
      return false;
    }
    administratorOptions.forEach(function (option) {
      option.checked = consent.probe_ids.includes(option.value);
    });
    administratorConsent.checked = true;
    automaticAdministratorLaunchInFlight = true;
    try {
      return await launchAdministratorSelection(
        consent.probe_ids,
        consent.consent_version,
        true
      );
    } finally {
      automaticAdministratorLaunchInFlight = false;
    }
  }

  function storeAIAnalysisPayload(administratorResults) {
    if (!currentResultSnapshot) {
      return;
    }
    window.sessionStorage.setItem(
      aiAnalysisPayloadKey,
      JSON.stringify({
        result_id: currentResultSnapshot.result_id,
        result_version: currentResultSnapshot.sequence,
        explanation_inputs:
          currentResultSnapshot.ai_explanation_inputs || [],
        administrator_results: administratorResults || []
      })
    );
  }

  function dispatchIntegratedResults(administratorResults, aiReady) {
    if (!currentResultSnapshot) {
      return;
    }
    const detail = {
      result_id: currentResultSnapshot.result_id,
      result_version: currentResultSnapshot.sequence,
      items: standardControlItems.map(normalizeProductControl),
      explanations: Array.from(officialExplanationItems.values()),
      explanation_inputs: currentResultSnapshot.ai_explanation_inputs || [],
      administrator_results: administratorResults || [],
      ai_ready: aiReady === true
    };
    window.SecAIProductResultsState = detail;
    window.dispatchEvent(new CustomEvent("secai:product-results", {detail: detail}));
  }

  function openPendingAIAnalysis(administratorResults) {
    storeAIAnalysisPayload(administratorResults);
    window.localStorage.removeItem(aiAnalysisPendingKey);
    dispatchIntegratedResults(administratorResults, true);
  }

  function updateControlFromAdministrator(item) {
    const index = standardControlItems.findIndex(function (control) {
      return control.control_id === item.control_id;
    });
    if (index < 0) {
      return;
    }
    standardControlItems[index] = normalizeProductControl(
      Object.assign(
        {},
        standardControlItems[index],
        item,
        {
          checked_summary: item.collected_summary ||
            standardControlItems[index].checked_summary,
          administrator_verified: true
        }
      )
    );
  }

  function mergeAdministratorResults(previous, latest) {
    const byControl = new Map();
    (previous || []).concat(latest || []).forEach(function (item) {
      if (item && typeof item.control_id === "string") {
        byControl.set(item.control_id, item);
      }
    });
    return Array.from(byControl.values()).sort(function (left, right) {
      return left.control_id.localeCompare(right.control_id, "en", {numeric: true});
    });
  }

  function renderAdministratorResult(latestResult, persistResult) {
    const previousResults = administratorReport &&
      administratorReport.standard_result_id === currentResultId
      ? administratorReport.results || []
      : [];
    const canonicalAdministratorResults = mergeAdministratorResults(
      previousResults,
      latestResult.results || []
    );
    const result = Object.assign({}, latestResult, {
      standard_result_id: currentResultId,
      results: canonicalAdministratorResults
    });
    administratorReport = result;
    window.sessionStorage.setItem(
      "secai_last_administrator_result",
      JSON.stringify(administratorReport)
    );
    if (persistResult !== false) {
      void persistWindowsPresentation("ADMINISTRATOR", result, null);
    }
    canonicalAdministratorResults.forEach(function (item) {
      updateControlFromAdministrator(item);
    });
    revealCompletedResults(result.results || []);
    const collectionErrorCount = Number(latestResult.collection_error_count || 0);
    const assessmentReviewCount = Number(latestResult.assessment_review_count || 0);
    showAdministratorRecheck(
      "관리자 권한 결과 " + latestResult.selected_probe_count + "개를 반영했습니다. " +
      "수집 오류 " + collectionErrorCount + "개 · 기준 확인 필요 " +
      assessmentReviewCount +
      "개입니다. 필요한 항목만 선택하여 다시 점검할 수 있습니다."
    );
    const firstResult = controls.querySelector(
      '[data-control-id="' + latestResult.results[0]?.control_id + '"]'
    );
    if (firstResult) {
      firstResult.scrollIntoView({behavior: "smooth", block: "center"});
    }
  }

  async function resetAdministratorLaunchState() {
    try {
      await window.fetch(bridgeUrl + "/v1/administrator/reset", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SecAI-Launcher-Token": token || ""
        },
        body: "{}",
        cache: "no-store"
      });
    } catch (_error) {
      administratorStatus.textContent +=
        " 다시 실행 준비에 실패했으므로 Windows 실행 파일을 다시 열어 주세요.";
    }
  }

  async function loadAdministratorResult() {
    if (
      !administratorToken ||
      !/^[A-Za-z0-9_-]{43}$/.test(administratorToken)
    ) {
      return;
    }
    try {
      const response = await window.fetch(
        administratorBridgeUrl + "/v1/status",
        {
          method: "GET",
          headers: {
            "X-SecAI-Administrator-Token": administratorToken
          },
          cache: "no-store"
        }
      );
      const result = await response.json();
      if (response.ok && result.status === "COMPLETED") {
        administratorLoadAttempt = 0;
        renderAdministratorResult(result);
        window.sessionStorage.removeItem(
          "secai_administrator_launcher_token"
        );
        administratorToken = null;
        await resetAdministratorLaunchState();
      } else if (response.ok && result.status === "FAILED") {
        const failureMessage =
          result.message ||
          "관리자 추가 점검을 완료하지 못했습니다. 필요한 항목을 선택해 다시 점검해 주세요.";
        administratorStatus.textContent = failureMessage;
        window.sessionStorage.removeItem(
          "secai_administrator_launcher_token"
        );
        administratorToken = null;
        await resetAdministratorLaunchState();
        showAdministratorRecheck(failureMessage);
        revealCompletedResults([]);
      } else if (
        response.ok &&
        (result.status === "PENDING" ||
          result.status === "RUNNING" ||
          result.status === "STARTING")
      ) {
        administratorLoadAttempt += 1;
        administratorStatus.textContent =
          result.message || "관리자 점검 결과를 불러오는 중입니다.";
        if (administratorLoadAttempt <= 1200) {
          window.setTimeout(loadAdministratorResult, 500);
        }
      } else {
        administratorLoadAttempt += 1;
        if (administratorLoadAttempt <= 1200) {
          administratorStatus.textContent =
            result.message || "관리자 점검 결과를 연결하고 있습니다.";
          window.setTimeout(loadAdministratorResult, 500);
        } else {
          administratorStatus.textContent =
            result.message || "관리자 추가 점검을 완료하지 못했습니다.";
          showAdministratorRecheck(administratorStatus.textContent);
          revealCompletedResults([]);
        }
      }
    } catch (_error) {
      administratorLoadAttempt += 1;
      if (administratorLoadAttempt <= 1200) {
        administratorStatus.textContent =
          "관리자 점검 결과를 불러오는 중입니다.";
        window.setTimeout(loadAdministratorResult, 500);
      } else {
        administratorStatus.textContent =
          "관리자 점검 결과를 10분 안에 받지 못했습니다. 필요한 항목을 선택해 다시 점검해 주세요.";
        showAdministratorRecheck(administratorStatus.textContent);
        revealCompletedResults([]);
      }
    }
  }

  async function loadResult() {
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
      title.textContent = "먼저 Windows 점검을 실행해 주세요";
      message.textContent = "SecAI Windows 실행 파일을 열어 점검을 마치면 이 화면에 실제 결과가 표시됩니다.";
      progress.hidden = true;
      hideScanControlProgress();
      content.hidden = true;
      showLauncherRecovery(
        "점검 프로그램을 다운로드하거나 실행한 뒤 연결을 확인해 주세요."
      );
      return;
    }
    hideLauncherRecovery();
    try {
      const report = await request("/v1/status", "GET");
      if ((report.status === "RUNNING" || report.status === "CANCELLING")) {
        renderWaiting(report);
      } else if (report.status === "COMPLETED" && report.result) {
        stopPolling();
        renderCompleted(report);
      } else {
        title.textContent = "완료된 점검 결과가 없습니다";
        message.textContent = "처음 화면에서 점검을 시작하거나 중단된 점검을 다시 시도해 주세요.";
        progress.hidden = true;
        hideScanControlProgress();
        content.hidden = true;
      }
    } catch (_error) {
      stopPolling();
      title.textContent = "Windows 실행 파일과 연결되지 않았습니다";
      message.textContent = "점검에 사용한 SecAI Windows 실행 파일을 다시 열어 주세요.";
      progress.hidden = true;
      hideScanControlProgress();
      content.hidden = true;
      showLauncherRecovery(
        "실행 파일을 다시 연 뒤 연결 다시 확인을 눌러 주세요."
      );
    }
  }

  async function retryLauncherConnection() {
    launcherRetryConnection.disabled = true;
    launcherRecoveryStatus.textContent = "실행 파일 연결 상태를 확인하고 있습니다.";
    if (!refreshLauncherToken()) {
      title.textContent = "아직 Windows 실행 파일이 연결되지 않았습니다";
      message.textContent = "다운로드한 파일을 먼저 실행한 뒤 다시 확인해 주세요.";
      launcherRecoveryStatus.textContent =
        "새 탭에서 연결이 완료된 뒤 이 버튼을 다시 눌러 주세요.";
      launcherRetryConnection.disabled = false;
      return;
    }

    try {
      const report = await request("/v1/status", "GET");
      if (report.status === "RUNNING" || report.status === "CANCELLING") {
        renderWaiting(report);
      } else if (report.status === "COMPLETED" && report.result) {
        stopPolling();
        renderCompleted(report);
      } else if (
        scanStartWasRequested &&
        pendingStandardScanConsentIsValid()
      ) {
        await startRequestedStandardScan();
      } else {
        title.textContent = "Windows 실행 파일이 연결되었습니다";
        message.textContent =
          "점검 동의를 다시 확인하려면 원클릭 점검으로 돌아가 주세요.";
        progress.hidden = true;
        hideScanControlProgress();
        showLauncherRecovery(
          "연결은 정상입니다. 원클릭 점검으로 돌아가 점검을 시작할 수 있습니다."
        );
      }
    } catch (_error) {
      title.textContent = "Windows 실행 파일과 아직 통신할 수 없습니다";
      message.textContent = "실행 파일이 열려 있는지 확인한 뒤 다시 시도해 주세요.";
      showLauncherRecovery(
        "같은 PC에서 실행 파일을 한 번만 열고 다시 확인해 주세요."
      );
    } finally {
      launcherRetryConnection.disabled = false;
    }
  }

  recheck.addEventListener("click", async function () {
    recheck.disabled = true;
    selectedFollowUpContext = null;
    resultFollowUpPanel.hidden = true;
    recheckComparisonPanel.hidden = true;
    aiComparisonContent.hidden = true;
    connection.hidden = false;
    content.hidden = true;
    title.textContent = "재점검을 시작하고 있습니다";
    message.textContent = "PC 설정은 바꾸지 않고 같은 항목을 다시 읽습니다.";
    progress.hidden = false;
    progress.value = 0;
    try {
      const report = await request("/v1/recheck", "POST");
      renderWaiting(report);
    } catch (_error) {
      title.textContent = "재점검을 시작하지 못했습니다";
      message.textContent = "Windows 실행 파일 연결을 확인한 뒤 다시 시도해 주세요.";
      showLauncherRecovery(
        "실행 파일을 다시 연 뒤 연결 다시 확인을 눌러 주세요."
      );
      recheck.disabled = false;
    }
  });

  openRecheckControls.addEventListener("click", function () {
    administratorScanPanel.hidden = false;
    recheckControlsPanel.open = true;
    recheckControlsPanel.scrollIntoView({behavior: "smooth", block: "start"});
  });

  openAIAnalysis.addEventListener("click", function () {
    storeAIAnalysisPayload(
      administratorReport && Array.isArray(administratorReport.results)
        ? administratorReport.results
        : []
    );
    dispatchIntegratedResults(
      administratorReport && Array.isArray(administratorReport.results)
        ? administratorReport.results
        : [],
      true
    );
  });

  userReportButton.addEventListener("click", function () {
    createReport("USER");
  });
  technicalReportButton.addEventListener("click", function () {
    createReport("TECHNICAL");
  });
  launcherOpenHelp.addEventListener("click", function () {
    const expanded = launcherOpenHelp.getAttribute("aria-expanded") === "true";
    launcherOpenHelp.setAttribute("aria-expanded", String(!expanded));
    launcherOpenHelpPanel.hidden = expanded;
  });
  launcherRetryConnection.addEventListener("click", function () {
    void retryLauncherConnection();
  });
  window.addEventListener("storage", function (event) {
    if (event.key !== launcherContinuationKey || !event.newValue) {
      return;
    }
    try {
      const received = JSON.parse(event.newValue);
      if (
        received &&
        /^[A-Za-z0-9_-]{43}$/.test(received.token) &&
        Number.isInteger(received.expires_at) &&
        received.expires_at >= Date.now()
      ) {
        token = received.token;
        window.sessionStorage.setItem("secai_launcher_token", token);
        if (!launcherRecovery.hidden) {
          launcherRecoveryStatus.textContent =
            "실행 파일의 연결 정보를 받았습니다. 연결 다시 확인을 눌러 주세요.";
        }
      }
    } catch (_error) {
      // 다른 탭의 손상된 저장 이벤트는 연결 정보로 사용하지 않습니다.
    }
  });
  administratorOptions.forEach(function (option) {
    option.addEventListener("change", updateAdministratorButton);
  });
  administratorConsent.addEventListener("change", updateAdministratorButton);
  administratorButton.addEventListener("click", launchAdministrator);
  resultFollowUpClose.addEventListener("click", function () {
    resultFollowUpPanel.hidden = true;
  });
  resultFollowUpForm.addEventListener("submit", function (event) {
    event.preventDefault();
    submitResultFollowUp();
  });
  document.querySelectorAll("[data-follow-up-question]").forEach(
    function (button) {
      button.addEventListener("click", function () {
        resultFollowUpQuestion.value =
          button.getAttribute("data-follow-up-question") || "";
        resultFollowUpQuestion.focus();
      });
    }
  );
  window.addEventListener("hashchange", function () {
    const received = captureAdministratorToken();
    if (received) {
      administratorToken = received;
      administratorLoadAttempt = 0;
      loadAdministratorResult();
    }
  });
  window.addEventListener("secai:windows-ai-snapshot-completed", function (event) {
    const detail = event.detail || {};
    if (
      !currentResultSnapshot ||
      detail.result_id !== currentResultSnapshot.result_id ||
      detail.result_version !== currentResultSnapshot.sequence
    ) {
      return;
    }
    void persistWindowsPresentation(
      "AI_COMPLETED",
      administratorReport,
      detail.ai_screen
    );
  });

  try {
    const savedAdministratorResult = JSON.parse(
      window.sessionStorage.getItem("secai_last_administrator_result") || "null"
    );
    if (
      savedAdministratorResult &&
      savedAdministratorResult.status === "COMPLETED" &&
      Array.isArray(savedAdministratorResult.results)
    ) {
      administratorReport = savedAdministratorResult;
    }
  } catch (_error) {
    window.sessionStorage.removeItem("secai_last_administrator_result");
  }

  async function initializeResultPage() {
    if (await startRequestedStandardScan()) {
      return;
    }
    await loadResult();
  }

  void initializeResultPage().then(function () {
    return loadAdministratorResult();
  });
}());
