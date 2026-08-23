(function () {
  "use strict";

  // [카드수정] PC 점검 카드의 시작 버튼과 동의창 동작을 연결합니다.
  const button = document.getElementById("start-standard-scan");
  const consentDialog = document.getElementById("scan-consent-dialog");
  const administratorDisclosure = document.getElementById(
    "administrator-scan-disclosure"
  );
  const consentCheck = document.getElementById("scan-consent-check");
  const confirmButton = document.getElementById("confirm-standard-scan");
  const closeConsentButton = document.getElementById("close-scan-consent");
  const personalCriteria = document.getElementById("scan-personal-criteria");
  const criteriaStatus = document.getElementById("scan-criteria-status");
  const organizationCriteria = document.getElementById(
    "scan-organization-criteria"
  );
  if (
    !button ||
    !consentDialog ||
    !administratorDisclosure ||
    !consentCheck ||
    !confirmButton ||
    !closeConsentButton ||
    !personalCriteria ||
    !criteriaStatus ||
    !organizationCriteria
  ) {
    return;
  }

  const consentStorageKey = "secai_pending_standard_scan_consent";
  const administratorConsentStorageKey =
    "secai_pending_administrator_scan_consent";
  const aiAnalysisPendingKey = "secai_ai_analysis_pending";
  const consentLifetimeMilliseconds = 120000;
  const selectedCriteriaStorageKey = "secai_selected_criteria_profile";
  const csrfToken = document.querySelector('meta[name="csrf-token"]');
  let criteriaReady = false;
  const explicitNewScan = new URLSearchParams(window.location.search).get(
    "new_scan"
  ) === "1";

  if (explicitNewScan) {
    window.localStorage.removeItem(consentStorageKey);
    window.localStorage.removeItem(administratorConsentStorageKey);
    window.localStorage.removeItem(aiAnalysisPendingKey);
    window.history.replaceState(null, "", "/");
  }

  async function loadCriteriaOptions(personalProfileId, restoreSavedSelection) {
    criteriaReady = false;
    confirmButton.disabled = true;
    const effectiveCriteriaPath = "/api/v1/criteria/effective";
    const defaultKind = personalCriteria.dataset.defaultKind || "KISA_DEFAULT";
    const path = personalProfileId
      ? effectiveCriteriaPath + "?personal_profile_id=" +
        encodeURIComponent(personalProfileId)
      : restoreSavedSelection
      ? effectiveCriteriaPath
      : effectiveCriteriaPath + "?selection_kind=" +
        encodeURIComponent(defaultKind);
    try {
      let response = await window.fetch(path, {cache: "no-store"});
      if (!response.ok && personalProfileId) {
        response = await window.fetch(
          effectiveCriteriaPath + "?selection_kind=" +
            encodeURIComponent(defaultKind),
          {cache: "no-store"}
        );
        personalProfileId = "";
      }
      if (!response.ok) {
        throw new Error("criteria unavailable");
      }
      const data = await response.json();
      const selectedPersonal = data.selected_personal_profile;
      const organization = data.organization_default;
      const resolvedDefaultKind = organization
        ? "ORGANIZATION"
        : "KISA_DEFAULT";
      personalCriteria.dataset.defaultKind = resolvedDefaultKind;
      personalCriteria.dataset.selectedKind = data.selected_kind || resolvedDefaultKind;
      const current = personalProfileId || (
        selectedPersonal && selectedPersonal.id
          ? selectedPersonal.id
          : ""
      );
      const blankOption = data.selected_kind === "ORGANIZATION" && organization
        ? new Option("조직 기본 기준 (현재 적용)", "")
        : selectedPersonal && organization
        ? new Option("조직 기본 기준 (개인 기준 해제 시)", "")
        : new Option("KISA·제품 기본 기준", "");
      personalCriteria.replaceChildren(blankOption);
      (data.personal_profiles || []).forEach(function (profile) {
        personalCriteria.appendChild(
          new Option(profile.name + " · " + profile.version + "판", profile.id)
        );
      });
      personalCriteria.value = current;
      organizationCriteria.textContent = organization
        ? organization.name + " " + organization.version +
          (data.selected_kind === "KISA_DEFAULT"
            ? "판 · 현재 선택하지 않음"
            : "판 · 이번 점검에 적용")
        : "등록 없음";
      criteriaStatus.textContent = selectedPersonal
        ? selectedPersonal.name +
          "을 KISA·제품 기본 기준에 추가 적용합니다."
        : data.selected_kind === "ORGANIZATION" && organization
        ? organization.name + "을 KISA·제품 기본 기준에 추가 적용합니다."
        : "KISA·제품 기본 기준을 자동 적용합니다.";
      const effectiveValues = {};
      const effectiveSources = {};
      (data.effective || []).forEach(function (item) {
        effectiveValues[item.key] = item.value;
        effectiveSources[item.key] = item.source;
      });
      function profileContext(profile) {
        return profile ? {
          id: profile.id,
          name: profile.name,
          version: profile.version,
          document_sha256: profile.document_sha256
        } : null;
      }
      window.localStorage.setItem(
        selectedCriteriaStorageKey,
        JSON.stringify({
          personal_profile_id: personalCriteria.value || null,
          criteria_context: {
            values: effectiveValues,
            sources: effectiveSources,
            criteria_sha256: data.effective_sha256,
            organization_profile: profileContext(
              data.selected_kind === "KISA_DEFAULT" ? null : organization
            ),
            personal_profile: profileContext(selectedPersonal)
          },
          selected_at: Date.now()
        })
      );
      criteriaReady = true;
      confirmButton.disabled = !consentCheck.checked;
    } catch (_error) {
      criteriaReady = false;
      criteriaStatus.textContent =
        "저장된 기준을 확인하지 못해 KISA·제품 기본값으로 점검합니다.";
      organizationCriteria.textContent = "기본값 적용";
      confirmButton.disabled = true;
    }
  }

  async function recordScanStartCriteria() {
    if (!csrfToken || !csrfToken.content) {
      throw new Error("csrf unavailable");
    }
    const selected = JSON.parse(
      window.localStorage.getItem(selectedCriteriaStorageKey) || "null"
    );
    const context = selected && selected.criteria_context;
    if (!context || typeof context.criteria_sha256 !== "string") {
      throw new Error("criteria context unavailable");
    }
    const selectionKind = personalCriteria.value
      ? "PERSONAL"
      : personalCriteria.dataset.selectedKind === "PERSONAL"
      ? (personalCriteria.dataset.defaultKind || "KISA_DEFAULT")
      : (personalCriteria.dataset.selectedKind ||
        personalCriteria.dataset.defaultKind || "KISA_DEFAULT");
    const body = new URLSearchParams({
      selection_kind: selectionKind,
      expected_criteria_sha256: context.criteria_sha256,
      csrf_token: csrfToken.content
    });
    if (personalCriteria.value) {
      body.set("personal_profile_id", personalCriteria.value);
    }
    const response = await window.fetch("/api/v1/criteria/scan-start", {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: body.toString(),
      cache: "no-store"
    });
    if (!response.ok) {
      throw new Error("criteria history unavailable");
    }
  }

  function pendingConsentIsValid() {
    try {
      const consent = JSON.parse(
        window.localStorage.getItem(consentStorageKey) || "null"
      );
      if (
        consent &&
        Number.isInteger(consent.expires_at) &&
        consent.expires_at >= Date.now()
      ) {
        return true;
      }
    } catch (_error) {
      // 잘못된 브라우저 임시 상태는 폐기하고 새 동의를 받습니다.
    }
    window.localStorage.removeItem(consentStorageKey);
    return false;
  }

  function captureLauncherToken() {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const receivedToken = hash.get("launcher_token");
    if (!receivedToken || !/^[A-Za-z0-9_-]{43}$/.test(receivedToken)) {
      return false;
    }
    window.sessionStorage.setItem("secai_launcher_token", receivedToken);
    window.history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search
    );
    return true;
  }

  const launcherTokenWasCaptured = captureLauncherToken();
  const storedLauncherToken = window.sessionStorage.getItem(
    "secai_launcher_token"
  );
  const launcherTokenIsAvailable = launcherTokenWasCaptured || (
    storedLauncherToken && /^[A-Za-z0-9_-]{43}$/.test(storedLauncherToken)
  );
  if (launcherTokenIsAvailable) {
    try {
      window.localStorage.removeItem("secai_launcher_continuation");
    } catch (_error) {
      // 현재 탭의 session token은 유지하고 일회성 공유 정보만 폐기합니다.
    }
  }
  if (!explicitNewScan && launcherTokenIsAvailable && pendingConsentIsValid()) {
    window.location.assign("/ui/results?start_scan=1");
    return;
  }

  button.addEventListener("click", function () {
    consentCheck.checked = false;
    confirmButton.disabled = true;
    // 저장된 조직·개인 기준 선택을 불러오고, 없을 때만 KISA 기본값을 사용합니다.
    void loadCriteriaOptions("", true);
    if (typeof consentDialog.showModal === "function") {
      consentDialog.showModal();
    } else {
      consentDialog.setAttribute("open", "");
    }
  });

  personalCriteria.addEventListener("change", function () {
    void loadCriteriaOptions(personalCriteria.value, false);
  });

  consentCheck.addEventListener("change", function () {
    confirmButton.disabled = !consentCheck.checked || !criteriaReady;
  });

  closeConsentButton.addEventListener("click", function () {
    if (typeof consentDialog.close === "function") {
      consentDialog.close();
    } else {
      consentDialog.removeAttribute("open");
    }
  });

  confirmButton.addEventListener("click", async function () {
    if (!consentCheck.checked) {
      return;
    }
    confirmButton.disabled = true;
    try {
      await recordScanStartCriteria();
    } catch (_error) {
      criteriaStatus.textContent =
        "점검 기준 이력을 저장하지 못했습니다. 기준을 다시 확인한 뒤 시도해 주세요.";
      confirmButton.disabled = false;
      return;
    }
    const grantedAt = Date.now();
    window.localStorage.setItem(
      consentStorageKey,
      JSON.stringify({
        granted_at: grantedAt,
        expires_at: grantedAt + consentLifetimeMilliseconds
      })
    );
    const probeIds = Array.from(
      administratorDisclosure.querySelectorAll(
        "[data-administrator-probe-id]"
      )
    ).map(function (item) {
      return item.getAttribute("data-administrator-probe-id") || "";
    }).filter(Boolean);
    const consentVersion = administratorDisclosure.dataset.consentVersion || "";
    if (probeIds.length !== 5 || !consentVersion) {
      window.localStorage.removeItem(consentStorageKey);
      window.localStorage.removeItem(administratorConsentStorageKey);
      return;
    }
    window.localStorage.setItem(
      administratorConsentStorageKey,
      JSON.stringify({
        consent: true,
        consent_version: consentVersion,
        probe_ids: probeIds,
        granted_at: grantedAt,
        expires_at: grantedAt + consentLifetimeMilliseconds
      })
    );
    window.localStorage.setItem(
      aiAnalysisPendingKey,
      JSON.stringify({expires_at: grantedAt + consentLifetimeMilliseconds})
    );
    window.location.assign("/ui/results?start_scan=1");
  });
}());
