(function () {
  "use strict";

  const startButton = document.getElementById("switch-start");
  if (!startButton) return;

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const startPanel = document.getElementById("switch-start-panel");
  const progressPanel = document.getElementById("switch-progress-panel");
  const progressMessage = document.getElementById("switch-progress-message");
  const progressCount = document.getElementById("switch-progress-count");
  const progress = document.getElementById("switch-progress");
  const usernameInput = document.getElementById("switch-username");
  const passwordInput = document.getElementById("switch-password");
  const errorOutput = document.getElementById("switch-start-error");
  const criteriaResetButton = document.getElementById("switch-criteria-reset");
  const criteriaStorageKey = "secai_switch_criteria_v3";
  const criteriaFields = Array.from(document.querySelectorAll("[data-switch-criteria-key]"));
  const defaultCriteria = readCriteria();
  let polling = false;
  const totalControls = document.querySelectorAll("[data-control-id]").length;

  const failureMessages = {
    AUTHENTICATION_FAILED: "사용자 이름 또는 비밀번호가 올바르지 않습니다.",
    INSUFFICIENT_PRIVILEGE: "REST 자료를 읽을 권한이 부족합니다.",
    CERTIFICATE_MISMATCH: "등록된 장비 인증서와 일치하지 않아 연결을 차단했습니다.",
    CERTIFICATE_PIN_UNAVAILABLE: "서버에 등록된 인증서 확인값을 읽지 못했습니다.",
    TIMEOUT: "스위치가 제한 시간 안에 응답하지 않았습니다.",
    CONNECTION_FAILED: "스위치에 연결하지 못했습니다. 관리망과 장비 상태를 확인해 주세요.",
    TLS_CONNECTION_FAILED: "안전한 HTTPS 연결을 만들지 못했습니다.",
    UNSUPPORTED_API_VERSION: "현재 점검기가 지원하지 않는 AOS-CX REST 버전입니다."
  };

  function setControls(state, label) {
    document.querySelectorAll("[data-control-id]").forEach(function (row) {
      row.className = "scan-control-progress-item scan-control-progress-" + state;
      const output = row.querySelector(".scan-control-progress-status");
      if (output) output.textContent = label;
    });
  }

  function restoreForm() {
    startPanel.querySelectorAll("input, select, button").forEach(function (item) {
      item.disabled = false;
    });
    startButton.disabled = false;
    passwordInput.value = "";
    passwordInput.focus();
  }

  function readCriteria() {
    return Object.fromEntries(criteriaFields.map(function (field) {
      const key = field.dataset.switchCriteriaKey;
      let value;
      if (field.dataset.switchCriteriaType === "integer") {
        value = Number(field.value);
      } else if (field.dataset.switchCriteriaType === "boolean") {
        value = field.value === "true";
      } else {
        value = field.value;
      }
      return [key, value];
    }));
  }

  function applyCriteria(values) {
    criteriaFields.forEach(function (field) {
      const key = field.dataset.switchCriteriaKey;
      if (!Object.prototype.hasOwnProperty.call(values, key)) return;
      if (field.dataset.switchCriteriaType === "integer") {
        field.value = String(values[key]);
      } else if (field.dataset.switchCriteriaType === "boolean" && typeof values[key] === "boolean") {
        field.value = values[key] ? "true" : "false";
      } else if (field.dataset.switchCriteriaType === "status" && typeof values[key] === "string") {
        field.value = values[key];
      }
    });
  }

  function saveCriteria() {
    window.localStorage.setItem(criteriaStorageKey, JSON.stringify(readCriteria()));
  }

  function restoreCriteria() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(criteriaStorageKey) || "null");
      if (saved && typeof saved === "object" && !Array.isArray(saved)) applyCriteria(saved);
    } catch (_reason) {
      window.localStorage.removeItem(criteriaStorageKey);
    }
  }

  async function pollRun(runId) {
    polling = true;
    while (polling) {
      await new Promise(function (resolve) { window.setTimeout(resolve, 1200); });
      let response;
      try {
        response = await fetch(`/api/v1/switch/audits/${encodeURIComponent(runId)}`, {
          cache: "no-store",
          headers: {"X-SecAI-Background": "true"}
        });
      } catch (_reason) {
        progressMessage.textContent = "점검 상태 연결을 다시 시도하고 있습니다.";
        continue;
      }
      if (!response.ok) {
        polling = false;
        throw new Error("점검 상태를 확인하지 못했습니다.");
      }
      const payload = await response.json();
      if (payload.status === "COMPLETED") {
        polling = false;
        progress.value = totalControls;
        progressCount.textContent = `${totalControls} / ${totalControls}`;
        setControls("complete", "확인 완료");
        progressMessage.textContent = `${totalControls}개 항목의 비식별 판정과 결과 확인값 저장을 완료했습니다.`;
        window.location.assign(payload.result_url);
        return;
      }
      if (payload.status === "FAILED") {
        polling = false;
        const message = failureMessages[payload.error_code] || "스위치 점검을 완료하지 못했습니다.";
        progressMessage.textContent = `${message} 오류 코드: ${payload.error_code || "SWITCH_AUDIT_FAILED"}`;
        setControls("waiting", "중단");
        restoreForm();
        return;
      }
      if (payload.status === "RUNNING") {
        progress.value = 1;
        progressCount.textContent = "자료 수집 중";
        setControls("active", "읽기·판정 중");
        progressMessage.textContent = "고정된 AOS-CX REST GET 자료를 비식별 판정으로 변환하고 있습니다.";
      }
    }
  }

  startButton.addEventListener("click", async function () {
    errorOutput.textContent = "";
    const selected = document.querySelector('input[name="switch-asset"]:checked');
    if (!selected || !usernameInput.value.trim() || !passwordInput.value) {
      errorOutput.textContent = "등록 장비와 REST 로그인 정보를 입력해 주세요.";
      return;
    }
    const invalidField = criteriaFields.find(function (field) { return !field.checkValidity(); });
    if (invalidField) {
      errorOutput.textContent = "판정 기준의 허용 범위를 확인해 주세요.";
      invalidField.focus();
      return;
    }
    startButton.disabled = true;
    const requestBody = {
      asset_key: selected.value,
      username: usernameInput.value.trim(),
      password: passwordInput.value,
      criteria: readCriteria()
    };
    passwordInput.value = "";
    try {
      const response = await fetch("/api/v1/switch/audits", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify(requestBody),
        cache: "no-store"
      });
      requestBody.password = "";
      if (!response.ok) throw new Error("스위치 점검을 시작하지 못했습니다. 로그인 상태를 확인해 주세요.");
      const payload = await response.json();
      saveCriteria();
      startPanel.querySelectorAll("input, select, button").forEach(function (item) {
        item.disabled = true;
      });
      progressPanel.hidden = false;
      progress.value = 0;
      progressMessage.textContent = payload.reused ? "이미 실행 중인 동일 장비 점검을 이어서 확인합니다." : "인증서와 REST 로그인을 확인하고 있습니다.";
      await pollRun(payload.run_id);
    } catch (reason) {
      requestBody.password = "";
      errorOutput.textContent = reason instanceof Error ? reason.message : "스위치 점검을 시작하지 못했습니다.";
      restoreForm();
    }
  });

  criteriaResetButton.addEventListener("click", function () {
    applyCriteria(defaultCriteria);
    window.localStorage.removeItem(criteriaStorageKey);
  });
  restoreCriteria();
}());
