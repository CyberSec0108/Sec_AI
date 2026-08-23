(function () {
  "use strict";
  const startButton = document.getElementById("linux-start");
  if (!startButton) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const startPanel = document.getElementById("linux-start-panel");
  const progressPanel = document.getElementById("linux-progress-panel");
  const message = document.getElementById("linux-progress-message");
  const count = document.getElementById("linux-progress-count");
  const progress = document.getElementById("linux-progress");
  const currentProbe = document.getElementById("linux-current-probe");
  const detectedPlatform = document.getElementById("linux-detected-platform");
  const detectedPlatformName = document.getElementById("linux-detected-platform-name");
  const detectedPlatformSupport = document.getElementById("linux-detected-platform-support");
  const controlProgressList = document.getElementById("linux-control-progress-list");
  const controlProgressSummary = document.getElementById("linux-control-progress-summary");
  const cancelButton = document.getElementById("linux-cancel");
  const error = document.getElementById("linux-start-error");
  let runId = "";
  let source = null;
  const criteriaStorageKey = "secai_linux_criteria_v1";
  const criteriaFields = {
    password_maximum_age_days: document.getElementById("linux-password-maximum-age"),
    password_minimum_length: document.getElementById("linux-password-minimum-length"),
    account_lock_threshold: document.getElementById("linux-account-lock-threshold"),
    session_timeout_seconds: document.getElementById("linux-session-timeout"),
    approved_admin_accounts: document.getElementById("linux-approved-admin-accounts"),
    approved_listening_ports: document.getElementById("linux-approved-listening-ports"),
    approved_suid_paths: document.getElementById("linux-approved-suid-paths")
  };
  const defaultCriteria = Object.fromEntries(Object.entries(criteriaFields).map(function (entry) {
    return [entry[0], entry[1] ? entry[1].value : ""];
  }));
  const completedControlIds = new Set();

  function restoreStartControls() {
    startPanel.querySelectorAll("input, textarea, button").forEach(function (item) {
      item.disabled = false;
    });
    startButton.disabled = false;
  }

  function resetProgress() {
    completedControlIds.clear();
    progress.value = 0;
    count.textContent = "0 / 67";
    controlProgressSummary.textContent = "확인 완료 0개 · 확인 중 0개 · 대기 67개";
    currentProbe.textContent = "연결 준비";
    detectedPlatform.hidden = true;
    detectedPlatformName.textContent = "운영체제를 확인하고 있습니다.";
    detectedPlatformSupport.textContent = "지원 여부를 확인한 뒤 읽기 전용 점검을 시작합니다.";
    controlProgressList.querySelectorAll("[data-control-id]").forEach(function (row) {
      row.className = "scan-control-progress-item scan-control-progress-waiting";
      const statusText = row.querySelector(".scan-control-progress-status");
      if (statusText) statusText.textContent = "대기";
    });
  }

  function listValues(value) {
    return String(value || "").split(/[\n,]/).map(function (item) {
      return item.trim();
    }).filter(Boolean);
  }

  function readCriteria() {
    return {
      password_maximum_age_days: Number(criteriaFields.password_maximum_age_days.value),
      password_minimum_length: Number(criteriaFields.password_minimum_length.value),
      account_lock_threshold: Number(criteriaFields.account_lock_threshold.value),
      session_timeout_seconds: Number(criteriaFields.session_timeout_seconds.value),
      approved_admin_accounts: listValues(criteriaFields.approved_admin_accounts.value),
      approved_listening_ports: listValues(criteriaFields.approved_listening_ports.value).map(Number),
      approved_suid_paths: listValues(criteriaFields.approved_suid_paths.value)
    };
  }

  function applyCriteria(values) {
    Object.entries(criteriaFields).forEach(function (entry) {
      const value = values[entry[0]];
      if (!entry[1] || value === undefined) return;
      entry[1].value = Array.isArray(value) ? value.join(entry[0] === "approved_listening_ports" ? ", " : "\n") : String(value);
    });
  }

  function saveCriteria() {
    window.localStorage.setItem(criteriaStorageKey, JSON.stringify(readCriteria()));
  }

  function restoreCriteria() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(criteriaStorageKey) || "null");
      if (saved && typeof saved === "object") applyCriteria(saved);
    } catch (_error) {
      window.localStorage.removeItem(criteriaStorageKey);
    }
  }

  function updateControlProgress(controlId, state, label) {
    const row = controlProgressList.querySelector(`[data-control-id="${controlId}"]`);
    if (!row) return;
    row.className = "scan-control-progress-item scan-control-progress-" + state;
    const statusText = row.querySelector(".scan-control-progress-status");
    if (statusText) statusText.textContent = label;
    if (state === "complete") completedControlIds.add(controlId);
    const activeCount = controlProgressList.querySelectorAll(".scan-control-progress-active").length;
    controlProgressSummary.textContent = "확인 완료 " + completedControlIds.size +
      "개 · 확인 중 " + activeCount + "개 · 대기 " +
      (67 - completedControlIds.size - activeCount) + "개";
  }

  const probeLabels = {
    "linux.os-release": "운영체제 종류와 버전",
    "linux.passwd-db": "사용자 계정 목록",
    "linux.group-db": "사용자 그룹 목록",
    "linux.login-defs": "로그인과 비밀번호 기본 정책",
    "linux.sshd-effective": "SSH 원격 접속 정책",
    "linux.listening": "현재 열려 있는 네트워크 서비스",
    "linux.packages": "설치된 보안 관련 패키지",
    "linux.systemd-units": "실행 중인 시스템 서비스"
  };

  function readableProbe(value) {
    if (probeLabels[value]) return probeLabels[value];
    return String(value || "서버 설정").replace(/^linux\./, "").replaceAll("-", " ");
  }

  function connectEvents(id) {
    source = new EventSource(`/api/v1/linux/audits/${id}/events`);
    source.addEventListener("RUN_STARTED", function () {
      message.textContent = "SSH로 서버 종류와 버전을 안전하게 확인하고 있습니다.";
    });
    source.addEventListener("PLATFORM_IDENTIFIED", function (event) {
      const data = JSON.parse(event.data);
      const fingerprint = data.fingerprint || {};
      const platformNames = {
        UBUNTU_LINUX: "Ubuntu Server",
        ROCKY_LINUX: "Rocky Linux"
      };
      const architectures = {
        X86_64: "x86_64",
        AARCH64: "aarch64",
        X86: "x86"
      };
      const name = platformNames[fingerprint.product_family] || "Linux 서버";
      const version = String(fingerprint.version || "버전 확인됨");
      const architecture = architectures[fingerprint.architecture] ||
        String(fingerprint.architecture || "구조 확인됨");
      detectedPlatformName.textContent = `${name} ${version} · ${architecture}`;
      detectedPlatformSupport.textContent = "지원되는 서버입니다. 확인된 서버에 맞는 읽기 전용 명령만 실행합니다.";
      detectedPlatform.hidden = false;
      currentProbe.textContent = "운영체제 자동 확인 완료";
      message.textContent = "확인된 서버에 맞는 읽기 전용 명령으로 보안 점검을 시작합니다.";
    });
    source.addEventListener("PREFLIGHT_RETRY", function (event) {
      const data = JSON.parse(event.data);
      currentProbe.textContent = "운영체제 정보 다시 확인 중";
      message.textContent = `첫 연결에서 운영체제 정보를 읽지 못해 다시 확인합니다. ` +
        `${data.next_attempt || 2} / ${data.maximum_attempts || 2}`;
    });
    source.addEventListener("PROBE_PROGRESS", function (event) {
      const data = JSON.parse(event.data);
      currentProbe.textContent = `${readableProbe(data.probe_id)} · ${data.state === "STARTED" ? "확인 중" : "확인 완료"}`;
      message.textContent = `서버 자료 수집 ${data.completed_probes || 0} / ${data.total_probes || 0} · 설정을 변경하지 않습니다.`;
      (data.affected_control_ids || []).forEach(function (controlId) {
        if (!completedControlIds.has(controlId)) {
          updateControlProgress(controlId, "active", "자료 수집 중");
        }
      });
      (data.ready_control_ids || []).forEach(function (controlId) {
        if (!completedControlIds.has(controlId)) {
          updateControlProgress(controlId, "active", "자료 수집 완료 · 판정 대기");
        }
      });
    });
    source.addEventListener("CONTROL_COMPLETED", function (event) {
      const data = JSON.parse(event.data);
      progress.value = data.control_index;
      count.textContent = `${data.control_index} / ${data.total_controls}`;
      message.textContent = `${data.control_id} ${data.title} 판정을 완료했습니다.`;
      updateControlProgress(data.control_id, "complete", "확인 완료");
    });
    source.addEventListener("RUN_COMPLETED", function () {
      source.close();
      message.textContent = "67개 항목 점검과 증적 확인값 저장을 완료했습니다.";
      window.location.assign(`/ui/linux-results?run_id=${encodeURIComponent(id)}`);
    });
    source.addEventListener("RUN_CANCELLED", function () {
      source.close();
      message.textContent = "사용자 요청으로 점검을 중단했습니다.";
      cancelButton.disabled = true;
      runId = "";
      restoreStartControls();
    });
    source.addEventListener("RUN_FAILED", function (event) {
      source.close();
      const data = JSON.parse(event.data);
      const code = data.code || "LINUX_AUDIT_FAILED";
      const failureMessages = {
        LINUX_PREFLIGHT_COLLECTION_FAILED: "서버 연결 또는 운영체제 정보를 읽지 못했습니다. 연결 상태를 확인한 뒤 다시 시도해 주세요.",
        LINUX_DISTRIBUTION_MISMATCH: "등록된 서버 정보와 실제 서버에서 확인한 운영체제가 일치하지 않습니다.",
        LINUX_DISTRIBUTION_UNSUPPORTED: "현재 지원하지 않는 Linux 배포판 또는 버전입니다."
      };
      message.textContent = (failureMessages[code] || "점검을 완료하지 못했습니다.") +
        ` 오류 코드: ${code}`;
      cancelButton.disabled = true;
      runId = "";
      restoreStartControls();
    });
  }

  startButton.addEventListener("click", async function () {
    error.textContent = "";
    startButton.disabled = true;
    resetProgress();
    cancelButton.disabled = false;
    const selected = document.querySelector('input[name="linux-asset"]:checked');
    try {
      const response = await fetch("/api/v1/linux/audits", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({asset_key: selected.value, criteria: readCriteria()}),
        cache: "no-store"
      });
      if (!response.ok) throw new Error("Linux 점검을 시작하지 못했습니다.");
      const payload = await response.json();
      runId = payload.run_id;
      saveCriteria();
      progressPanel.hidden = false;
      startPanel.querySelectorAll("input, textarea, button").forEach(function (item) {
        item.disabled = true;
      });
      connectEvents(runId);
    } catch (reason) {
      error.textContent = reason.message;
      restoreStartControls();
    }
  });

  cancelButton.addEventListener("click", async function () {
    if (!runId) return;
    cancelButton.disabled = true;
    await fetch(`/api/v1/linux/audits/${runId}/cancel`, {
      method: "POST", headers: {"X-CSRF-Token": csrf}, cache: "no-store"
    });
    message.textContent = "현재 읽기 작업이 끝나는 즉시 안전하게 중단합니다.";
  });

  document.getElementById("linux-criteria-reset").addEventListener("click", function () {
    applyCriteria(defaultCriteria);
    window.localStorage.removeItem(criteriaStorageKey);
  });
  restoreCriteria();
}());
