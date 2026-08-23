(function () {
  "use strict";
  const createButton = document.getElementById("self-create");
  if (!createButton) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const connectPanel = document.getElementById("self-connect-panel");
  const offlinePanel = document.getElementById("self-offline-panel");
  const code = document.getElementById("self-device-code");
  const expiry = document.getElementById("self-code-expiry");
  const waiting = document.getElementById("self-waiting");
  const artifactStatus = document.getElementById("self-artifact-status");
  const createError = document.getElementById("self-create-error");
  const cancelPending = document.getElementById("self-cancel-pending");
  const uploadForm = document.getElementById("self-upload-form");
  const uploadStatus = document.getElementById("self-upload-status");
  let runId = "";
  let pollTimer = 0;
  let pendingRunId = "";

  async function readErrorDetail(response, fallbackMessage) {
    try {
      const payload = await response.json();
      const detail = payload.detail;
      if (typeof detail === "string" && detail) {
        return {message: detail, pendingRunId: ""};
      }
      if (detail && typeof detail === "object") {
        return {
          message: detail.message || fallbackMessage,
          pendingRunId: detail.pending_run_id || ""
        };
      }
    } catch (reason) {
      // 본문이 없거나 JSON이 아니면 준비된 문구를 그대로 사용합니다.
    }
    return {message: fallbackMessage, pendingRunId: ""};
  }

  async function pollStatus() {
    if (!runId) return;
    try {
      const response = await fetch(`/api/v1/linux/one-shot/runs/${encodeURIComponent(runId)}`, {
        cache: "no-store",
        headers: {"X-SecAI-Background": "true"}
      });
      if (!response.ok) throw new Error("점검 상태를 확인하지 못했습니다.");
      const payload = await response.json();
      if (payload.status === "COMPLETED") {
        window.clearInterval(pollTimer);
        waiting.textContent = `Package 검증과 67개 항목 판정을 완료했습니다. 보증 수준: ${payload.assurance_level || "LOW"}`;
        window.location.assign(`/ui/linux-results?run_id=${encodeURIComponent(runId)}`);
      } else {
        waiting.textContent = "프로그램 실행 또는 오프라인 Package 제출을 기다립니다.";
      }
    } catch (reason) {
      waiting.textContent = reason.message;
    }
  }

  async function createSelfScan() {
    createButton.disabled = true;
    createError.textContent = "";
    cancelPending.hidden = true;
    pendingRunId = "";
    try {
      const response = await fetch("/api/v1/linux/one-shot/runs", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({criteria: null}),
        cache: "no-store"
      });
      if (!response.ok) {
        const failure = await readErrorDetail(response, "새 Linux 자가 점검을 만들지 못했습니다.");
        pendingRunId = failure.pendingRunId;
        cancelPending.hidden = !pendingRunId;
        throw new Error(failure.message);
      }
      const payload = await response.json();
      runId = payload.run_id;
      code.textContent = payload.device_code;
      expiry.textContent = new Date(payload.code_expires_at).toLocaleTimeString() + "까지 한 번 사용할 수 있습니다.";
      artifactStatus.textContent = payload.artifact.download_allowed ?
        `${payload.artifact.status} 파일을 다운로드 화면에서 받을 수 있습니다.` :
        "현재는 DEV 빌드 검증 중이므로 운영 다운로드가 비활성화되어 있습니다.";
      connectPanel.hidden = false;
      offlinePanel.hidden = false;
      pollTimer = window.setInterval(pollStatus, 2000);
      pollStatus();
    } catch (reason) {
      createError.textContent = reason.message;
      createButton.disabled = false;
    }
  }

  createButton.addEventListener("click", createSelfScan);

  cancelPending.addEventListener("click", async function () {
    if (!pendingRunId) return;
    cancelPending.disabled = true;
    try {
      const response = await fetch(`/api/v1/linux/one-shot/runs/${encodeURIComponent(pendingRunId)}`, {
        method: "DELETE",
        headers: {"X-CSRF-Token": csrf},
        cache: "no-store"
      });
      if (!response.ok) {
        const failure = await readErrorDetail(response, "대기 중인 점검을 취소하지 못했습니다.");
        throw new Error(failure.message);
      }
      cancelPending.hidden = true;
      await createSelfScan();
    } catch (reason) {
      createError.textContent = reason.message;
    } finally {
      cancelPending.disabled = false;
    }
  });

  uploadForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (!runId) return;
    const packageFile = document.getElementById("self-package-file").files[0];
    const descriptorFile = document.getElementById("self-descriptor-file").files[0];
    if (!packageFile || !descriptorFile) return;
    uploadStatus.textContent = "ZIP 구조·Schema·hash·악성코드를 확인하고 있습니다.";
    try {
      const descriptor = await descriptorFile.text();
      const body = new FormData();
      body.append("package", packageFile, packageFile.name);
      body.append("descriptor", descriptor);
      body.append("csrf_token", csrf);
      const response = await fetch(`/api/v1/linux/one-shot/runs/${encodeURIComponent(runId)}/upload`, {
        method: "POST", body: body, cache: "no-store"
      });
      if (!response.ok) throw new Error("파일이 검증을 통과하지 못했습니다. 원본 파일을 다시 확인해 주세요.");
      const payload = await response.json();
      uploadStatus.textContent = `업로드를 완료했습니다. 자가 제출 보증 수준: ${payload.assurance_level}`;
      window.location.assign(payload.result_url);
    } catch (reason) {
      uploadStatus.textContent = reason.message;
    }
  });
}());
