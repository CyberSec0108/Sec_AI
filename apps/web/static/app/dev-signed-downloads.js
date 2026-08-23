(function () {
  "use strict";
  const status = document.getElementById("download-release-status");
  if (!status) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const cards = Array.from(document.querySelectorAll("[data-platform]"));

  function field(card, name) {
    return card.querySelector(`[data-field="${name}"]`);
  }

  function hex(buffer) {
    return Array.from(new Uint8Array(buffer), function (value) {
      return value.toString(16).padStart(2, "0");
    }).join("");
  }

  async function issue(platform) {
    const response = await fetch("/api/v1/dev-downloads/codes", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify({platform: platform}),
      cache: "no-store"
    });
    if (!response.ok) throw new Error("일회용 다운로드 코드를 만들지 못했습니다.");
    return response.json();
  }

  async function browserDownload(card, platform) {
    const message = field(card, "message");
    message.textContent = "일회용 코드와 파일 서명을 확인하고 있습니다.";
    const issued = await issue(platform);
    const response = await fetch(issued.fetch_url, {
      method: "POST",
      headers: {"Content-Type": "text/plain"},
      body: issued.code,
      cache: "no-store"
    });
    if (!response.ok) throw new Error("다운로드가 서명 검증을 통과하지 못했습니다.");
    const payload = await response.arrayBuffer();
    const digest = hex(await crypto.subtle.digest("SHA-256", payload));
    if (digest !== issued.sha256) throw new Error("받은 파일의 SHA-256이 다릅니다.");
    const url = URL.createObjectURL(new Blob([payload]));
    const link = document.createElement("a");
    link.href = url;
    link.download = issued.filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    message.textContent = "서명과 SHA-256이 확인된 개발용 파일을 받았습니다.";
  }

  function commandFor(issued) {
    const endpoint = issued.terminal_base_url + issued.fetch_url;
    if (issued.platform === "WINDOWS_X64") {
      return [
        "$code = Read-Host '다운로드 코드'",
        `Invoke-WebRequest -Uri '${endpoint}' -Method Post -ContentType 'text/plain' -Body $code -OutFile '${issued.filename}'`,
        "Remove-Variable code",
        `Get-FileHash -Algorithm SHA256 .\\${issued.filename}`,
        `.\\${issued.filename}`
      ].join("\n");
    }
    return [
      "read -rsp '다운로드 코드: ' CODE; echo",
      `printf '%s' \"$CODE\" | curl -fL --data-binary @- '${endpoint}' -o '${issued.filename}'`,
      "unset CODE",
      `sha256sum './${issued.filename}'`,
      `chmod 0755 './${issued.filename}'`,
      `./${issued.filename} --server-url http://127.0.0.1:18480`
    ].join("\n");
  }

  async function showCode(card, platform) {
    const issued = await issue(platform);
    const panel = field(card, "code-panel");
    field(card, "code").textContent = issued.code;
    field(card, "expiry").textContent = new Date(issued.expires_at).toLocaleTimeString() + "까지 한 번 사용할 수 있습니다.";
    field(card, "command").textContent = commandFor(issued);
    panel.hidden = false;
    field(card, "message").textContent = "코드를 VM 터미널에 입력하세요. 명령에는 코드가 포함되지 않습니다.";
  }

  cards.forEach(function (card) {
    const platform = card.dataset.platform;
    card.querySelector('[data-action="browser"]').addEventListener("click", function () {
      browserDownload(card, platform).catch(function (reason) {
        field(card, "message").textContent = reason.message;
      });
    });
    card.querySelector('[data-action="code"]').addEventListener("click", function () {
      showCode(card, platform).catch(function (reason) {
        field(card, "message").textContent = reason.message;
      });
    });
  });

  fetch("/api/v1/dev-downloads/status", {cache: "no-store"})
    .then(function (response) {
      if (!response.ok) throw new Error("개발용 서명 파일이 아직 준비되지 않았습니다.");
      return response.json();
    })
    .then(function (payload) {
      payload.artifacts.forEach(function (artifact) {
        const card = cards.find(function (item) { return item.dataset.platform === artifact.platform; });
        if (!card) return;
        field(card, "filename").textContent = artifact.filename;
        field(card, "sha256").textContent = artifact.sha256;
      });
      status.textContent = `${payload.release_channel} · ${new Date(payload.expires_at).toLocaleString()}까지 · 운영 사용 금지`;
    })
    .catch(function (reason) {
      status.textContent = reason.message;
      cards.forEach(function (card) {
        card.querySelectorAll("button").forEach(function (button) { button.disabled = true; });
      });
    });
}());
