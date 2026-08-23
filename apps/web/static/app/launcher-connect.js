(function () {
  "use strict";

  const status = document.getElementById("launcher-connect-status");
  const hash = new URLSearchParams(window.location.hash.slice(1));
  const token = hash.get("launcher_token");

  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    if (status) {
      status.textContent =
        "연결 정보가 올바르지 않습니다. Windows 실행 파일을 다시 열어 주세요.";
    }
    return;
  }

  window.sessionStorage.setItem("secai_launcher_token", token);
  const expiresAt = Date.now() + 120000;
  try {
    window.localStorage.setItem("secai_launcher_continuation", JSON.stringify({
      token: token,
      expires_at: expiresAt
    }));
  } catch (_error) {
    // 다른 탭 전달을 저장하지 못해도 현재 탭의 session 연결은 계속합니다.
  }
  window.location.replace("/");
}());
