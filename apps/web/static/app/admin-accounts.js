"use strict";

const copyButton = document.getElementById("copy-issued-mfa");
const codeInput = document.getElementById("issued-mfa-code");
const copyStatus = document.getElementById("copy-issued-mfa-status");

if (copyButton instanceof HTMLButtonElement && codeInput instanceof HTMLInputElement) {
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(codeInput.value);
      if (copyStatus) copyStatus.textContent = "인증 코드를 복사했습니다.";
    } catch {
      if (copyStatus) copyStatus.textContent = "자동 복사가 차단되었습니다. 브라우저의 클립보드 권한을 확인해 주세요.";
    }
  });
}
