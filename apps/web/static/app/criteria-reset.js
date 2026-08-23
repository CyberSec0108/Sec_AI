(function () {
  "use strict";

  document.querySelectorAll("[data-reset-kisa]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      if (
        !window.confirm(
          "다음 점검에 KISA 기준과 SecAI 보조 기본 범위를 적용할까요? 개인 기준 버전은 삭제되지 않습니다."
        )
      ) {
        event.preventDefault();
      }
    });
  });

  const criteriaPage = document.querySelector("[data-selected-criteria-kind]");
  const selectionKind = criteriaPage
    ? criteriaPage.getAttribute("data-selected-criteria-kind")
    : "";
  const profileId = criteriaPage
    ? criteriaPage.getAttribute("data-selected-personal-profile-id")
    : "";
  if (selectionKind === "PERSONAL" && profileId) {
    window.localStorage.setItem(
      "secai_selected_criteria_profile",
      JSON.stringify({
        personal_profile_id: profileId,
        selected_at: Date.now()
      })
    );
  } else if (selectionKind) {
    window.localStorage.removeItem("secai_selected_criteria_profile");
  }
})();
