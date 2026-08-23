(function () {
  "use strict";

  const result = document.getElementById("test-result");

  function assert(condition, message) {
    if (!condition) {
      throw new Error(message);
    }
  }

  function pass() {
    result.dataset.status = "PASS";
    result.textContent = "restricted-markdown browser gate: PASS";
  }

  function fail(error) {
    result.dataset.status = "FAIL";
    result.textContent = error && error.message ? error.message : String(error);
  }

  try {
    const renderer = window.SecAIRestrictedMarkdown;
    assert(renderer, "restricted Markdown renderer가 로드되지 않았습니다.");
    const output = document.getElementById("markdown-output");
    let activatedCitation = "";
    renderer.render(
      output,
      "## 왜 중요한가요?\n\n" +
      "**양호** 상태이며 *현재 설정*을 유지하세요.\n\n" +
      "- 첫 번째 조치\n- 두 번째 조치\n\n" +
      "1. 결과 확인\n2. 다시 점검\n\n" +
      "`PC-01`과 [상세 결과](/ui/results)\n\n" +
      "<script>window.__markdownXss = true</script>\n\n" +
      "<svg onload=\"window.__markdownXss = true\"></svg>\n\n" +
      "<math><mtext onclick=\"window.__markdownXss = true\">X</mtext></math>\n\n" +
      "<iframe srcdoc=\"<script>window.__markdownXss=true</script>\"></iframe>\n\n" +
      "<style>body{display:none}</style>\n\n" +
      "[위험](javascript:window.__markdownXss=true)\n\n" +
      "실제 확인값입니다.[1] 확인되지 않은 번호[9]\n\n" +
      "| 점검 항목 | 상태 | 확인 내용 |\n" +
      "|---|:---:|---|\n" +
      "| PC-01 | **양호** | 42일마다 변경 |\n" +
      "| PC-02 | 확인 필요 | <img src=x onerror=window.__markdownXss=true> |",
      {
        allowedCitationIds: ["[1]", "[2]", "[3]", "[4]"],
        onCitationActivate: function (citationId) {
          activatedCitation = citationId;
        }
      }
    );

    assert(output.querySelector("h3"), "제목이 의미 있는 DOM으로 렌더링되지 않았습니다.");
    assert(output.querySelector("strong"), "굵은 글씨가 렌더링되지 않았습니다.");
    assert(output.querySelector("em"), "기울임이 렌더링되지 않았습니다.");
    assert(output.querySelectorAll("ul li").length === 2, "목록이 렌더링되지 않았습니다.");
    assert(output.querySelectorAll("ol li").length === 2, "번호 목록이 렌더링되지 않았습니다.");
    assert(output.querySelector("code"), "inline code가 렌더링되지 않았습니다.");
    assert(output.querySelectorAll("a").length === 1, "안전한 링크만 남지 않았습니다.");
    assert(output.querySelector(".ai-markdown-table-wrap table"),
      "허용된 Markdown 표가 안전한 DOM으로 렌더링되지 않았습니다.");
    assert(output.querySelectorAll("thead th").length === 3,
      "표 제목 열이 올바르게 렌더링되지 않았습니다.");
    assert(output.querySelectorAll("tbody tr").length === 2,
      "표 데이터 행이 올바르게 렌더링되지 않았습니다.");
    assert(!output.querySelector("img"), "표 셀의 HTML이 실행 가능한 DOM이 됐습니다.");
    const safeLink = output.querySelector("a");
    assert(safeLink.getAttribute("rel") === "noopener noreferrer",
      "링크 rel 보안 속성이 없습니다.");
    safeLink.focus();
    assert(document.activeElement === safeLink, "안전한 링크를 키보드로 탐색할 수 없습니다.");
    assert(!output.querySelector("script,svg,iframe,object,style,math"),
      "금지된 HTML 요소가 생성됐습니다.");
    assert(window.__markdownXss !== true, "XSS payload가 실행됐습니다.");
    const citationButton = output.querySelector(".ai-citation-ref");
    assert(citationButton, "허용된 [1] 출처가 버튼으로 렌더링되지 않았습니다.");
    assert(output.querySelectorAll(".ai-citation-ref").length === 1,
      "목록에 없는 [9]가 출처 버튼으로 렌더링됐습니다.");
    citationButton.focus();
    assert(document.activeElement === citationButton,
      "인라인 출처를 키보드로 탐색할 수 없습니다.");
    citationButton.click();
    assert(activatedCitation === "[1]", "인라인 출처 선택 이벤트가 연결되지 않았습니다.");
    assert(citationButton.getBoundingClientRect().width < 48,
      "인라인 출처 버튼에 불필요한 최소 폭이 적용됐습니다.");

    const inlineStrongOutput = document.createElement("div");
    inlineStrongOutput.className = "ai-markdown";
    document.body.appendChild(inlineStrongOutput);
    renderer.render(
      inlineStrongOutput,
      "클라우드 환경에서\n\n**CA-03 MFA(다중 인증) 설정**\n\n은 다음과 같이 판단합니다."
    );
    assert(inlineStrongOutput.querySelectorAll("p").length === 1,
      "문장 중간의 굵은 구문이 불필요한 별도 문단으로 분리됐습니다.");
    assert(inlineStrongOutput.querySelector("p > strong"),
      "문장 중간의 굵은 구문이 인라인 강조로 유지되지 않았습니다.");
    assert(
      inlineStrongOutput.textContent ===
        "클라우드 환경에서 CA-03 MFA(다중 인증) 설정은 다음과 같이 판단합니다.",
      "굵은 구문 앞뒤 문장이 자연스럽게 연결되지 않았습니다."
    );

    const progressiveOutput = document.createElement("div");
    progressiveOutput.className = "ai-markdown";
    document.body.appendChild(progressiveOutput);
    const originalSetTimeout = window.setTimeout;
    const originalClearTimeout = window.clearTimeout;
    const scheduledRenders = [];
    window.setTimeout = function (callback) {
      scheduledRenders.push(callback);
      return scheduledRenders.length;
    };
    window.clearTimeout = function () {};
    try {
      const progressiveStream = renderer.createStreamingRenderer(
        progressiveOutput,
        {throttleMs: 75}
      );
      progressiveStream.append("첫 번째 ");
      progressiveStream.append("두 번째 ");
      progressiveStream.append("세 번째");
      assert(scheduledRenders.length === 1,
        "연속 토큰마다 화면 갱신 시간이 다시 미뤄졌습니다.");
      scheduledRenders[0]();
      assert(progressiveOutput.textContent.includes("첫 번째 두 번째 세 번째"),
        "예약된 중간 화면 갱신에서 누적 토큰이 표시되지 않았습니다.");
      progressiveStream.complete();
    } finally {
      window.setTimeout = originalSetTimeout;
      window.clearTimeout = originalClearTimeout;
    }

    const streamOutput = document.getElementById("stream-output");
    const stream = renderer.createStreamingRenderer(streamOutput, {throttleMs: 0});
    stream.append("**왜 중요한");
    stream.flush();
    assert(!streamOutput.querySelector("strong"), "미완성 강조가 실행됐습니다.");
    stream.append("가요?**");
    stream.complete();
    assert(streamOutput.querySelector("strong"), "완성된 강조가 렌더링되지 않았습니다.");
    assert(!streamOutput.textContent.includes("**"), "완성 후 Markdown 표식이 남았습니다.");

    const longTable = "| 번호 | 확인 내용 |\n|---:|---|\n" + Array.from(
      {length: 1800},
      function (_, index) {
        return "|" + index + "|" + "긴값".repeat(12) + "|";
      }
    ).join("\n");
    const longTableStream = renderer.createStreamingRenderer(output, {throttleMs: 0});
    longTableStream.append(longTable);
    longTableStream.complete();
    assert(output.dataset.markdownFallback === "true",
      "지나치게 긴 표가 안전한 일반 텍스트로 전환되지 않았습니다.");
    assert(getComputedStyle(output).overflowWrap === "anywhere",
      "긴 출력의 줄바꿈 보호가 적용되지 않았습니다.");
    assert(output.getAttribute("role") === "document", "문서 role이 유지되지 않았습니다.");
    assert(output.tabIndex === 0, "키보드로 결과 영역에 접근할 수 없습니다.");

    document.documentElement.dataset.theme = "light";
    const lightColor = getComputedStyle(output).color;
    document.documentElement.dataset.theme = "dark";
    const darkColor = getComputedStyle(output).color;
    assert(lightColor !== darkColor, "주간·야간 모드에서 결과 글자색이 전환되지 않았습니다.");

    const fallbackOutput = document.createElement("div");
    fallbackOutput.className = "ai-markdown";
    document.body.appendChild(fallbackOutput);
    const fallbackStream = renderer.createStreamingRenderer(fallbackOutput, {throttleMs: 0});
    fallbackStream.append("x".repeat(renderer.CONTRACT.maxSourceChars + 1));
    fallbackStream.complete();
    assert(fallbackOutput.dataset.markdownFallback === "true",
      "제한을 넘긴 출력이 안전한 일반 텍스트로 전환되지 않았습니다.");
    assert(!fallbackOutput.querySelector("script,svg,iframe,object,style,math,a"),
      "일반 텍스트 폴백에서 실행 가능한 요소가 생성됐습니다.");

    pass();
  } catch (error) {
    fail(error);
  }
}());
