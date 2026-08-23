(function () {
  "use strict";

  const form = document.getElementById("audit-history-filter");
  const list = document.getElementById("audit-history-list");
  const status = document.getElementById("audit-history-status");
  const count = document.getElementById("audit-history-count");
  const more = document.getElementById("audit-history-more");
  const policy = document.getElementById("audit-history-policy");
  const historyEndpoint = "/api/v1/audit-history";
  if (!form || !list || !status || !count || !more || !policy) {
    return;
  }

  const pageSize = 50;
  let offset = 0;
  let total = 0;
  let loading = false;

  function element(tagName, className, text) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function platformLabel(value) {
    return {
      WINDOWS: "Windows PC",
      LINUX: "Linux 서버",
      SWITCH: "네트워크 Switch"
    }[value] || "장비";
  }

  function localTime(value) {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime())
      ? "점검 시각 확인 필요"
      : parsed.toLocaleString("ko-KR");
  }

  function historyUrl() {
    const values = new FormData(form);
    const query = new URLSearchParams({
      limit: String(pageSize),
      offset: String(offset)
    });
    ["platform", "date_from", "date_to"].forEach(function (name) {
      const value = String(values.get(name) || "").trim();
      if (value) {
        query.set(name, value);
      }
    });
    return historyEndpoint + "?" + query.toString();
  }

  function renderPolicy(value) {
    const backup = value.backup_required
      ? "별도 Backup 검증 필요"
      : "정책상 Backup 필수 아님";
    policy.textContent =
      "정책 v" + value.version + " · " + value.retention_days +
      "일 보존 · " + backup + " · " + value.deletion_mode;
  }

  function renderItem(item) {
    const row = element("li", "audit-history-item");
    const heading = element("div", "audit-history-item-heading");
    const title = element(
      "strong",
      "",
      platformLabel(item.platform) + " · " + item.asset_label
    );
    const time = element("span", "", localTime(item.completed_at));
    heading.append(title, time);

    const counts = item.counts;
    const summary = element(
      "p",
      "audit-history-counts",
      "양호 " + counts.pass + " · 취약 " + counts.fail +
      " · 오류 " + counts.error + " · 검토 " + counts.review +
      " · 해당 없음 " + counts.not_applicable
    );
    const actions = element("div", "audit-history-item-actions");
    const detail = element("a", "button-secondary", "저장 결과 열기");
    detail.href = item.detail_url;
    actions.appendChild(detail);
    row.append(heading, summary, actions);
    list.appendChild(row);
  }

  async function loadHistory(reset) {
    if (loading) {
      return;
    }
    loading = true;
    if (reset) {
      offset = 0;
      list.replaceChildren();
    }
    status.textContent = "저장된 점검 기록을 확인하고 있습니다.";
    more.disabled = true;
    try {
      const response = await window.fetch(historyUrl(), {cache: "no-store"});
      if (!response.ok) {
        throw new Error("history unavailable");
      }
      const body = await response.json();
      total = body.total;
      body.items.forEach(renderItem);
      offset += body.items.length;
      count.textContent = total + "건";
      status.textContent = total
        ? "현재 로그인한 아이디의 점검 기록입니다."
        : "선택한 조건에 저장된 점검 기록이 없습니다.";
      more.hidden = offset >= total;
      renderPolicy(body.policy);
    } catch (_error) {
      status.textContent =
        "점검 기록을 불러오지 못했습니다. 로그인과 저장소 상태를 확인해 주세요.";
      count.textContent = "확인 실패";
      more.hidden = true;
    } finally {
      loading = false;
      more.disabled = false;
    }
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    void loadHistory(true);
  });
  more.addEventListener("click", function () {
    void loadHistory(false);
  });
  void loadHistory(true);
}());
