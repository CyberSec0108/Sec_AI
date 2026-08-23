"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const threadList = document.getElementById("thread-list");
const historyEmpty = document.getElementById("history-empty");
const historyCount = document.getElementById("history-count");
const messageList = document.getElementById("message-list");
const welcome = document.getElementById("chat-welcome");
const sourceList = document.getElementById("source-list");
const sourceTitle = document.getElementById("source-title");
const questionForm = document.getElementById("question-form");
const questionInput = document.getElementById("question-input");
const answerProfile = document.getElementById("answer-profile");
const chatStatus = document.getElementById("chat-status");
const newChatButton = document.getElementById("new-chat");
const sendButton = document.getElementById("send-question");
const stopButton = document.getElementById("stop-answer");
const cancelEditButton = document.getElementById("cancel-edit");
const questionCount = document.getElementById("question-count");
const chatLayout = document.getElementById("chat-layout");
const historyPanelToggle = document.getElementById("history-panel-toggle");
const historyPanelContent = document.getElementById("history-panel-content");
const historyPanelResizer = document.getElementById("history-panel-resizer");
const sourcePanelToggle = document.getElementById("source-panel-toggle");
const sourcePanelContent = document.getElementById("source-panel-content");
const sourcePanelClose = document.getElementById("source-panel-close");
const threadSearch = document.getElementById("thread-search");
const threadView = document.getElementById("thread-view");
const threadDeleteUndo = document.getElementById("thread-delete-undo");
const threadDeleteUndoButton = document.getElementById("thread-delete-undo-button");
const guideSelect = document.getElementById("guide-select");

let currentThreadId = null;
let currentThreadStatus = "ACTIVE";
let deletedThread = null;
let deleteUndoTimer = null;
let searchTimer = null;
let currentGenerationId = null;
let editingMessageId = null;
let generationRequest = null;
let conversationRefreshPromise = null;
let generationInProgress = false;
let streamingAnswer = null;
let streamingRenderer = null;
let activeThreadEditor = null;
let followStreamingAnswer = true;
let approvedGuides = [];

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const ICON_PARTS = {
  edit: [
    ["path", {d: "M12 20h9"}],
    ["path", {d: "M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4z"}],
  ],
  source: [
    ["path", {d: "M4 5.5A2.5 2.5 0 0 1 6.5 3H11v16H6.5A2.5 2.5 0 0 0 4 21.5z"}],
    ["path", {d: "M20 5.5A2.5 2.5 0 0 0 17.5 3H13v16h4.5a2.5 2.5 0 0 1 2.5 2.5z"}],
  ],
  copy: [
    ["rect", {x: "9", y: "9", width: "12", height: "12", rx: "2"}],
    ["path", {d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"}],
  ],
  check: [["polyline", {points: "20 6 9 17 4 12"}]],
  "thumb-up": [["path", {d: "M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3m0 11V11l4-9a3 3 0 0 1 3 3v4h5.3a2 2 0 0 1 2 2.3l-1.4 9A2 2 0 0 1 18 22z"}]],
  "thumb-down": [["path", {d: "M17 2h3a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2h-3m0-11v11l-4 9a3 3 0 0 1-3-3v-4H4.7a2 2 0 0 1-2-2.3l1.4-9A2 2 0 0 1 6 2z"}]],
  retry: [
    ["path", {d: "M3 12a9 9 0 1 0 3-6.7"}],
    ["polyline", {points: "3 4 3 10 9 10"}],
  ],
  branch: [
    ["circle", {cx: "6", cy: "5", r: "2"}],
    ["circle", {cx: "18", cy: "7", r: "2"}],
    ["circle", {cx: "18", cy: "19", r: "2"}],
    ["path", {d: "M8 5h3a4 4 0 0 1 4 4v6a4 4 0 0 0 1 2.7M8 5a7 7 0 0 1 7 7v1"}],
  ],
  pin: [
    ["path", {d: "M16 3l5 5-4 2-3 5-2 6-2-6-5-3 6-3 2-4z"}],
    ["path", {d: "M5 19l4-4"}],
  ],
  archive: [
    ["rect", {x: "3", y: "4", width: "18", height: "5", rx: "1"}],
    ["path", {d: "M5 9v10h14V9M10 13h4"}],
  ],
  trash: [
    ["path", {d: "M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15"}],
    ["path", {d: "M10 11v6M14 11v6"}],
  ],
};
const PANEL_STORAGE_KEYS = {
  history: "secai-guide-chat-history-collapsed",
  source: "secai-guide-chat-source-collapsed",
  historyWidth: "secai-guide-chat-history-width",
};

function createSvgIcon(name) {
  const svg = document.createElementNS(SVG_NAMESPACE, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("chat-action-icon");
  (ICON_PARTS[name] || []).forEach(([tagName, attributes]) => {
    const part = document.createElementNS(SVG_NAMESPACE, tagName);
    Object.entries(attributes).forEach(([key, value]) => {
      part.setAttribute(key, value);
    });
    svg.append(part);
  });
  return svg;
}

function setIcon(button, name) {
  clearNode(button);
  button.append(createSvgIcon(name));
}

function createIconButton(label, icon, action, className = "chat-icon-button") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.setAttribute("aria-label", label);
  button.setAttribute("title", label);
  button.append(createSvgIcon(icon));
  button.addEventListener("click", action);
  return button;
}

function feedbackStorageKey(messageId) {
  return `secai-guide-feedback:${messageId}`;
}

function readFeedback(messageId) {
  try {
    return window.localStorage.getItem(feedbackStorageKey(messageId));
  } catch (_error) {
    return null;
  }
}

function writeFeedback(messageId, value) {
  try {
    if (value) {
      window.localStorage.setItem(feedbackStorageKey(messageId), value);
    } else {
      window.localStorage.removeItem(feedbackStorageKey(messageId));
    }
  } catch (_error) {
    // 브라우저 저장소를 사용할 수 없어도 현재 화면의 선택 상태는 유지합니다.
  }
}

function applyFeedbackState(positiveButton, negativeButton, value) {
  const positive = value === "positive";
  const negative = value === "negative";
  positiveButton.classList.toggle("is-active", positive);
  negativeButton.classList.toggle("is-active", negative);
  positiveButton.setAttribute("aria-pressed", String(positive));
  negativeButton.setAttribute("aria-pressed", String(negative));
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_error) {
      // 보안 컨텍스트의 클립보드 호출이 거부되면 선택 복사 방식으로 계속합니다.
    }
  }
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.setAttribute("readonly", "");
  textArea.className = "chat-copy-fallback";
  document.body.append(textArea);
  textArea.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_error) {
    copied = false;
  }
  textArea.remove();
  return copied;
}

function uniqueKey(prefix) {
  const randomValue = crypto.getRandomValues(new Uint32Array(2)).join("-");
  return `${prefix}:${Date.now()}:${randomValue}`;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body) {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers,
  });
  const body = await response.json();
  if (!response.ok) {
    const detail = body.detail || {};
    const code = detail.code || "REQUEST_FAILED";
    throw new Error(code);
  }
  return body;
}

function clearNode(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function setBusy(busy) {
  sendButton.disabled = busy || currentThreadStatus !== "ACTIVE";
  answerProfile.disabled = busy;
  guideSelect.disabled = busy || currentThreadId !== null;
  stopButton.hidden = !busy;
  messageList.setAttribute("aria-busy", String(busy));
  if (!busy) {
    currentGenerationId = null;
    generationRequest = null;
  }
}

function guideKey(guide) {
  return `${guide.guide_id}|${guide.version}|${guide.scope_id}`;
}

function selectedGuide() {
  return approvedGuides.find((guide) => guideKey(guide) === guideSelect.value)
    || approvedGuides[0]
    || {
      guide_id: "kisa-major-infrastructure-detailed-guide",
      version: "2026",
      scope_id: "kisa-2026-all",
      retrieval_role: "OFFICIAL_CHECK_REFERENCE",
    };
}

function selectThreadGuide(thread) {
  const guide = thread?.guide;
  if (!guide) {
    return;
  }
  const value = `${guide.guide_id}|${guide.version}|${guide.scope_id}`;
  if (approvedGuides.some((item) => guideKey(item) === value)) {
    guideSelect.value = value;
  }
}

async function loadGuideOptions() {
  const body = await api("/api/v1/chat/guides");
  approvedGuides = Array.isArray(body.guides) ? body.guides : [];
  if (!approvedGuides.length) {
    throw new Error("GUIDE_SCOPE_NOT_APPROVED");
  }
  guideSelect.value = guideKey(approvedGuides[0]);
}

function referencedCitationOrdinals(content) {
  const value = String(content ?? "");
  const matches = [];
  const patterns = [
    {pattern: /\[([1-9]\d?)\]|［([1-9]\d?)］|【([1-9]\d?)】/gu, canonical: true},
    {pattern: /\(([1-9]\d?)\)|（([1-9]\d?)）/gu, canonical: false},
  ];
  patterns.forEach(({pattern, canonical}) => {
    for (const matched of value.matchAll(pattern)) {
      const number = matched.slice(1).find((item) => item !== undefined);
      matches.push({
        start: matched.index,
        end: matched.index + matched[0].length,
        ordinal: Number.parseInt(number, 10),
        canonical,
      });
    }
  });
  matches.sort((left, right) => left.start - right.start);

  const sentenceEndings = ".!?。！？;；:：";
  const closingMarks = "\"'”’」』》〉";
  const ordinals = new Set();
  let previousReferenceEnd = null;
  matches.forEach((matched) => {
    let accepted = matched.canonical;
    if (!accepted) {
      let prefixEnd = matched.start;
      while (prefixEnd > 0 && /\s/u.test(value[prefixEnd - 1])) {
        prefixEnd -= 1;
      }
      let precedingIndex = prefixEnd - 1;
      while (
        precedingIndex >= 0 &&
        closingMarks.includes(value[precedingIndex])
      ) {
        precedingIndex -= 1;
      }
      accepted = (
        precedingIndex >= 0 &&
        sentenceEndings.includes(value[precedingIndex])
      ) || (
        previousReferenceEnd !== null &&
        prefixEnd === previousReferenceEnd
      );
    }
    if (accepted) {
      previousReferenceEnd = matched.end;
      ordinals.add(matched.ordinal);
    }
  });
  return ordinals;
}

function referencedCitations(content, citations) {
  const ordinals = referencedCitationOrdinals(content);
  return (Array.isArray(citations) ? citations : []).filter((citation) => (
    Number.isInteger(citation.ordinal) && ordinals.has(citation.ordinal)
  ));
}

function markdownOptions(citations = []) {
  const citationIds = citations.map((citation) => `[${citation.ordinal}]`);
  return {
    allowedCitationIds: citationIds,
    allowedOrigins: [window.location.origin],
    onCitationActivate: (citationId) => {
      const citation = citations.find(
        (item) => `[${item.ordinal}]` === citationId,
      );
      if (citation) {
        window.open(guidePdfUrl(citation), "_blank", "noopener,noreferrer");
        return;
      }
      showSources(citations);
      setPanelCollapsed("source", false);
      sourceTitle.focus();
    },
  };
}

function normalizeInlineCitationPlacement(content) {
  const citationToken = "\\[(?:[1-9]|1\\d|20)\\]";
  const leadingCitationPattern = new RegExp(
    `^([-*+•]\\s*)?((?:${citationToken}\\s*)+)(.+)$`,
    "u",
  );
  const citationPattern = new RegExp(citationToken, "gu");
  const sourceDescriptionPattern = /(?:KISA|가이드|상세가이드).*(?:페이지|쪽)/u;
  const normalized = [];
  let pendingCitations = [];

  String(content ?? "")
    .split(/\r?\n/u)
    .forEach((line) => {
      const trimmed = line.trim();
      const leading = trimmed.match(leadingCitationPattern);
      if (leading) {
        const citations = leading[2].match(citationPattern) || [];
        const body = leading[3].trim();
        if (sourceDescriptionPattern.test(body)) {
          pendingCitations.push(...citations);
          return;
        }
        const uniqueCitations = [...new Set(citations)];
        normalized.push(`${leading[1] || ""}${body}${uniqueCitations.join("")}`);
        return;
      }

      if (pendingCitations.length && trimmed) {
        const uniqueCitations = [...new Set(pendingCitations)].filter(
          (citation) => !line.includes(citation),
        );
        normalized.push(`${line.trimEnd()}${uniqueCitations.join("")}`);
        pendingCitations = [];
        return;
      }
      normalized.push(line);
    });

  if (pendingCitations.length) {
    normalized.push([...new Set(pendingCitations)].join(""));
  }
  return normalized.join("\n");
}

function renderAnswerContent(container, content, citations = []) {
  const wrapper = document.createElement("div");
  wrapper.className = "chat-answer-content ai-markdown";
  container.append(wrapper);
  const normalizedContent = normalizeInlineCitationPlacement(content);
  try {
    window.SecAIRestrictedMarkdown.render(
      wrapper,
      normalizedContent,
      markdownOptions(citations),
    );
  } catch (_error) {
    wrapper.textContent = normalizedContent;
    wrapper.classList.add("ai-markdown-fallback");
  }
}

function generationIndicator() {
  const article = document.createElement("article");
  article.id = "generation-indicator";
  article.className = "chat-message chat-message-assistant generation-indicator";
  article.setAttribute("role", "status");
  article.setAttribute("aria-label", "답변 생성 과정");
  const heading = document.createElement("strong");
  heading.className = "generation-indicator-title";
  heading.textContent = "답변을 준비하고 있습니다";
  const list = document.createElement("ol");
  list.className = "generation-steps";
  ["질문 확인", "통합 가이드 검색", "답변과 출처 정리"].forEach(
    (label, index) => {
      const item = document.createElement("li");
      item.dataset.state = index === 0 ? "active" : "pending";
      const marker = document.createElement("span");
      marker.className = "generation-step-marker";
      marker.setAttribute("aria-hidden", "true");
      const text = document.createElement("span");
      text.textContent = label;
      item.append(marker, text);
      list.append(item);
    },
  );
  article.append(heading, list);
  return article;
}

function showGenerationIndicator() {
  resetStreamingAnswer();
  followStreamingAnswer = true;
  document.getElementById("generation-indicator")?.remove();
  messageList.append(generationIndicator());
  messageList.scrollTop = messageList.scrollHeight;
}

function ensureStreamingAnswer() {
  if (streamingAnswer && streamingRenderer) {
    return streamingRenderer;
  }
  streamingAnswer = document.createElement("article");
  streamingAnswer.id = "streaming-answer";
  streamingAnswer.className = "chat-message chat-message-assistant is-streaming";
  streamingAnswer.setAttribute("aria-label", "생성 중인 AI 답변");
  const label = document.createElement("p");
  label.className = "chat-message-label";
  label.textContent = "AI 답변";
  const body = document.createElement("div");
  body.className = "chat-answer-content ai-markdown";
  streamingAnswer.append(label, body);
  messageList.append(streamingAnswer);
  streamingRenderer = window.SecAIRestrictedMarkdown.createStreamingRenderer(
    body,
    markdownOptions(),
  );
  return streamingRenderer;
}

function appendStreamingToken(delta) {
  if (!delta) {
    return;
  }
  const shouldFollow = followStreamingAnswer || messageListNearBottom();
  removeGenerationIndicator();
  ensureStreamingAnswer().append(delta);
  chatStatus.textContent = "AI가 답변을 작성하고 있습니다.";
  if (shouldFollow) {
    window.requestAnimationFrame(() => {
      messageList.scrollTop = messageList.scrollHeight;
    });
  }
}

function messageListNearBottom() {
  return messageList.scrollHeight - messageList.scrollTop - messageList.clientHeight < 96;
}

function completeStreamingAnswer() {
  streamingRenderer?.complete();
}

function resetStreamingAnswer() {
  streamingRenderer?.destroy();
  streamingRenderer = null;
  streamingAnswer?.remove();
  streamingAnswer = null;
}

function setGenerationStage(targetIndex) {
  const indicator = document.getElementById("generation-indicator");
  if (!indicator) {
    return;
  }
  indicator.querySelectorAll(".generation-steps li").forEach((item, index) => {
    item.dataset.state = index < targetIndex
      ? "done"
      : index === targetIndex
        ? "active"
        : "pending";
  });
}

function completeGenerationIndicator() {
  const indicator = document.getElementById("generation-indicator");
  indicator?.querySelectorAll(".generation-steps li").forEach((item) => {
    item.dataset.state = "done";
  });
}

function removeGenerationIndicator() {
  document.getElementById("generation-indicator")?.remove();
}

function readableError(error) {
  const messages = {
    PROMPT_INJECTION_DETECTED: "안전하지 않은 지시가 포함되어 답변을 만들지 않았습니다.",
    GUIDE_QUERY_LENGTH_INVALID: "질문은 500자 이내로 입력해 주세요.",
    GUIDE_SCOPE_NOT_APPROVED: "승인된 가이드를 불러오지 못했습니다.",
    GENERATION_ALREADY_TERMINAL: "이미 끝난 답변입니다. 대화 기록을 새로 불러왔습니다.",
    CHAT_SCOPE_DENIED: "이 대화를 볼 권한이 없습니다.",
    CHAT_DELETE_UNDO_EXPIRED: "삭제 취소 시간이 지났습니다.",
    CHAT_DELETE_UNDO_NOT_AVAILABLE: "이 대화는 삭제를 취소할 수 없습니다.",
    CHAT_THREAD_NOT_ACTIVE: "보관한 대화에는 새 질문을 추가할 수 없습니다.",
    CHAT_MANAGEMENT_TEXT_INVALID: "대화 이름은 한 줄로 입력해 주세요.",
  };
  return messages[error.message] || "답변을 만들지 못했습니다. 잠시 후 다시 시도해 주세요.";
}

function showSources(citations) {
  clearNode(sourceList);
  if (!citations.length) {
    const empty = document.createElement("p");
    empty.className = "chat-empty";
    empty.textContent = "답변에 사용할 수 있는 승인된 원문 근거가 없습니다.";
    sourceList.append(empty);
    return;
  }
  citations.forEach((citation) => {
    const card = document.createElement("article");
    card.className = "chat-source-card";
    const heading = document.createElement("div");
    heading.className = "chat-source-card-heading";
    const number = document.createElement("span");
    number.className = "chat-source-card-number";
    number.textContent = `[${citation.ordinal}]`;
    const title = document.createElement("strong");
    title.textContent = citation.section_label;
    const location = document.createElement("p");
    location.textContent = `${citation.document_code || citation.guide_id} · ${citation.pdf_page_number}쪽 · 문단 ${citation.paragraph_ordinal}`;
    const link = document.createElement("a");
    link.href = guidePdfUrl(citation);
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = `PDF ${citation.pdf_page_number}쪽 원문 보기`;
    heading.append(number, title);
    card.append(heading, location, link);
    sourceList.append(card);
  });
}

  function guidePdfUrl(citation) {
    const guideId = encodeURIComponent(citation.guide_id);
    const guideVersion = encodeURIComponent(citation.guide_version);
    const pageNumber = Number.parseInt(citation.pdf_page_number, 10);
    return `/api/v1/guides/${guideId}/${guideVersion}/source.pdf?requested_page=${pageNumber}#page=${pageNumber}&zoom=page-width`;
  }

function renderMessage(message) {
  if (message.status === "SUPERSEDED") {
    return;
  }
  const article = document.createElement("article");
  article.className = `chat-message chat-message-${message.role.toLowerCase()}`;
  const role = document.createElement("span");
  role.className = "chat-message-role";
  role.textContent = message.role === "USER" ? "내 질문" : "Sec_AI 답변";
  article.append(role);
  const messageCitations = referencedCitations(
    message.content,
    message.citations || [],
  );
  renderAnswerContent(article, message.content, messageCitations);

  const actions = document.createElement("div");
  actions.className = "chat-message-actions";
  if (message.role === "USER") {
    actions.append(createIconButton("질문 수정", "edit", () => {
      editingMessageId = message.message_id;
      questionInput.value = message.content;
      updateQuestionCount();
      cancelEditButton.hidden = false;
      questionInput.focus();
    }));
  } else {
    actions.append(createIconButton("답변 출처 보기", "source", () => {
      setPanelCollapsed("source", false);
      showSources(messageCitations);
      sourceTitle.focus();
    }));
    const copyButton = createIconButton("답변 복사", "copy", async () => {
      if (await copyText(message.content)) {
        copyButton.classList.add("is-copied");
        setIcon(copyButton, "check");
        chatStatus.textContent = "답변을 복사했습니다.";
        window.setTimeout(() => {
          copyButton.classList.remove("is-copied");
          setIcon(copyButton, "copy");
        }, 1800);
      } else {
        chatStatus.textContent = "복사하지 못했습니다. 답변을 선택해 복사해 주세요.";
      }
    });
    const positiveButton = createIconButton("도움이 됐어요", "thumb-up", () => {
      const nextValue = positiveButton.getAttribute("aria-pressed") === "true"
        ? null
        : "positive";
      writeFeedback(message.message_id, nextValue);
      applyFeedbackState(positiveButton, negativeButton, nextValue);
      chatStatus.textContent = nextValue
        ? "도움이 됐다는 의견을 표시했습니다."
        : "의견 선택을 취소했습니다.";
    }, "chat-icon-button chat-feedback-button");
    const negativeButton = createIconButton("개선이 필요해요", "thumb-down", () => {
      const nextValue = negativeButton.getAttribute("aria-pressed") === "true"
        ? null
        : "negative";
      writeFeedback(message.message_id, nextValue);
      applyFeedbackState(positiveButton, negativeButton, nextValue);
      chatStatus.textContent = nextValue
        ? "개선이 필요하다는 의견을 표시했습니다."
        : "의견 선택을 취소했습니다.";
    }, "chat-icon-button chat-feedback-button");
    applyFeedbackState(
      positiveButton,
      negativeButton,
      readFeedback(message.message_id),
    );
    actions.append(copyButton, positiveButton, negativeButton);
    actions.append(createIconButton("답변 다시 생성", "retry", async () => {
      await retryAnswer(message);
    }));
    actions.append(createIconButton("이 답변에서 새 대화", "branch", async () => {
      await branchConversation(message);
    }));
  }
  article.append(actions);
  messageList.append(article);
}

function threadQueryPath() {
  const parameters = new URLSearchParams({view: threadView.value});
  const query = threadSearch.value.trim();
  if (query) {
    parameters.set("q", query);
  }
  return `/api/v1/chat/threads?${parameters.toString()}`;
}

function closeInlineThreadEditor() {
  activeThreadEditor?.remove();
  activeThreadEditor = null;
}

async function updateThread(thread, path, payload) {
  const updated = await api(
    `/api/v1/chat/threads/${thread.thread_id}/${path}`,
    {method: "PATCH", body: JSON.stringify(payload)},
  );
  if (currentThreadId === updated.thread_id) {
    currentThreadStatus = updated.status;
    sendButton.disabled = currentThreadStatus !== "ACTIVE";
  }
  await loadThreads();
  return updated;
}

function startInlineThreadRename(thread, row, title) {
  closeInlineThreadEditor();
  const original = thread.title;
  const input = document.createElement("input");
  input.type = "text";
  input.className = "chat-thread-rename-input";
  input.maxLength = 160;
  input.value = original;
  input.setAttribute("aria-label", `${original} 대화 이름 수정`);
  title.replaceWith(input);
  activeThreadEditor = input;
  let finished = false;
  const finish = async (save) => {
    if (finished) {
      return;
    }
    finished = true;
    const nextTitle = input.value.trim();
    try {
      if (save && nextTitle && nextTitle !== original) {
        await updateThread(thread, "title", {title: nextTitle});
        chatStatus.textContent = "대화 이름을 변경했습니다.";
      } else {
        await loadThreads();
      }
    } catch (error) {
      chatStatus.textContent = readableError(error);
      await loadThreads();
    }
  };
  input.addEventListener("blur", () => finish(true), {once: true});
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      input.blur();
    } else if (event.key === "Escape") {
      event.preventDefault();
      input.value = original;
      finish(false);
    }
  });
  input.focus();
  input.select();
  row.classList.add("is-editing");
}

async function deleteThread(thread) {
  const removed = await api(
    `/api/v1/chat/threads/${thread.thread_id}/tombstone`,
    {method: "POST", body: JSON.stringify({})},
  );
  deletedThread = removed;
  if (deleteUndoTimer) {
    clearTimeout(deleteUndoTimer);
  }
  threadDeleteUndo.hidden = false;
  deleteUndoTimer = setTimeout(() => {
    threadDeleteUndo.hidden = true;
    deletedThread = null;
  }, 30000);
  if (currentThreadId === removed.thread_id) {
    currentThreadId = null;
    currentThreadStatus = "ACTIVE";
    resetStreamingAnswer();
    clearNode(messageList);
    messageList.append(welcome);
    setBusy(false);
  }
  await loadThreads();
  chatStatus.textContent = "대화를 삭제했습니다. 30초 안에 취소할 수 있습니다.";
}

async function loadThreads() {
  closeInlineThreadEditor();
  const body = await api(threadQueryPath());
  clearNode(threadList);
  historyCount.textContent = `${body.threads.length}건`;
  historyEmpty.hidden = body.threads.length !== 0;
  body.threads.forEach((thread) => {
    const row = document.createElement("div");
    row.className = "chat-thread-row";
    const openButton = document.createElement("button");
    openButton.type = "button";
    openButton.className = "chat-thread-button";
    const title = document.createElement("span");
    title.textContent = thread.title;
    openButton.append(title);
    if (thread.status === "ARCHIVED") {
      const meta = document.createElement("small");
      meta.textContent = "보관됨";
      openButton.append(meta);
    }
    if (thread.thread_id === currentThreadId) {
      openButton.setAttribute("aria-current", "true");
      row.classList.add("is-current");
    }
    openButton.addEventListener("click", async () => {
      currentThreadId = thread.thread_id;
      currentThreadStatus = thread.status;
      answerProfile.value = thread.profile;
      selectThreadGuide(thread);
      await loadMessages();
    });
    const actions = document.createElement("div");
    actions.className = "chat-thread-actions";
    actions.append(
      createIconButton(
        thread.is_pinned ? "고정 해제" : "대화 고정",
        "pin",
        async () => {
          try {
            await updateThread(thread, "pin", {is_pinned: !thread.is_pinned});
            chatStatus.textContent = thread.is_pinned
              ? "대화 고정을 해제했습니다."
              : "대화를 목록 위에 고정했습니다.";
          } catch (error) {
            chatStatus.textContent = readableError(error);
          }
        },
        `chat-icon-button chat-thread-action${thread.is_pinned ? " is-active" : ""}`,
      ),
      createIconButton("대화 이름 수정", "edit", () => {
        startInlineThreadRename(thread, row, title);
      }, "chat-icon-button chat-thread-action"),
      createIconButton(
        thread.status === "ARCHIVED" ? "보관 해제" : "대화 보관",
        "archive",
        async () => {
          try {
            const archive = thread.status !== "ARCHIVED";
            await updateThread(thread, "archive", {archived: archive});
            chatStatus.textContent = archive
              ? "대화를 보관했습니다."
              : "대화를 다시 사용할 수 있게 했습니다.";
          } catch (error) {
            chatStatus.textContent = readableError(error);
          }
        },
        "chat-icon-button chat-thread-action",
      ),
      createIconButton("대화 삭제", "trash", async () => {
        try {
          await deleteThread(thread);
        } catch (error) {
          chatStatus.textContent = readableError(error);
        }
      }, "chat-icon-button chat-thread-action chat-thread-action-danger"),
    );
    row.append(openButton, actions);
    threadList.append(row);
  });
}

async function loadMessages(threadId = currentThreadId) {
  if (!threadId) {
    return;
  }
  const body = await api(`/api/v1/chat/threads/${threadId}/messages`);
  if (threadId !== currentThreadId) {
    return;
  }
  resetStreamingAnswer();
  clearNode(messageList);
  currentThreadStatus = body.thread.status;
  selectThreadGuide(body.thread);
  sendButton.disabled = currentThreadStatus !== "ACTIVE";
  guideSelect.disabled = true;
  body.messages.forEach(renderMessage);
  if (!body.messages.length) {
    messageList.append(welcome);
  }
  const lastAnswer = [...body.messages].reverse().find(
    (message) => message.role === "ASSISTANT" && message.status === "COMPLETED",
  );
  if (lastAnswer) {
    showSources(referencedCitations(
      lastAnswer.content,
      lastAnswer.citations || [],
    ));
  } else {
    showSources([]);
  }
  messageList.scrollTop = messageList.scrollHeight;
  if (currentThreadStatus === "ARCHIVED") {
    chatStatus.textContent = "보관한 대화입니다. 새 질문을 하려면 보관을 해제해 주세요.";
  }
}

async function refreshConversation() {
  if (!currentThreadId) {
    return;
  }
  if (conversationRefreshPromise) {
    await conversationRefreshPromise;
    return;
  }
  conversationRefreshPromise = loadMessages(currentThreadId);
  try {
    await conversationRefreshPromise;
  } finally {
    conversationRefreshPromise = null;
  }
}

async function createThread(question) {
  const title = question.length > 38 ? `${question.slice(0, 38)}…` : question;
  const guide = selectedGuide();
  const thread = await api("/api/v1/chat/threads", {
    method: "POST",
    body: JSON.stringify({
      title,
      guide_id: guide.guide_id,
      guide_version: guide.version,
      scope_id: guide.scope_id,
      profile: answerProfile.value,
    }),
  });
  currentThreadId = thread.thread_id;
  currentThreadStatus = "ACTIVE";
  return thread;
}

function observeGeneration(generationId) {
  const events = new EventSource(`/api/v1/chat/generations/${generationId}/events`);
  events.addEventListener("answer-token", (event) => {
    const chunk = JSON.parse(event.data);
    appendStreamingToken(chunk.content_delta || "");
    setGenerationStage(2);
  });
  events.addEventListener("answer-reset", () => {
    resetStreamingAnswer();
    showGenerationIndicator();
    setGenerationStage(2);
  });
  events.addEventListener("generation-status", async (event) => {
    const state = JSON.parse(event.data);
    if (state.status === "STREAMING") {
      chatStatus.textContent = "통합 가이드에서 관련 근거를 찾고 있습니다.";
      setGenerationStage(1);
    } else if (state.status === "COMPLETED") {
      completeGenerationIndicator();
      completeStreamingAnswer();
      chatStatus.textContent = "답변과 출처를 저장했습니다.";
      try {
        await refreshConversation();
      } catch (error) {
        chatStatus.textContent = readableError(error);
      } finally {
        generationInProgress = false;
        setBusy(false);
        events.close();
      }
    } else if (state.status === "STOPPED") {
      removeGenerationIndicator();
      resetStreamingAnswer();
      chatStatus.textContent = "답변 생성을 중단했습니다.";
      generationInProgress = false;
      setBusy(false);
      events.close();
    } else if (state.status === "FAILED") {
      removeGenerationIndicator();
      resetStreamingAnswer();
      chatStatus.textContent = "안전하게 답변할 수 없어 생성을 중단했습니다.";
      generationInProgress = false;
      setBusy(false);
      events.close();
    }
  });
  events.addEventListener("chat-error", () => events.close());
  setTimeout(() => events.close(), 300000);
}

async function runAnswer(generationId) {
  currentGenerationId = generationId;
  generationInProgress = true;
  setBusy(true);
  chatStatus.textContent = "통합 가이드에서 근거를 찾고 답변을 정리하고 있습니다.";
  showGenerationIndicator();
  observeGeneration(generationId);
  generationRequest = new AbortController();
  const result = await api(`/api/v1/chat/generations/${generationId}/run`, {
    method: "POST",
    body: JSON.stringify({}),
    signal: generationRequest.signal,
  });
  generationRequest = null;
  if (result.status === "FAILED") {
    throw new Error(result.code || "GENERATION_FAILED");
  }
  if (result.status === "COMPLETED") {
    generationInProgress = false;
    completeGenerationIndicator();
    chatStatus.textContent = "답변과 출처를 저장했습니다.";
    await refreshConversation();
    setBusy(false);
    return;
  }
  if (result.status !== "STREAMING") {
    generationInProgress = false;
    throw new Error(result.code || "GENERATION_NOT_RUNNING");
  }
  setGenerationStage(1);
  chatStatus.textContent = "관련 가이드 근거를 함께 정리하고 있습니다.";
}

async function sendQuestion() {
  const question = questionInput.value.trim();
  if (!question) {
    questionInput.focus();
    return;
  }
  if (!currentThreadId) {
    await createThread(question);
  }
  const idempotencyKey = uniqueKey(editingMessageId ? "edit" : "message");
  const path = editingMessageId
    ? `/api/v1/chat/threads/${currentThreadId}/messages/${editingMessageId}/edit`
    : `/api/v1/chat/threads/${currentThreadId}/messages`;
  const payload = editingMessageId
    ? {content: question, idempotency_key: idempotencyKey}
    : {content: question, idempotency_key: idempotencyKey, parent_message_id: null};
  const created = await api(path, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  editingMessageId = null;
  cancelEditButton.hidden = true;
  questionInput.value = "";
  updateQuestionCount();
  await loadMessages();
  await runAnswer(created.generation_id);
  await loadThreads();
}

async function retryAnswer(message) {
  try {
    const created = await api(
      `/api/v1/chat/threads/${currentThreadId}/messages/${message.message_id}/retry`,
      {
        method: "POST",
        body: JSON.stringify({idempotency_key: uniqueKey("retry")}),
      },
    );
    await runAnswer(created.generation_id);
    await loadMessages();
  } catch (error) {
    chatStatus.textContent = readableError(error);
  } finally {
    if (!generationInProgress) {
      setBusy(false);
    }
  }
}

async function branchConversation(message) {
  try {
    const guide = selectedGuide();
    const thread = await api(
      `/api/v1/chat/threads/${currentThreadId}/messages/${message.message_id}/branch`,
      {
        method: "POST",
        body: JSON.stringify({
          title: "이 답변에서 이어가는 새 대화",
          guide_id: guide.guide_id,
          guide_version: guide.version,
          scope_id: guide.scope_id,
          profile: answerProfile.value,
        }),
      },
    );
    currentThreadId = thread.thread_id;
    clearNode(messageList);
    messageList.append(welcome);
    await loadThreads();
    chatStatus.textContent = "기존 기록을 보존하고 새 대화를 만들었습니다.";
    questionInput.focus();
  } catch (error) {
    chatStatus.textContent = readableError(error);
  }
}

threadDeleteUndoButton.addEventListener("click", async () => {
  if (!deletedThread) {
    return;
  }
  try {
    const restored = await api(
      `/api/v1/chat/threads/${deletedThread.thread_id}/undo-delete`,
      {
        method: "POST",
        body: JSON.stringify({}),
      },
    );
    if (deleteUndoTimer) {
      clearTimeout(deleteUndoTimer);
    }
    deletedThread = null;
    threadDeleteUndo.hidden = true;
    currentThreadId = restored.thread_id;
    currentThreadStatus = restored.status;
    threadView.value = restored.status;
    await Promise.all([loadThreads(), loadMessages(restored.thread_id)]);
    chatStatus.textContent = "삭제를 취소하고 대화를 복원했습니다.";
  } catch (error) {
    threadDeleteUndo.hidden = true;
    deletedThread = null;
    chatStatus.textContent = readableError(error);
  }
});

threadSearch.addEventListener("input", () => {
  if (searchTimer) {
    clearTimeout(searchTimer);
  }
  searchTimer = setTimeout(() => {
    loadThreads().catch((error) => {
      chatStatus.textContent = readableError(error);
    });
  }, 250);
});

threadView.addEventListener("change", () => {
  closeInlineThreadEditor();
  loadThreads().catch((error) => {
    chatStatus.textContent = readableError(error);
  });
});

questionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await sendQuestion();
  } catch (error) {
    if (error.name !== "AbortError") {
      chatStatus.textContent = readableError(error);
    }
  } finally {
    if (!generationInProgress) {
      setBusy(false);
    }
  }
});

questionInput.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && editingMessageId) {
    event.preventDefault();
    cancelQuestionEdit();
    return;
  }
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    questionForm.requestSubmit();
  }
});

function updateQuestionCount() {
  questionCount.textContent = `${questionInput.value.length}/500자`;
}

function cancelQuestionEdit() {
  editingMessageId = null;
  questionInput.value = "";
  cancelEditButton.hidden = true;
  updateQuestionCount();
  chatStatus.textContent = "질문 수정을 취소했습니다.";
}

function setPanelCollapsed(name, collapsed, persist = true) {
  const historyPanel = name === "history";
  const toggle = historyPanel ? historyPanelToggle : sourcePanelToggle;
  const content = historyPanel ? historyPanelContent : sourcePanelContent;
  toggle.setAttribute("aria-expanded", String(!collapsed));
  content.hidden = collapsed;
  chatLayout.classList.toggle(`${name}-panel-collapsed`, collapsed);
  const actionLabel = historyPanel
    ? `내 대화 패널 ${collapsed ? "펼치기" : "접기"}`
    : `답변 출처 ${collapsed ? "열기" : "닫기"}`;
  toggle.setAttribute("aria-label", actionLabel);
  toggle.setAttribute("title", actionLabel);
  toggle.querySelector(".panel-toggle-label").textContent = actionLabel;
  if (persist) {
    try {
      window.localStorage.setItem(PANEL_STORAGE_KEYS[name], String(collapsed));
    } catch (_error) {
      // 저장소를 차단한 브라우저에서는 현재 화면에만 적용합니다.
    }
  }
}

function restorePanelState(name, mobileDefault) {
  let collapsed = mobileDefault;
  try {
    const stored = window.localStorage.getItem(PANEL_STORAGE_KEYS[name]);
    if (stored === "true" || stored === "false") {
      collapsed = stored === "true";
    }
  } catch (_error) {
    // 저장된 상태를 읽을 수 없으면 화면 크기에 맞는 기본값을 사용합니다.
  }
  setPanelCollapsed(name, collapsed, false);
}

function setHistoryPanelWidth(width, persist = true) {
  const safeWidth = Math.max(220, Math.min(460, Math.round(width)));
  chatLayout.style.setProperty("--chat-history-width", `${safeWidth}px`);
  historyPanelResizer.setAttribute("aria-valuenow", String(safeWidth));
  if (persist) {
    try {
      window.localStorage.setItem(
        PANEL_STORAGE_KEYS.historyWidth,
        String(safeWidth),
      );
    } catch (_error) {
      // 저장소를 차단한 브라우저에서는 현재 화면 너비만 유지합니다.
    }
  }
}

function initializeHistoryPanelResizer() {
  let storedWidth = 300;
  try {
    const savedValue = window.localStorage.getItem(PANEL_STORAGE_KEYS.historyWidth);
    if (savedValue !== null && savedValue.trim() !== "") {
      const value = Number(savedValue);
      if (Number.isFinite(value)) {
        storedWidth = value;
      }
    }
  } catch (_error) {
    // 저장값을 읽지 못하면 기본 너비를 사용합니다.
  }
  setHistoryPanelWidth(storedWidth, false);

  let dragging = false;
  const finishDragging = () => {
    if (!dragging) {
      return;
    }
    dragging = false;
    historyPanelResizer.classList.remove("is-resizing");
    document.body.classList.remove("is-chat-panel-resizing");
    const current = Number(historyPanelResizer.getAttribute("aria-valuenow"));
    setHistoryPanelWidth(current, true);
  };
  historyPanelResizer.addEventListener("pointerdown", (event) => {
    if (window.matchMedia("(max-width: 900px)").matches) {
      return;
    }
    dragging = true;
    historyPanelResizer.setPointerCapture(event.pointerId);
    historyPanelResizer.classList.add("is-resizing");
    document.body.classList.add("is-chat-panel-resizing");
  });
  historyPanelResizer.addEventListener("pointermove", (event) => {
    if (!dragging) {
      return;
    }
    const layoutLeft = chatLayout.getBoundingClientRect().left;
    setHistoryPanelWidth(event.clientX - layoutLeft, false);
  });
  historyPanelResizer.addEventListener("pointerup", finishDragging);
  historyPanelResizer.addEventListener("pointercancel", finishDragging);
  historyPanelResizer.addEventListener("keydown", (event) => {
    const current = Number(historyPanelResizer.getAttribute("aria-valuenow"));
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      setHistoryPanelWidth(current + (event.key === "ArrowRight" ? 16 : -16));
    } else if (event.key === "Home") {
      event.preventDefault();
      setHistoryPanelWidth(280);
    }
  });
}

newChatButton.addEventListener("click", () => {
  currentThreadId = null;
  currentThreadStatus = "ACTIVE";
  editingMessageId = null;
  clearNode(messageList);
  messageList.append(welcome);
  questionInput.value = "";
  updateQuestionCount();
  cancelEditButton.hidden = true;
  showSources([]);
  closeInlineThreadEditor();
  setBusy(false);
  guideSelect.disabled = false;
  questionInput.focus();
  chatStatus.textContent = "새 질문을 입력해 주세요.";
});

stopButton.addEventListener("click", async () => {
  if (!currentGenerationId) {
    return;
  }
  if (generationRequest) {
    generationRequest.abort();
  }
  try {
    await api(`/api/v1/chat/generations/${currentGenerationId}/stop`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    chatStatus.textContent = "답변 생성을 중단했습니다. 질문 내용은 보존됩니다.";
  } catch (error) {
    chatStatus.textContent = readableError(error);
  } finally {
    generationInProgress = false;
    setBusy(false);
  }
});

cancelEditButton.addEventListener("click", () => {
  cancelQuestionEdit();
});

historyPanelToggle.addEventListener("click", () => {
  setPanelCollapsed(
    "history",
    historyPanelToggle.getAttribute("aria-expanded") === "true",
  );
});

sourcePanelToggle.addEventListener("click", () => {
  setPanelCollapsed(
    "source",
    sourcePanelToggle.getAttribute("aria-expanded") === "true",
  );
});

sourcePanelClose.addEventListener("click", () => {
  setPanelCollapsed("source", true);
  sourcePanelToggle.focus();
});

questionInput.addEventListener("input", updateQuestionCount);

const narrowChatScreen = window.matchMedia("(max-width: 640px)").matches;
restorePanelState("history", narrowChatScreen);
restorePanelState("source", true);
initializeHistoryPanelResizer();

messageList.addEventListener("scroll", () => {
  if (generationInProgress) {
    followStreamingAnswer = messageListNearBottom();
  }
}, {passive: true});

document.querySelectorAll(".question-example").forEach((button) => {
  button.addEventListener("click", () => {
    questionInput.value = button.textContent;
    updateQuestionCount();
    questionInput.focus();
  });
});

const prefilledQuestion = new URLSearchParams(window.location.search).get("question");
if (prefilledQuestion && prefilledQuestion.length <= 500) {
  questionInput.value = prefilledQuestion;
  updateQuestionCount();
  chatStatus.textContent = "점검 결과에서 가져온 질문입니다. 내용을 확인하고 보내세요.";
}

Promise.all([loadGuideOptions(), loadThreads()]).catch((error) => {
  chatStatus.textContent = readableError(error);
});
