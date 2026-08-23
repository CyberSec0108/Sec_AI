(function (root, factory) {
  "use strict";

  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.SecAIRestrictedMarkdown = api;
  }
}(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  const CONTRACT = Object.freeze({
    version: "secai.restricted-markdown.v3",
    maxSourceChars: 100 * 1024,
    throttleMs: 75,
    allowedBlocks: Object.freeze([
      "heading",
      "paragraph",
      "unordered_list",
      "ordered_list",
      "table"
    ]),
    allowedInline: Object.freeze([
      "text",
      "strong",
      "emphasis",
      "inline_code",
      "link",
      "citation_ref"
    ]),
    allowedLinkKinds: Object.freeze(["same_origin", "https"]),
    blockedSchemes: Object.freeze(["javascript:", "data:", "vbscript:"]),
    blockedSyntax: Object.freeze([
      "raw_html",
      "image",
      "fenced_code",
      "protocol_relative"
    ])
  });

  const MAX_BLOCKS = 512;
  const MAX_LIST_ITEMS = 512;
  const MAX_TABLE_ROWS = 256;
  const MAX_TABLE_COLUMNS = 8;
  const MAX_INLINE_NODES = 4096;
  const INLINE_CODE_MARK = String.fromCharCode(96);

  function pushText(nodes, text) {
    if (!text) {
      return;
    }
    const previous = nodes[nodes.length - 1];
    if (previous && previous.type === "text") {
      previous.text += text;
      return;
    }
    nodes.push({type: "text", text: text});
  }

  function normalizedOrigins(allowedOrigins) {
    if (!Array.isArray(allowedOrigins)) {
      return [];
    }
    return allowedOrigins.map(function (origin) {
      try {
        return new URL(origin).origin;
      } catch (_error) {
        return "";
      }
    }).filter(Boolean);
  }

  function sanitizeLinkTarget(target, allowedOrigins) {
    const value = typeof target === "string" ? target.trim() : "";
    if (!value || /[\u0000-\u001f\u007f\\\s]/.test(value)) {
      return {kind: "blocked", href: ""};
    }
    const lowered = value.toLowerCase();
    if (
      lowered.startsWith("javascript:") ||
      lowered.startsWith("data:") ||
      lowered.startsWith("vbscript:") ||
      value.startsWith("//")
    ) {
      return {kind: "blocked", href: ""};
    }
    if (value.startsWith("/") && !value.startsWith("//")) {
      return {kind: "same_origin", href: value};
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch (_error) {
      return {kind: "blocked", href: ""};
    }
    if (
      parsed.protocol !== "https:" ||
      !normalizedOrigins(allowedOrigins).includes(parsed.origin)
    ) {
      return {kind: "blocked", href: ""};
    }
    return {kind: "https", href: parsed.href};
  }

  function normalizedCitationIds(value) {
    if (!Array.isArray(value)) {
      return [];
    }
    return value.filter(function (item) {
      return typeof item === "string" && /^\[\d{1,2}\]$/.test(item);
    });
  }

  function citationAllowed(citationId, options) {
    return normalizedCitationIds(options && options.allowedCitationIds)
      .includes(citationId);
  }

  function normalizeCitationSyntax(source, options) {
    const allowed = new Set(
      normalizedCitationIds(options && options.allowedCitationIds)
    );
    if (!allowed.size) {
      return source;
    }
    return source.replace(
      /\((\d{1,2})\)|（(\d{1,2})）|【(\d{1,2})】/g,
      function (matched, asciiNumber, fullWidthNumber, bracketNumber) {
        const number = asciiNumber || fullWidthNumber || bracketNumber;
        const citationId = "[" + number + "]";
        return allowed.has(citationId) ? citationId : matched;
      }
    );
  }

  function parseInline(source, options, depth) {
    const nodes = [];
    let index = 0;
    const nesting = depth || 0;

    function nested(value) {
      if (nesting >= 3) {
        return [{type: "text", text: value}];
      }
      return parseInline(value, options, nesting + 1);
    }

    while (index < source.length) {
      if (nodes.length > MAX_INLINE_NODES) {
        throw new RangeError("restricted Markdown exceeds maximum inline nodes");
      }

      if (source.startsWith("**", index)) {
        const closing = source.indexOf("**", index + 2);
        if (closing > index + 2) {
          nodes.push({
            type: "strong",
            children: nested(source.slice(index + 2, closing))
          });
          index = closing + 2;
          continue;
        }
      }

      if (source[index] === "*" && source[index + 1] !== "*") {
        const closing = source.indexOf("*", index + 1);
        if (closing > index + 1) {
          nodes.push({
            type: "emphasis",
            children: nested(source.slice(index + 1, closing))
          });
          index = closing + 1;
          continue;
        }
      }

      if (source[index] === INLINE_CODE_MARK) {
        const closing = source.indexOf(INLINE_CODE_MARK, index + 1);
        if (closing > index + 1) {
          nodes.push({
            type: "inline_code",
            text: source.slice(index + 1, closing)
          });
          index = closing + 1;
          continue;
        }
      }

      if (source[index] === "[") {
        const citation = /^\[(\d{1,2})\]/.exec(source.slice(index));
        if (citation && citationAllowed(citation[0], options)) {
          nodes.push({type: "citation_ref", citationId: citation[0]});
          index += citation[0].length;
          continue;
        }
        const labelEnd = source.indexOf("](", index + 1);
        const targetEnd = labelEnd >= 0 ? source.indexOf(")", labelEnd + 2) : -1;
        if (labelEnd > index + 1 && targetEnd > labelEnd + 2) {
          const label = source.slice(index + 1, labelEnd);
          const target = source.slice(labelEnd + 2, targetEnd);
          const safeTarget = sanitizeLinkTarget(
            target,
            options && options.allowedOrigins
          );
          if (safeTarget.kind !== "blocked") {
            nodes.push({
              type: "link",
              href: safeTarget.href,
              linkKind: safeTarget.kind,
              children: nested(label)
            });
          } else {
            pushText(nodes, label);
          }
          index = targetEnd + 1;
          continue;
        }
      }

      const nextCandidates = [
        source.indexOf("**", index + 1),
        source.indexOf("*", index + 1),
        source.indexOf(INLINE_CODE_MARK, index + 1),
        source.indexOf("[", index + 1)
      ].filter(function (candidate) {
        return candidate >= 0;
      });
      const next = nextCandidates.length
        ? Math.min.apply(Math, nextCandidates)
        : source.length;
      if (next > index) {
        pushText(nodes, source.slice(index, next));
        index = next;
      } else {
        pushText(nodes, source[index]);
        index += 1;
      }
    }
    return nodes;
  }

  function headingMatch(line) {
    return /^(#{2,6})\s+(.+?)\s*$/.exec(line);
  }

  function unorderedMatch(line) {
    return /^[-+*]\s+(.+)$/.exec(line);
  }

  function orderedMatch(line) {
    return /^\d+[.)]\s+(.+)$/.exec(line);
  }

  function splitTableRow(line) {
    const value = typeof line === "string" ? line.trim() : "";
    if (!value.startsWith("|") || !value.endsWith("|")) {
      return null;
    }
    const cells = value.slice(1, -1).split("|").map(function (cell) {
      return cell.trim();
    });
    if (
      cells.length < 2 ||
      cells.length > MAX_TABLE_COLUMNS ||
      !cells.some(Boolean)
    ) {
      return null;
    }
    return cells;
  }

  function tableAlignment(cell) {
    const value = cell.trim();
    if (!/^:?-{3,}:?$/.test(value)) {
      return null;
    }
    if (value.startsWith(":") && value.endsWith(":")) {
      return "center";
    }
    if (value.endsWith(":")) {
      return "right";
    }
    return "left";
  }

  function tableMatch(lines, index) {
    if (!Array.isArray(lines) || index + 1 >= lines.length) {
      return null;
    }
    const headers = splitTableRow(lines[index]);
    const separators = splitTableRow(lines[index + 1]);
    if (!headers || !separators || headers.length !== separators.length) {
      return null;
    }
    const alignments = separators.map(tableAlignment);
    if (alignments.some(function (alignment) { return alignment === null; })) {
      return null;
    }
    return {headers: headers, alignments: alignments};
  }

  function isBlockStart(lines, index) {
    const line = lines[index];
    return Boolean(
      headingMatch(line) ||
      unorderedMatch(line) ||
      orderedMatch(line) ||
      tableMatch(lines, index)
    );
  }

  function normalizeInlineStrongParagraphs(source) {
    return source.replace(
      /([^\n])\n[ \t]*\n[ \t]*(\*\*[^\n]+?\*\*)[ \t]*\n[ \t]*\n[ \t]*((?:에서|으로|부터|까지|처럼|보다|이며|이고|이라|라고|이라는|은|는|이|가|을|를|의|에|로|와|과|도|만)(?=[\s가-힣]))/g,
      "$1 $2$3"
    );
  }

  function parse(source, options) {
    if (typeof source !== "string") {
      throw new TypeError("restricted Markdown source must be a string");
    }
    if (source.length > CONTRACT.maxSourceChars) {
      throw new RangeError("restricted Markdown exceeds maximum length");
    }
    const lines = normalizeCitationSyntax(
      normalizeInlineStrongParagraphs(source),
      options
    )
      .replace(/\r\n?/g, "\n")
      .replace(/\u0000/g, "\ufffd")
      .split("\n");
    const blocks = [];
    let index = 0;

    while (index < lines.length) {
      if (blocks.length > MAX_BLOCKS) {
        throw new RangeError("restricted Markdown exceeds maximum blocks");
      }
      const line = lines[index];
      if (!line.trim()) {
        index += 1;
        continue;
      }

      const table = tableMatch(lines, index);
      if (table) {
        index += 2;
        const rows = [];
        while (index < lines.length && lines[index].trim()) {
          const cells = splitTableRow(lines[index]);
          if (!cells || cells.length !== table.headers.length) {
            break;
          }
          if (rows.length >= MAX_TABLE_ROWS) {
            throw new RangeError("restricted Markdown exceeds maximum table rows");
          }
          rows.push(cells.map(function (cell) {
            return parseInline(cell, options);
          }));
          index += 1;
        }
        blocks.push({
          type: "table",
          headers: table.headers.map(function (cell) {
            return parseInline(cell, options);
          }),
          alignments: table.alignments,
          rows: rows
        });
        continue;
      }

      const heading = headingMatch(line);
      if (heading) {
        blocks.push({
          type: "heading",
          level: heading[1].length,
          children: parseInline(heading[2], options)
        });
        index += 1;
        continue;
      }

      const unordered = unorderedMatch(line);
      if (unordered) {
        const items = [];
        while (index < lines.length) {
          const item = unorderedMatch(lines[index]);
          if (!item) {
            break;
          }
          if (items.length >= MAX_LIST_ITEMS) {
            throw new RangeError("restricted Markdown exceeds maximum list items");
          }
          items.push(parseInline(item[1], options));
          index += 1;
        }
        blocks.push({type: "unordered_list", items: items});
        continue;
      }

      const ordered = orderedMatch(line);
      if (ordered) {
        const items = [];
        while (index < lines.length) {
          const item = orderedMatch(lines[index]);
          if (!item) {
            break;
          }
          if (items.length >= MAX_LIST_ITEMS) {
            throw new RangeError("restricted Markdown exceeds maximum list items");
          }
          items.push(parseInline(item[1], options));
          index += 1;
        }
        blocks.push({type: "ordered_list", items: items});
        continue;
      }

      const paragraph = [line.trim()];
      index += 1;
      while (
        index < lines.length &&
        lines[index].trim() &&
        !isBlockStart(lines, index)
      ) {
        paragraph.push(lines[index].trim());
        index += 1;
      }
      blocks.push({
        type: "paragraph",
        children: parseInline(paragraph.join(" "), options)
      });
    }

    return {
      version: CONTRACT.version,
      blocks: blocks
    };
  }

  function sanitizeInline(nodes, options, depth) {
    if (!Array.isArray(nodes) || (depth || 0) > 3) {
      return [];
    }
    const safe = [];
    nodes.slice(0, MAX_INLINE_NODES).forEach(function (node) {
      if (!node || typeof node !== "object") {
        return;
      }
      if (node.type === "text" && typeof node.text === "string") {
        pushText(safe, node.text);
        return;
      }
      if (node.type === "inline_code" && typeof node.text === "string") {
        safe.push({type: "inline_code", text: node.text});
        return;
      }
      if (
        node.type === "citation_ref" &&
        typeof node.citationId === "string" &&
        citationAllowed(node.citationId, options)
      ) {
        safe.push({type: "citation_ref", citationId: node.citationId});
        return;
      }
      if (
        (node.type === "strong" || node.type === "emphasis") &&
        Array.isArray(node.children)
      ) {
        safe.push({
          type: node.type,
          children: sanitizeInline(node.children, options, (depth || 0) + 1)
        });
        return;
      }
      if (node.type === "link" && Array.isArray(node.children)) {
        const target = sanitizeLinkTarget(
          typeof node.href === "string" ? node.href : "",
          options && options.allowedOrigins
        );
        if (target.kind === "blocked") {
          sanitizeInline(node.children, options, (depth || 0) + 1)
            .forEach(function (child) {
              if (child.type === "text") {
                pushText(safe, child.text);
              } else {
                safe.push(child);
              }
            });
          return;
        }
        safe.push({
          type: "link",
          href: target.href,
          linkKind: target.kind,
          children: sanitizeInline(node.children, options, (depth || 0) + 1)
        });
      }
    });
    return safe;
  }

  function sanitizeAst(ast, options) {
    if (
      !ast ||
      typeof ast !== "object" ||
      ast.version !== CONTRACT.version ||
      !Array.isArray(ast.blocks)
    ) {
      throw new TypeError("restricted Markdown AST contract is invalid");
    }
    const blocks = [];
    ast.blocks.slice(0, MAX_BLOCKS).forEach(function (block) {
      if (!block || typeof block !== "object") {
        return;
      }
      if (block.type === "heading" && Array.isArray(block.children)) {
        blocks.push({
          type: "heading",
          level: Math.max(2, Math.min(6, Number(block.level) || 2)),
          children: sanitizeInline(block.children, options)
        });
        return;
      }
      if (block.type === "paragraph" && Array.isArray(block.children)) {
        blocks.push({
          type: "paragraph",
          children: sanitizeInline(block.children, options)
        });
        return;
      }
      if (
        (block.type === "unordered_list" || block.type === "ordered_list") &&
        Array.isArray(block.items)
      ) {
        blocks.push({
          type: block.type,
          items: block.items.slice(0, MAX_LIST_ITEMS).map(function (item) {
            return sanitizeInline(item, options);
          })
        });
        return;
      }
      if (
        block.type === "table" &&
        Array.isArray(block.headers) &&
        Array.isArray(block.rows) &&
        Array.isArray(block.alignments) &&
        block.headers.length >= 2 &&
        block.headers.length <= MAX_TABLE_COLUMNS &&
        block.alignments.length === block.headers.length
      ) {
        const columnCount = block.headers.length;
        const alignments = block.alignments.map(function (alignment) {
          return ["left", "center", "right"].includes(alignment)
            ? alignment
            : "left";
        });
        blocks.push({
          type: "table",
          headers: block.headers.map(function (cell) {
            return sanitizeInline(cell, options);
          }),
          alignments: alignments,
          rows: block.rows.slice(0, MAX_TABLE_ROWS).filter(function (row) {
            return Array.isArray(row) && row.length === columnCount;
          }).map(function (row) {
            return row.map(function (cell) {
              return sanitizeInline(cell, options);
            });
          })
        });
      }
    });
    return {version: CONTRACT.version, blocks: blocks};
  }

  function appendInline(documentRef, parent, nodes, options) {
    nodes.forEach(function (node) {
      if (node.type === "text") {
        parent.appendChild(documentRef.createTextNode(node.text));
        return;
      }
      if (node.type === "inline_code") {
        const code = documentRef.createElement("code");
        code.textContent = node.text;
        parent.appendChild(code);
        return;
      }
      if (node.type === "strong" || node.type === "emphasis") {
        const emphasis = documentRef.createElement(
          node.type === "strong" ? "strong" : "em"
        );
        appendInline(documentRef, emphasis, node.children, options);
        parent.appendChild(emphasis);
        return;
      }
      if (node.type === "citation_ref") {
        const button = documentRef.createElement("button");
        button.setAttribute("type", "button");
        button.className = "ai-citation-ref";
        button.textContent = node.citationId;
        button.setAttribute("aria-label", node.citationId + " 출처 보기");
        button.addEventListener("click", function () {
          if (options && typeof options.onCitationActivate === "function") {
            options.onCitationActivate(node.citationId);
          }
        });
        parent.appendChild(button);
        return;
      }
      if (node.type === "link") {
        const link = documentRef.createElement("a");
        link.setAttribute("href", node.href);
        link.setAttribute("rel", "noopener noreferrer");
        if (node.linkKind === "https") {
          link.setAttribute("target", "_blank");
        }
        appendInline(documentRef, link, node.children, options);
        parent.appendChild(link);
      }
    });
  }

  function renderAst(container, ast, options) {
    if (!container || !container.ownerDocument) {
      throw new TypeError("restricted Markdown container is invalid");
    }
    const documentRef = container.ownerDocument;
    const safeAst = sanitizeAst(ast, options);
    const fragment = documentRef.createDocumentFragment();

    safeAst.blocks.forEach(function (block) {
      if (block.type === "heading") {
        const heading = documentRef.createElement(block.level === 2 ? "h3" : "h4");
        appendInline(documentRef, heading, block.children, options);
        fragment.appendChild(heading);
        return;
      }
      if (block.type === "paragraph") {
        const paragraph = documentRef.createElement("p");
        appendInline(documentRef, paragraph, block.children, options);
        fragment.appendChild(paragraph);
        return;
      }
      if (block.type === "table") {
        const wrapper = documentRef.createElement("div");
        wrapper.className = "ai-markdown-table-wrap";
        wrapper.setAttribute("role", "region");
        wrapper.setAttribute("aria-label", "AI 설명 표");
        wrapper.setAttribute("tabindex", "0");
        const table = documentRef.createElement("table");
        table.className = "ai-markdown-table";
        const head = documentRef.createElement("thead");
        const headRow = documentRef.createElement("tr");
        block.headers.forEach(function (cell, cellIndex) {
          const header = documentRef.createElement("th");
          header.setAttribute("scope", "col");
          header.style.textAlign = block.alignments[cellIndex];
          appendInline(documentRef, header, cell, options);
          headRow.appendChild(header);
        });
        head.appendChild(headRow);
        table.appendChild(head);
        const body = documentRef.createElement("tbody");
        block.rows.forEach(function (row) {
          const tableRow = documentRef.createElement("tr");
          row.forEach(function (cell, cellIndex) {
            const data = documentRef.createElement("td");
            data.style.textAlign = block.alignments[cellIndex];
            appendInline(documentRef, data, cell, options);
            tableRow.appendChild(data);
          });
          body.appendChild(tableRow);
        });
        table.appendChild(body);
        wrapper.appendChild(table);
        fragment.appendChild(wrapper);
        return;
      }
      const list = documentRef.createElement(
        block.type === "ordered_list" ? "ol" : "ul"
      );
      block.items.forEach(function (item) {
        const listItem = documentRef.createElement("li");
        appendInline(documentRef, listItem, item, options);
        list.appendChild(listItem);
      });
      fragment.appendChild(list);
    });

    container.replaceChildren(fragment);
    container.classList.remove("ai-markdown-fallback");
    container.removeAttribute("data-markdown-fallback");
    return safeAst;
  }

  function render(container, source, options) {
    return renderAst(container, parse(source, options), options);
  }

  function createStreamingRenderer(container, options) {
    const settings = options || {};
    const throttleMs = Number.isFinite(settings.throttleMs)
      ? Math.max(0, Math.min(1000, settings.throttleMs))
      : CONTRACT.throttleMs;
    let source = "";
    let timer = null;
    let destroyed = false;
    let exceeded = false;

    function sourceForDisplay() {
      if (typeof settings.sourceTransform !== "function") {
        return source;
      }
      const transformed = settings.sourceTransform(source);
      return typeof transformed === "string" ? transformed : source;
    }

    function clearTimer() {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    function fallbackToPlainText() {
      clearTimer();
      try {
        container.textContent = sourceForDisplay();
      } catch (_error) {
        container.textContent = source;
      }
      container.classList.add("ai-markdown-fallback");
      container.dataset.markdownFallback = "true";
    }

    function flush() {
      if (destroyed) {
        return;
      }
      clearTimer();
      if (exceeded) {
        fallbackToPlainText();
        return;
      }
      try {
        render(container, sourceForDisplay(), settings);
      } catch (_error) {
        fallbackToPlainText();
      }
    }

    function schedule() {
      if (throttleMs === 0) {
        flush();
        return;
      }
      if (timer !== null) {
        return;
      }
      timer = setTimeout(flush, throttleMs);
    }

    function append(delta) {
      if (destroyed || typeof delta !== "string" || !delta) {
        return;
      }
      if (source.length + delta.length > CONTRACT.maxSourceChars) {
        const remaining = Math.max(0, CONTRACT.maxSourceChars - source.length);
        source += delta.slice(0, remaining);
        source += "\n\n[AI 설명이 길어 일부 내용을 표시하지 않았습니다.]";
        exceeded = true;
        fallbackToPlainText();
        return;
      }
      source += delta;
      schedule();
    }

    function complete() {
      flush();
    }

    function destroy() {
      clearTimer();
      destroyed = true;
    }

    return Object.freeze({
      append: append,
      complete: complete,
      destroy: destroy,
      fallbackToPlainText: fallbackToPlainText,
      flush: flush,
      getSource: function () {
        return source;
      }
    });
  }

  return Object.freeze({
    CONTRACT: CONTRACT,
    createStreamingRenderer: createStreamingRenderer,
    parse: parse,
    render: render,
    renderAst: renderAst,
    sanitizeAst: sanitizeAst,
    sanitizeLinkTarget: sanitizeLinkTarget
  });
}));
