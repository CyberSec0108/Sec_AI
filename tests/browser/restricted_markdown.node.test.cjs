"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const renderer = require(path.resolve(
  __dirname,
  "../../apps/web/static/app/restricted-markdown.js"
));

assert.equal(renderer.CONTRACT.version, "secai.restricted-markdown.v3");
assert.deepEqual(renderer.CONTRACT.allowedBlocks, [
  "heading",
  "paragraph",
  "unordered_list",
  "ordered_list",
  "table"
]);
assert.deepEqual(renderer.CONTRACT.allowedInline, [
  "text",
  "strong",
  "emphasis",
  "inline_code",
  "link",
  "citation_ref"
]);

const ast = renderer.parse(
  "## 왜 중요한가요?\n\n" +
  "**양호** 상태이며 *현재 설정*을 유지하세요.\n\n" +
  "- 첫 번째 조치\n- 두 번째 조치\n\n" +
  "1. 결과 확인\n2. 다시 점검\n\n" +
  "`PC-01`과 [상세 결과](/ui/results)"
);
assert.deepEqual(ast.blocks.map((block) => block.type), [
  "heading",
  "paragraph",
  "unordered_list",
  "ordered_list",
  "paragraph"
]);
assert.equal(ast.blocks[0].level, 2);
assert.equal(ast.blocks[1].children[0].type, "strong");
assert.equal(ast.blocks[1].children[2].type, "emphasis");
assert.equal(ast.blocks[4].children[0].type, "inline_code");
assert.equal(ast.blocks[4].children[2].type, "link");

const cited = renderer.parse(
  "실제값입니다.[1] 확인되지 않은 번호 [9]",
  {allowedCitationIds: ["[1]", "[2]", "[3]", "[4]"]}
);
assert.equal(cited.blocks[0].children[1].type, "citation_ref");
assert.equal(cited.blocks[0].children[1].citationId, "[1]");
assert.equal(JSON.stringify(cited).includes('"citationId":"[9]"'), false);

const tableAst = renderer.parse(
  "| 점검 항목 | 상태 | 확인 내용 |\n" +
  "|---|:---:|---|\n" +
  "| PC-01 | **양호** | 42일마다 변경 |\n" +
  "| PC-02 | 확인 필요 | `<script>`는 글자로 표시 |"
);
assert.equal(tableAst.blocks[0].type, "table");
assert.equal(tableAst.blocks[0].headers.length, 3);
assert.equal(tableAst.blocks[0].rows.length, 2);
assert.deepEqual(tableAst.blocks[0].alignments, ["left", "center", "left"]);

assert.equal(renderer.sanitizeLinkTarget("/ui/results").kind, "same_origin");
assert.equal(
  renderer.sanitizeLinkTarget(
    "https://www.kisa.or.kr/security",
    ["https://www.kisa.or.kr"]
  ).kind,
  "https"
);
for (const unsafe of [
  "javascript:alert(1)",
  "data:text/html,<script>alert(1)</script>",
  "vbscript:msgbox(1)",
  "//evil.example/path",
  "https://evil.example/path"
]) {
  assert.equal(renderer.sanitizeLinkTarget(unsafe).kind, "blocked");
}

const partial = renderer.parse("**왜 중요한");
assert.equal(partial.blocks[0].children[0].type, "text");
assert.equal(partial.blocks[0].children[0].text, "**왜 중요한");
const completed = renderer.parse("**왜 중요한가요?**");
assert.equal(completed.blocks[0].children[0].type, "strong");

const attacks = renderer.parse(
  "<script>globalThis.pwned=true</script>\n\n" +
  "<svg onload=alert(1)>\n\n" +
  "[위험](javascript:alert(1))\n\n" +
  "![이미지](data:text/html,boom)\n\n" +
  "|열1|열2|\n|---|---|\n|값1|값2|"
);
const serialized = JSON.stringify(attacks);
for (const forbiddenType of ["script", "svg", "image", "raw_html"]) {
  assert.equal(serialized.includes('"type":"' + forbiddenType + '"'), false);
}

const longText = "긴 결과 ".repeat(12800).slice(0, 100 * 1024);
const started = performance.now();
const longAst = renderer.parse(longText);
assert.equal(longAst.blocks.length, 1);
assert.ok(performance.now() - started < 1500);
assert.throws(
  () => renderer.parse("x".repeat(renderer.CONTRACT.maxSourceChars + 1)),
  /maximum length/
);

console.log("restricted-markdown node contract: PASS");
