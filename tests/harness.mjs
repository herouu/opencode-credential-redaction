/**
 * credential-redaction 零依赖回归测试
 * ============================================================================
 * 运行：bun tests/harness.mjs
 *
 * 设计要点：
 *   - 密钥表在 setup() 里 rebuild()，所以所有 env 必须在 import 插件之前设好；
 *   - 用假 ctx 捕获注册的回调，逐个手动调用，断言事件对象被如何改写；
 *   - 不开 OPENCODE_REDACT_DEBUG，避免污染日志与引入额外分支。
 *
 * 本文件不修改插件，只观察行为。插件若真有 bug，测试应失败而不是被绕过。
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ─────────────────────────────── 准备环境 ───────────────────────────────

const API_KEY = "dummy-api-key-abcdef123456"; // 环境变量来源的密钥
const FILE_SECRET = "file-secret-value-9876543210"; // 清单文件来源的密钥
const API_PH = "[[REDACTED:TEST_API_KEY]]";
const FILE_PH = "[[REDACTED:FILE_SECRET]]";

const secretDir = mkdtempSync(join(tmpdir(), "cred-redact-test-"));
const secretFile = join(secretDir, "secrets.txt");
writeFileSync(secretFile, `FILE_SECRET=${FILE_SECRET}\n`, "utf8");

process.env.TEST_API_KEY = API_KEY;
process.env.OPENCODE_REDACT_SECRETS_FILE = secretFile;
// 确保不受外部环境干扰
delete process.env.OPENCODE_REDACT_DISABLE;
delete process.env.OPENCODE_REDACT_REHYDRATE_EDIT;
delete process.env.OPENCODE_REDACT_DEBUG;

const { default: plugin } = await import("../credential-redaction.ts");

// ─────────────────────────────── 假 ctx ───────────────────────────────

const handlers = new Map();
const makeCtx = () => ({
  session: {
    hook: async (n, cb) => {
      handlers.set("session:" + n, cb);
      return {};
    },
  },
  tool: {
    hook: async (n, cb) => {
      handlers.set("tool:" + n, cb);
      return {};
    },
  },
});

const cleanup = await plugin.setup(makeCtx());

// ─────────────────────────────── 迷你断言框架 ───────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
    const msg = err instanceof Error ? err.message : String(err);
    failures.push(`${name}: ${msg}`);
    console.log(`FAIL  ${name}`);
    console.log(`      → ${msg}`);
  }
}

function eq(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}：期望 ${JSON.stringify(expected)}，实际 ${JSON.stringify(actual)}`);
  }
}

function ok(cond, label) {
  if (!cond) throw new Error(label);
}

function handler(key) {
  const h = handlers.get(key);
  if (typeof h !== "function") throw new Error(`钩子未注册或不可调用：${key}`);
  return h;
}

// ─────────────────────────────── 用例 ───────────────────────────────

// a) prompt 入口脱敏
await test("a) session:prompt 脱敏用户输入", async () => {
  const h = handler("session:prompt");
  const e = { prompt: { text: `my key is ${API_KEY}` } };
  await h(e);
  eq(e.prompt.text, `my key is ${API_PH}`, "prompt.text");
});

// b) execute.after：completed 三处 + 文件密钥
await test("b) execute.after(completed) 脱敏 output/content/metadata", async () => {
  const h = handler("tool:execute.after");
  const e = {
    status: "completed",
    result: {
      output: `x ${API_KEY} y`,
      content: [{ type: "text", text: FILE_SECRET }],
      metadata: { note: API_KEY },
    },
  };
  await h(e);
  eq(e.result.output, `x ${API_PH} y`, "result.output");
  eq(e.result.content[0].text, FILE_PH, "result.content[0].text");
  eq(e.result.metadata.note, API_PH, "result.metadata.note");
});

// c) execute.after：error 分支
await test("c) execute.after(error) 脱敏 error.message", async () => {
  const h = handler("tool:execute.after");
  const e = { status: "error", error: { message: `401 with ${API_KEY}` } };
  await h(e);
  eq(e.error.message, "401 with " + API_PH, "error.message");
});

// d) context：类实例 messages 必须被深度改写，且不得就地污染原对象
await test("d) session:context 改写 messages/system 且不污染原实例", async () => {
  const h = handler("session:context");

  class Msg {
    constructor(text) {
      this.text = text;
    }
  }

  const originalMsg = new Msg(API_KEY);
  const messages = [originalMsg];
  const system = [{ type: "text", text: API_KEY }];
  const e = { messages, system };

  await h(e);

  ok(e.messages !== messages, "messages 应被替换为新数组（不得原地修改持久历史）");
  eq(e.messages.length, 1, "messages 长度");
  eq(e.messages[0].text, API_PH, "messages[0].text");
  ok(e.messages[0] instanceof Msg, "改写后仍应保持原原型（类实例可再校验）");
  eq(originalMsg.text, API_KEY, "原 Msg 实例的 text 必须保持原值（证明未就地污染）");

  ok(e.system !== system, "system 应被替换为新数组");
  eq(e.system[0].text, API_PH, "system[0].text");
  eq(system[0].text, API_KEY, "原 system 元素必须保持原值");
});

// e) 四种出站 kind 全部注册
await test("e) 四种 kind 已注册（context/compaction/generate/title）", async () => {
  for (const kind of ["context", "compaction", "generate", "title"]) {
    ok(typeof handlers.get("session:" + kind) === "function", `缺少钩子 session:${kind}`);
  }
});

// f) execute.before：普通工具回填，写盘类工具不回填
await test("f) execute.before 回填真值，write 工具保持占位符", async () => {
  const h = handler("tool:execute.before");

  const bashEvent = { tool: "bash", input: { command: `echo ${API_PH}` } };
  await h(bashEvent);
  eq(bashEvent.input.command, `echo ${API_KEY}`, "bash input.command");

  const writeEvent = {
    tool: "write",
    input: { filePath: "a.txt", content: `token = ${API_PH}` },
  };
  await h(writeEvent);
  eq(writeEvent.input.content, `token = ${API_PH}`, "write input.content 应保持占位符");
});

// g) 无命中不改写
await test("g) 无敏感内容时原样返回", async () => {
  const h = handler("session:prompt");
  const e = { prompt: { text: "hello world" } };
  const before = e.prompt.text;
  await h(e);
  eq(e.prompt.text, "hello world", "prompt.text 值");
  ok(e.prompt.text === before, "无命中时字符串引用应保持不变");
});

// h) 停用开关
await test("h) OPENCODE_REDACT_DISABLE=1 时不注册任何钩子", async () => {
  handlers.clear();
  process.env.OPENCODE_REDACT_DISABLE = "1";
  let mod;
  try {
    mod = await import("../credential-redaction.ts?v=disabled");
  } catch {
    // 运行时不支持 import query 时退化为同一模块副本；setup 在调用时才读 env，结论不变
    mod = plugin;
  }
  await mod.default.setup(makeCtx());
  eq(handlers.size, 0, "handlers.size");
});

// ─────────────────────────────── 收尾 ───────────────────────────────

process.env.OPENCODE_REDACT_DISABLE = "1"; // 防止 cleanup 后残留钩子被误判为启用
cleanup();

try {
  rmSync(secretDir, { recursive: true, force: true });
} catch {
  // 临时目录清理失败不影响测试结论
}

console.log("");
console.log(`汇总：${passed} 通过 / ${failed} 失败 / 共 ${passed + failed} 条`);
if (failures.length > 0) {
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
