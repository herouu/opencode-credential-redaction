/**
 * credential-redaction —— 阻止 API key / 密码 / token 进入 LLM 上下文（双向）
 * ============================================================================
 * 宿主：opencode v2（本机 2.2.0）。加载器要求 default 导出为对象且含 `id` + `setup`。
 *       与同目录 local-memory.ts 同约定：不 import 任何 npm 包，只用 node: 内置模块。
 *
 * 为什么需要它（L0 配置层管不到的部分）：
 *   配置里的 permission deny 只能拦「工具明确请求某个路径/命令」。以下路径仍会漏：
 *     1. curl -v 回显 Authorization header
 *     2. MCP / HTTP 错误文本带凭证
 *     3. 日志文件里 grep 命中 token（路径本身不敏感）
 *     4. 用户自己粘贴进 prompt
 *     5. 子代理把原文结果汇总上报
 *     6. 压缩摘要、会话标题生成两条辅助模型调用
 *   本插件按「入口遮 + 出站兜底 + 执行前回填」三层覆盖以上全部。
 *
 * 五个钩子：
 *   session.hook("prompt")        —— 用户输入落地即脱敏（会写入持久历史）
 *   tool.hook("execute.after")    —— 工具结果写历史前脱敏（覆盖 1/2/3）
 *   session.hook("context")       —— 出站主循环 request 兜底（覆盖 4/5/6）
 *   session.hook("compaction")    —— 同上，压缩摘要调用
 *   session.hook("generate")      —— 同上，其它生成调用
 *   session.hook("title")         —— 同上，标题生成（漏这个就漏一条）
 *   tool.hook("execute.before")   —— 把占位符回填成真值，否则模型拿不到密钥、工具跑不了
 *
 * 占位符格式：[[REDACTED:<NAME>]]。同一个真值始终映射到同一个占位符，模型可稳定引用。
 *
 * 密钥来源（按顺序合并，同值去重）：
 *   1. 显式清单文件 ~/.config/opencode/redact-secrets.txt
 *      每行 `NAME=VALUE`，或裸值（自动命名 SECRET_<n>）；空行与 # 注释跳过。
 *      文件改动无需重启，判定延迟上限 5s。
 *   2. 环境变量扫描：变量名匹配 /(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|
 *      CREDENTIAL|PRIVATE_?KEY|AUTH)/i 且值长度 >= 12 的。
 *
 * 回填策略：execute.before 默认对**除文件写入类以外**的工具回填真值。
 *   为什么排除 edit/write/patch：模型看到占位符后可能把 [[REDACTED:X]] 写进新文件，
 *   若无脑回填等于把真密钥复制到磁盘新位置。确实需要写盘时设
 *   OPENCODE_REDACT_REHYDRATE_EDIT=1。
 *
 * 开关：
 *   OPENCODE_REDACT_DISABLE=1     —— 整体停用
 *   建标记文件 %TEMP%\opencode\credential-redaction.debug —— 开调试日志
 *   （日志只记变量名/长度/命中次数，**绝不记真值**）
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

// ─────────────────────────────── 常量 ───────────────────────────────

const PLUGIN_ID = "credential-redaction";
const LOG_PATH = join(tmpdir(), "opencode", "credential-redaction.log");
const DEBUG_FLAG = join(tmpdir(), "opencode", "credential-redaction.debug");
/** 全局配置目录：优先 OPENCODE_CONFIG_DIR，其次 XDG_CONFIG_HOME，最后 ~/.config/opencode。 */
const CONFIG_DIR =
  process.env.OPENCODE_CONFIG_DIR ??
  (process.env.XDG_CONFIG_HOME
    ? join(process.env.XDG_CONFIG_HOME, "opencode")
    : join(homedir(), ".config", "opencode"));
const EXTRA_FILE = process.env.OPENCODE_REDACT_SECRETS_FILE ?? join(CONFIG_DIR, "redact-secrets.txt");

/** 变量名命中即视为凭据候选。 */
const ENV_NAME_RE = /(API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)/i;
/** 值过短会造成大面积误伤（例如某个变量恰好等于 "test"），不够长的一律不处理。 */
const MIN_SECRET_LEN = 12;
/** 变量名黑名单：名字含 TOKEN/KEY 之类但其实是路径或开关的。 */
const ENV_NAME_DENY = new Set([
  "PATH", "PWD", "OLDPWD", "HOME", "SHELL", "TERM", "PAGER", "EDITOR", "VISUAL",
  "TMPDIR", "TEMP", "TMP", "COMSPEC", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
  "OPENCODE_REDACT_DISABLE", "OPENCODE_REDACT_REHYDRATE_EDIT",
]);
/** 默认不回填真值的工具（文件写入类）。 */
const NO_REHYDRATE_TOOLS = new Set(["edit", "write", "patch", "apply_patch"]);
/** 占位符前后缀。 */
const PH_OPEN = "[[REDACTED:";
const PH_CLOSE = "]]";

// ─────────────────────────────── 调试日志 ───────────────────────────────

let logDirReady = false;
function ensureLogDir(): boolean {
  if (logDirReady) return true;
  try {
    mkdirSync(dirname(LOG_PATH), { recursive: true });
    logDirReady = true;
    return true;
  } catch {
    return false;
  }
}

function debugEnabled(): boolean {
  if (process.env.OPENCODE_REDACT_DISABLE === "1") return false;
  try {
    if (existsSync(DEBUG_FLAG)) return true;
  } catch {
    // ignore
  }
  return process.env.OPENCODE_REDACT_DEBUG === "1";
}

function flog(...parts: unknown[]): void {
  if (!debugEnabled()) return;
  try {
    if (!ensureLogDir()) return;
    const body = parts
      .map((p) => (typeof p === "string" ? p : safeJson(p)))
      .join(" ");
    appendFileSync(LOG_PATH, `[${new Date().toISOString()}] [${PLUGIN_ID}] ${body}\n`, "utf8");
  } catch {
    // 调试日志失败绝不影响宿主
  }
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}

// ─────────────────────────────── 密钥表 ───────────────────────────────

type Secret = { name: string; value: string; placeholder: string };

/** 按「值」索引，用于脱敏时反查占位符。 */
let byValue = new Map<string, Secret>();
/** 按「名字」索引，用于回填时反查真值。 */
let byName = new Map<string, Secret>();
/** 快检查：先用非全局正则 test，未命中直接返回原字符串，避免无谓替换。 */
let checkRe: RegExp | null = null;
/** 替换用：全局正则，备选项按真值长度降序排列（正则择左优先，长值必须在前）。 */
let replaceRe: RegExp | null = null;
/** 清单文件 mtime，用于热刷新节流。 */
let extraMtimeMs = -1;
let lastRefreshCheck = 0;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readExtraFile(): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  let raw = "";
  try {
    if (!existsSync(EXTRA_FILE)) return out;
    const st = statSync(EXTRA_FILE);
    extraMtimeMs = st.mtimeMs;
    raw = readFileSync(EXTRA_FILE, "utf8");
  } catch {
    return out;
  }
  let anon = 0;
  for (const line0 of raw.split(/\r?\n/)) {
    const line = line0.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    let name: string;
    let value: string;
    if (eq > 0) {
      name = line.slice(0, eq).trim() || `SECRET_${++anon}`;
      value = line.slice(eq + 1).trim();
    } else {
      name = `SECRET_${++anon}`;
      value = line;
    }
    // 去包裹引号
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    if (value.length >= MIN_SECRET_LEN) out.push({ name, value });
  }
  return out;
}

function collectEnvSecrets(): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  for (const [name, value] of Object.entries(process.env)) {
    if (!value || value.length < MIN_SECRET_LEN) continue;
    if (ENV_NAME_DENY.has(name)) continue;
    // 插件自身的开关变量名里常带 SECRET（如 OPENCODE_REDACT_SECRETS_FILE），
    // 它们的值是路径/布尔值，收进密钥表会把普通路径误脱敏成占位符。
    if (name.startsWith("OPENCODE_REDACT_")) continue;
    if (!ENV_NAME_RE.test(name)) continue;
    out.push({ name, value });
  }
  return out;
}

function rebuild(): void {
  const candidates = [...readExtraFile(), ...collectEnvSecrets()];
  const nextByValue = new Map<string, Secret>();
  const nextByName = new Map<string, Secret>();
  for (const c of candidates) {
    if (nextByValue.has(c.value)) continue; // 同值只保留首个名字
    if (nextByName.has(c.name)) continue; // 同名只保留首个值
    const s: Secret = { name: c.name, value: c.value, placeholder: `${PH_OPEN}${c.name}${PH_CLOSE}` };
    nextByValue.set(s.value, s);
    nextByName.set(s.name, s);
  }
  byValue = nextByValue;
  byName = nextByName;

  // 备选项长度降序，保证 [[A]] 之类的长值先匹配
  const values = [...nextByValue.keys()].sort((a, b) => b.length - a.length);
  if (values.length === 0) {
    checkRe = null;
    replaceRe = null;
  } else {
    const alternation = values.map(escapeRe).join("|");
    checkRe = new RegExp(alternation);
    replaceRe = new RegExp(alternation, "g");
  }
}

/** 清单文件改动热生效：每 5s 最多检查一次 mtime。 */
function refreshIfStale(): void {
  const now = Date.now();
  if (now - lastRefreshCheck < 5000) return;
  lastRefreshCheck = now;
  try {
    if (!existsSync(EXTRA_FILE)) return;
    const mtime = statSync(EXTRA_FILE).mtimeMs;
    if (mtime !== extraMtimeMs) {
      rebuild();
      flog("密钥表已因文件变更重建", { count: byValue.size, names: [...byName.keys()] });
    }
  } catch {
    // ignore
  }
}

// ─────────────────────────────── 脱敏 / 回填 ───────────────────────────────

function redactString(s: string): string {
  // 先用非全局正则做一次快检：绝大多数字符串不含密钥，省掉 replace 的分配
  if (!checkRe || !checkRe.test(s)) return s;
  return s.replace(replaceRe as RegExp, (m) => byValue.get(m)?.placeholder ?? unknownPlaceholder);
}

/** 理论不可达：正则备选项全部来自 byValue 的键。真走到这里说明替换正则与表脱节。 */
const unknownPlaceholder = `${PH_OPEN}UNKNOWN${PH_CLOSE}`;

function rehydrateString(s: string): string {
  if (s.indexOf(PH_OPEN) === -1) return s;
  return s.replace(/\[\[REDACTED:([^\]]+)\]\]/g, (m, name: string) => byName.get(name.trim())?.value ?? m);
}

type Mapper = (s: string) => string;

/** 不可/不应深度遍历的对象：二进制、日期、容器类。其余（含 schema 解出的类实例）都要走。 */
function isOpaqueObject(v: object): boolean {
  return (
    v instanceof Date ||
    v instanceof RegExp ||
    v instanceof Map ||
    v instanceof Set ||
    v instanceof ArrayBuffer ||
    ArrayBuffer.isView(v)
  );
}

/**
 * 深度遍历字符串并映射，**不修改入参对象**（context 钩子的 messages 是按引用传入的，
 * 就地改会污染持久会话状态）。无改动时原样返回同一引用，避免无谓的写放大。
 *
 * 注意：opencode 传给钩子的 message 是 schema 解码产物（类实例），
 * `Object.getPrototypeOf(v) !== Object.prototype` **不能**作为跳过条件 —— 早先版本
 * 就是这么写的，导致 messages 深度改写整体静默失效（system 因为只是 push 新元素才没暴露）。
 * 这里用「保持原原型 + 只复制自有可枚举键」的方式克隆，既遍历到内部又维持类型可再校验。
 */
function mapDeep<T>(v: T, f: Mapper): T {
  if (typeof v === "string") return f(v) as unknown as T;
  if (Array.isArray(v)) {
    let changed = false;
    const out = v.map((x) => {
      const y = mapDeep(x, f);
      if (y !== x) changed = true;
      return y;
    });
    return (changed ? out : v) as unknown as T;
  }
  if (v && typeof v === "object") {
    if (isOpaqueObject(v as object)) return v;
    const src = v as unknown as Record<string, unknown>;
    let changed = false;
    const out = Object.create(Object.getPrototypeOf(v)) as Record<string, unknown>;
    for (const k of Object.keys(src)) {
      const y = mapDeep(src[k], f);
      if (y !== src[k]) changed = true;
      out[k] = y;
    }
    return (changed ? out : v) as unknown as T;
  }
  return v;
}

let hits = { redact: 0, rehydrate: 0 };

function redactDeep<T>(v: T): T {
  if (!checkRe) return v;
  const out = mapDeep(v, redactString);
  if (out !== v) hits.redact++;
  return out;
}

// ─────────────────────────────── setup ───────────────────────────────

async function setup(ctx: any): Promise<() => void> {
  if (process.env.OPENCODE_REDACT_DISABLE === "1") {
    flog("OPENCODE_REDACT_DISABLE=1，插件不注册任何钩子");
    return () => {};
  }

  rebuild();
  flog("setup 完成", { secrets: byValue.size, names: [...byName.keys()] });
  if (byValue.size === 0) {
    flog(`密钥表为空：请写 ${EXTRA_FILE}（NAME=VALUE 每行一条）或设置匹配的环境变量`);
  }

  const eager = (label: string, fn: () => Promise<unknown>) =>
    fn().catch((err: unknown) => flog(`钩子注册失败：${label}`, String(err)));

  // 1) 用户输入落地即脱敏（会写入持久历史）
  await eager("session.prompt", () =>
    ctx.session.hook("prompt", (e: any) => {
      refreshIfStale();
      if (typeof e?.prompt?.text !== "string") return;
      const next = redactDeep(e.prompt.text);
      if (next !== e.prompt.text) {
        e.prompt.text = next;
        flog("prompt 已脱敏");
      }
    }),
  );

  // 2) 工具结果写历史前脱敏（bash 输出 / 文件内容 / MCP 错误文本）
  await eager("tool.execute.after", () =>
    ctx.tool.hook("execute.after", (e: any) => {
      refreshIfStale();
      if (e?.status === "completed" && e.result) {
        const r = e.result;
        if (typeof r.output === "string") r.output = redactDeep(r.output);
        if (r.content !== undefined) r.content = redactDeep(r.content);
        if (r.metadata !== undefined) r.metadata = redactDeep(r.metadata);
      } else if (e?.status === "error" && e.error) {
        const err = e.error;
        if (typeof err.message === "string") err.message = redactDeep(err.message);
        if (err.data !== undefined) err.data = redactDeep(err.data);
      }
    }),
  );

  // 3) 出站兜底：四种 kind 必须各注册一次，漏 title 就漏一条辅助调用
  const probed = new Set<string>();
  for (const kind of ["context", "compaction", "generate", "title"] as const) {
    await eager(`session.${kind}`, () =>
      ctx.session.hook(kind, (e: any) => {
        refreshIfStale();
        if (debugEnabled() && !probed.has(kind)) {
          probed.add(kind);
          flog(`探针 ${kind} 首次触发`, {
            keys: Object.keys(e ?? {}),
            messages: Array.isArray(e?.messages) ? `array(${e.messages.length})` : typeof e?.messages,
            system: Array.isArray(e?.system) ? `array(${e.system.length})` : typeof e?.system,
          });
        }
        if (Array.isArray(e.messages)) {
          const next = redactDeep(e.messages);
          if (next !== e.messages) {
            e.messages = next;
            flog(`${kind}: messages 已脱敏`, { n: e.messages.length });
          }
        }
        if (Array.isArray(e.system)) {
          const next = redactDeep(e.system);
          if (next !== e.system) {
            e.system = next;
            flog(`${kind}: system 已脱敏`);
          }
        }
        // title/compaction 自带 result 时可跳过模型调用，也要脱敏
        if (typeof e.result === "string") e.result = redactDeep(e.result);
      }),
    );
  }

  // 4) 执行前回填：让模型能用占位符驱动真实工具
  const rehydrateEdit = process.env.OPENCODE_REDACT_REHYDRATE_EDIT === "1";
  await eager("tool.execute.before", () =>
    ctx.tool.hook("execute.before", (e: any) => {
      refreshIfStale();
      if (byName.size === 0) return;
      if (!rehydrateEdit && NO_REHYDRATE_TOOLS.has(String(e?.tool ?? ""))) {
        flog("跳过回填（文件写入类工具）", String(e?.tool));
        return;
      }
      const next = mapDeep(e.input, (s) => {
        const out = rehydrateString(s);
        if (out !== s) hits.rehydrate++;
        return out;
      });
      if (next !== e.input) e.input = next;
    }),
  );

  flog("全部钩子已注册", { secrets: byName.size });
  return () => {
    flog("cleanup", hits);
  };
}

export default {
  id: PLUGIN_ID,
  setup,
};
