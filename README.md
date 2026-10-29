# opencode-credential-redaction

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**opencode v2 原生凭证脱敏插件**：让 API key、token、密码在**进入模型上下文之前**就被替换成占位符 `[[REDACTED:NAME]]`，并在**真正执行工具之前**把占位符回填成真值。单文件、**零 npm 依赖**、无需构建。

> An **opencode v2 native credential-redaction plugin**: secrets (API keys, tokens, passwords) are replaced with `[[REDACTED:NAME]]` placeholders *before* they reach the model context, and rehydrated back to real values right before a tool actually runs. Single file, **zero npm dependencies**, no build step.

---

## 目录

- [为什么需要它](#为什么需要它)
- [它做什么](#它做什么)
- [安装](#安装)
- [工作原理：五个钩子](#工作原理五个钩子)
- [占位符与回填策略](#占位符与回填策略)
- [密钥来源](#密钥来源)
- [配套：配置层 deny](#配套配置层-deny)
- [调试](#调试)
- [已知边界](#已知边界)
- [踩坑记录：类实例导致静默失效](#踩坑记录类实例导致静默失效)
- [测试](#测试)
- [相关上游工作](#相关上游工作)
- [License](#license)

---

## 为什么需要它

opencode 的 `permissions` 配置能拦「工具明确请求某个路径或命令」，但管不到这些路径：

| # | 泄露路径 | 例子 |
|---|---|---|
| 1 | shell 输出回显 | `curl -v` 打印 `Authorization` header |
| 2 | 文件内容里含密钥 | 日志文件、`.npmrc`、导出的配置快照 |
| 3 | 工具/协议错误文本 | MCP 报错、HTTP 401 回显 request headers |
| 4 | 用户自己粘贴 | 直接把 key 贴进 prompt 让它「帮我调这个接口」 |
| 5 | 子代理汇总 | 子会话把原文结果上报给父会话 |
| 6 | 辅助模型调用 | 压缩摘要、会话标题生成（不走主循环） |

只要密钥进了上下文，它就是**已经被发出去了**——粘贴回来、改配置、删会话都救不回来。这个插件在发出去之前动手。

## 它做什么

- **入口遮**：用户输入落地即脱敏（第 4 条）
- **写历史前遮**：工具输出、错误文本、元数据在写入会话历史之前脱敏（第 1/2/3 条）
- **出站兜底**：每次模型请求前重扫 `system` 与 `messages`（第 4/5/6 条，覆盖主循环、压缩、生成、标题四种调用）
- **回填**：模型拿着占位符也能真正跑命令——执行前把占位符换回真值

模型全程只看见 `[[REDACTED:CLOUDFLARE_API_TOKEN]]` 这种字符串，而 `curl` 拿到的是真 token。

## 安装

**方式一：npm（推荐）**

在 `opencode.jsonc` 的 `plugins` 里加上包名，opencode 会自行解析安装：

```jsonc
{
  "plugins": ["opencode-credential-redaction"]
}
```

**方式二：手动放文件**

把 `credential-redaction.ts` 放进 opencode 的插件目录：

```
~/.config/opencode/plugin/credential-redaction.ts
```

Windows 即 `C:\Users\<你>\.config\opencode\plugin\credential-redaction.ts`。目录不存在就建。opencode 会自动发现，**不需要**在 `plugins` 里登记。

---

然后建密钥清单（可选，但推荐）：

```sh
cp redact-secrets.example.txt ~/.config/opencode/redact-secrets.txt
```

每行 `NAME=VALUE`。改完不用重启，5 秒内自动生效。

保存即热加载。验证方法见[调试](#调试)。

> 需要 opencode v2（插件 loader 在 v2 要求 `export default { id, setup }`；v1 的 `export const X = async (ctx) => ({...})` 形状在 v2 **完全不加载**）。

## 工作原理：五个钩子

| 钩子 | 时机 | 作用 | 是否影响持久历史 |
|---|---|---|---|
| `session.hook("prompt")` | 用户消息落地 | 脱敏 `prompt.text` | **是**（成为规范历史） |
| `tool.hook("execute.after")` | 工具返回、写历史前 | 脱敏 `result.output` / `content` / `metadata` / `error.message` / `error.data` | **是** |
| `session.hook("context")` | 每次主循环请求前 | 脱敏 `system` / `messages` | 否（只改本次出站） |
| `session.hook("compaction")` | 压缩摘要请求前 | 同上 | 否 |
| `session.hook("generate")` | 其它生成请求前 | 同上 | 否 |
| `session.hook("title")` | 会话标题生成前 | 同上 | 否 |
| `tool.hook("execute.before")` | 工具执行前 | 把占位符回填成真值 | — |

⚠️ **四种 kind 必须各自注册一次**。只挂 `context` 会漏掉标题生成与压缩摘要这两条独立模型调用——上游曾有 issue（#46115）就是这个绕过路径。

## 占位符与回填策略

占位符形如 `[[REDACTED:NAME]]`，同一个真值始终映射到同一个占位符，模型可以稳定地重复引用。

**写盘类工具默认不回填**：`edit` / `write` / `patch` / `apply_patch`。

原因：模型看到占位符后，可能把它写进某个新文件（比如「帮我把这个 key 写进 deploy.sh」）。若无脑回填，等于把真密钥**复制到磁盘的新位置**，扩大了泄露面。默认保留占位符，让这种写入显式失败而不是静默泄密。

确实需要写盘时：

```sh
OPENCODE_REDACT_REHYDRATE_EDIT=1
```

## 密钥来源

按顺序合并，同值去重：

1. **清单文件**：`$OPENCODE_CONFIG_DIR/redact-secrets.txt`（默认 `~/.config/opencode/redact-secrets.txt`，可用环境变量 `OPENCODE_REDACT_SECRETS_FILE` 覆盖）
   - 每行 `NAME=VALUE`，也支持裸值（自动命名 `SECRET_<n>`）
   - 空行与 `#` 开头的行跳过
   - **值长度 < 12 的一律忽略**，避免把普通短字符串当密钥造成大面积误伤
2. **环境变量扫描**：变量名匹配 `API_KEY` / `ACCESS_KEY` / `SECRET` / `TOKEN` / `PASSWORD` / `PASSWD` / `CREDENTIAL` / `PRIVATE_KEY` / `AUTH`（大小写不敏感）且值长度 ≥ 12

清单文件的 mtime 每 5 秒检查一次，改动即时生效，无需重启 opencode。

> 这个文件本身是明文。它等价于「把密钥交给插件保管」，不要提交进 git（仓库的 `.gitignore` 已包含 `redact-secrets.txt`）。

## 配套：配置层 deny

插件是**中间层**，最外层仍建议在 `opencode.jsonc` 里直接禁掉敏感文件与命令。opencode v2 的原生形状是 `permissions` **数组**，规则**最后匹配者生效**（源码 `permission.ts` 用 `findLast`），所以每组要「宽泛/放行在前，具体/守卫在后」：

```jsonc
{
  "permissions": [
    // 凭据文件硬 deny（泛化在前）
    { "action": "read", "resource": "**/.env",     "effect": "deny" },
    { "action": "read", "resource": "**/.env.*",   "effect": "deny" },
    { "action": "read", "resource": "**/.ssh/**",  "effect": "deny" },
    { "action": "read", "resource": "**/.aws/credentials", "effect": "deny" },
    { "action": "read", "resource": "**/id_rsa*",  "effect": "deny" },
    // 白名单例外必须更晚，否则会被上面的 deny 盖掉
    { "action": "read", "resource": "**/.env.example", "effect": "allow" },
    // shell 侧：dump 环境变量要人工点头
    { "action": "shell", "resource": "*Get-ChildItem Env*", "effect": "ask" },
    { "action": "shell", "resource": "*printenv*",          "effect": "ask" },
    { "action": "shell", "resource": "*gh auth token*",     "effect": "ask" }
  ]
}
```

注意 v1 → v2 的 action 改名：`bash` → `shell`、`task` → `subagent`、`write`/`patch`/`apply_patch` → `edit`。`read`/`edit` 的 `resource` 是**纯路径**（内部相对、外部绝对），`~` 会在路径类 action 上展开。

## 调试

```sh
# 打开调试日志（二选一）
export OPENCODE_REDACT_DEBUG=1
# 或建标记文件（无需重启宿主，判定延迟 5s）
#   %TEMP%\opencode\credential-redaction.debug
```

日志：`%TEMP%\opencode\credential-redaction.log`（Linux/macOS 为系统临时目录）。**只记变量名、长度、命中次数，绝不记真值。**

看到这些行说明在工作：

```
[credential-redaction] setup 完成 {"secrets":2,"names":["CLOUDFLARE_API_TOKEN","COMMANDCODE_API_KEY"]}
[credential-redaction] 全部钩子已注册 {"secrets":2}
[credential-redaction] prompt 已脱敏
[credential-redaction] context: messages 已脱敏 {"n":95}
```

整体停用：

```sh
OPENCODE_REDACT_DISABLE=1
```

## 已知边界

1. **密钥必须在清单里或环境变量里**。源码里硬编码的、或只存在 `auth.json` 的凭证，插件不认识——加一行清单即可。
2. **本地会话存储仍是明文**。出站脱敏不写回历史原文，插件管的是「不再进模型」，不是「本地加密」。
3. **压缩可能复活被删文本**（上游 issue #54916 仍 open），极端情况下压缩缩减阶段可能把已脱敏的内容又拉回来。
4. **不覆盖 WebSocket 供应商**。本插件不审 HTTP body，依赖的是 opencode 的 session/tool 钩子；字节级兜底需另挂 `http.request` / `experimental.ws.*`。
5. 占位符一旦泄露到**其他模型或人**手里没有风险，但**回填**会让它们获得真值——所以回填范围才限制在 `execute.before`。

## 踩坑记录：类实例导致静默失效

第一版 `mapDeep` 用 `Object.getPrototypeOf(v) !== Object.prototype` 判断「这是类实例就跳过」。结果 `session.hook("context")` 里的 messages 深度改写**整体静默失效**——opencode 传进来的是 schema 解码产物（类实例），全被跳过。

更阴的是：`system` 看起来正常，因为另一个插件只是往数组里 push 新元素，根本不走深度遍历。所以从外部表现完全看不出这个 bug，日志里也没有任何报错——插件「注册成功」，覆盖率 0。

正确做法：保留原原型克隆，只复制自有可枚举键。

```ts
const out = Object.create(Object.getPrototypeOf(v));
for (const k of Object.keys(v)) { ... }
```

**教训**：安全控制项必须验证到「行为」，不能只看「注册成功」。这也是本仓库带 `tests/harness.mjs` 的原因。

## 测试

```sh
bun tests/harness.mjs
```

覆盖：prompt 脱敏、工具输出脱敏、错误文本脱敏、context 改写且不污染原对象（含类实例回归）、四种 kind 均已注册、执行前回填、写盘工具不回填、无命中不改写、`OPENCODE_REDACT_DISABLE` 停用开关。

## 相关上游工作

- [#50904](https://github.com/anomalyco/opencode/issues/50904) — 官方 opt-in 凭证脱敏提议（`secret_shield`），未落地
- [#59571](https://github.com/anomalyco/opencode/pull/59571) — 上述功能的 V2 移植 PR，作者自述只覆盖主 runner step
- [#46115](https://github.com/anomalyco/opencode/issues/46115) — 标题生成绕过插件钩子（已修复，故本插件能覆盖 `title`）
- [#54916](https://github.com/anomalyco/opencode/issues/54916) — 压缩缩减可能恢复被 hook 删掉的文本

同类第三方方案：`@kkchengg/opencode-redact`、`@rehydra/opencode`。

## License

MIT
