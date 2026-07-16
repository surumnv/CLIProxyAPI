# CLIProxyAPI 原版请求头处理方式总结（vanilla，未套用自定义改动）

本文件记录 **官方原版 CLIProxyAPI**（7.2.71 / 7.2.77 官方源码，未套用 `CHANGES_CUSTOM.md` 里的自定义改动）
对各类出站请求的请求头（尤其是 `User-Agent` / `Originator` / 认证头）的处理方式，以及对应的代码模块。

> 目的：作为“基准线”。自定义改动相对本文件的差异全部记录在 [`CHANGES_CUSTOM.md`](./CHANGES_CUSTOM.md)。
> 升级官方版本时，先用本文件核对官方是否改了原版行为，再套 `CHANGES_CUSTOM.md`。

---

## 一、请求分两大类

CPA 的出站请求（发给上游厂商）按用途分两类，走**完全不同**的代码路径：

| 类别 | 触发场景 | 代码入口 | 用途 |
|------|---------|---------|------|
| **A. AI 请求转发** | 客户端（Codex/Claude Code/等）经 CPA 转发真实对话请求 | `internal/runtime/executor/*_executor.go` | 真正的 chat / responses / generateContent |
| **B. 管理面板 api-call** | 管理面板“拉取模型列表”“查询额度”等 | `internal/api/handlers/management/api_tools.go` 的 `APICall` | 辅助查询，前端 → `/v0/management/api-call` → 上游 |

两类的 UA 来源不同，务必分开看。

---

## 二、A 类：AI 请求转发（executor）

### A1. Codex — `internal/runtime/executor/codex_executor.go`

原版对出站 Codex 请求头的处理（`prepareCodexRequest` 一带，约 1613–1667 行）：

- **常量**（约 38 行）：
  ```go
  codexUserAgent  = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"
  codexOriginator = "codex-tui"
  ```
- **两个包装函数走不同子路径（关键，早前版本文档在此以偏概全，现校正）**：
  Codex 出站头由两个包装函数设置，二者最后都调同一个 `applyCodexHeadersFromSources`（真正设头处），
  区别只在**调用前是否删入站 UA**：
  ```go
  // 主转发路径（流式/非流式/count 都走这个）—— 不删入站 UA
  func applyCodexHeaders(r, ...) {
      ginHeaders = ginCtx.Request.Header          // 直接用，未删 UA
      applyCodexHeadersFromSources(r, ..., ginHeaders)
  }
  // 直连图片路径（/images/*）—— 才删入站 UA
  func applyCodexDirectImageHeaders(r, ...) {
      ginHeaders = ginCtx.Request.Header.Clone()
      ginHeaders.Del("User-Agent")                // ← Del 只在这里
      applyCodexHeadersFromSources(r, ..., ginHeaders)
  }
  ```
  注释 `// Downstream client User-Agent values are not forwarded to reduce Cloudflare 1010 blocks.`
  与 `ginHeaders.Del("User-Agent")` **只属于图片子路径**，不是 Codex 转发的通用行为。
  （7.2.77 与 7.2.80 均是这两个包装函数结构，Del 都只在图片路径——非官方改动，是早前文档表述糊了。）
- **UA 按优先级决定**（`applyCodexHeadersFromSources` 内）：
  ```go
  ensureHeaderWithConfigPrecedence(r.Header, ginHeaders, "User-Agent", cfgUserAgent, codexUserAgent)
  ```
  优先级：`target` 已有值则不动 > 配置里的 `cfgUserAgent` > 入站 `ginHeaders` 里的 > 兜底常量 `codexUserAgent`。
  - **主转发路径**：入站 UA 未删 → 若无配置 UA 但客户端带了 UA，会用客户端 UA。
  - **图片路径**：入站 UA 已删 → 优先级中"入站"一档为空 → 配置 UA 或兜底常量。
  （`ensureHeaderWithConfigPrecedence` 定义在 `codex_websockets_executor.go:1147`）
- **认证 / 其它权威头**：
  - `Authorization: Bearer <token>`（约 1631）
  - `Content-Type: application/json`（1630）
  - `Accept`: 流式 `text/event-stream`，否则 `application/json`（1647/1649）
  - `Connection: Keep-Alive`（1651）
  - `Originator`: 入站有则用入站，否则用 `codexOriginator`=`codex-tui`（1659–1662）
  - `Chatgpt-Account-Id`（1667，账号相关）
  - `X-Codex-Beta-Features`（1634，从入站透传）

**原版小结（Codex 转发）**：主转发路径**不删**入站 UA，出站 UA 优先级 = 配置值 > 入站 UA > 兜底
`codex-tui/0.135.0 (Mac OS ...)`；图片直连路径先 `Del` 入站 UA，故其优先级实际 = 配置值 > 兜底。
**注意兜底是 Mac OS 串**。（早前本节把"入站 UA 被 Del"当成 Codex 转发的通用行为，是把图片子路径的行为
以偏概全了，此处已更正。）

### A2. OpenAI 兼容 — `internal/runtime/executor/openai_compat_executor.go`

原版 **4 处**（约 142 / 233 / 341 / 495 行）**统一硬编码**：
```go
httpReq.Header.Set("User-Agent", "cli-proxy-openai-compat")
```
无兜底判断、无透传。凡走 openai 兼容通道的出站请求，UA 一律 `cli-proxy-openai-compat`。

### A3. Claude — `internal/runtime/executor/claude_executor.go`

原版处理（约 1070–1169 行）：
- 认证：`x-api-key: <key>`（1070）或 `Authorization: Bearer <key>`（1072）
- `Content-Type: application/json`（1074）
- `Anthropic-Beta`（1118）、`Connection: keep-alive`（1141）
- `Accept`: 流式 `text/event-stream` + `Accept-Encoding: identity`（1143/1147），否则 `application/json` + `gzip,deflate,br,zstd`（1149/1150）
- UA/包名/运行时指纹：从入站客户端提取（`getClientUserAgent` @1714、`parseEntrypointFromUA` @1722），用于“升级软件指纹”。Claude 路径**会参考入站 UA**，与 Codex 不同。

### A4. Gemini / Vertex — `internal/runtime/executor/gemini_executor.go` / `gemini_vertex_executor.go`

原版主要设认证与内容类型，**不设伪装 UA**：
- Gemini：`x-goog-api-key: <apiKey>`（多处：89/184/293/411/487/641）、`Content-Type: application/json`、`Api-Revision`（807/816）
- Vertex：`x-goog-api-key`（200/495）或 `Authorization: Bearer <token>`（215/367）、`Content-Type`
- 未见 `User-Agent` 显式设置 → 走 Go 默认 `Go-http-client/1.1`（Google 端点通常不因此拒绝）。

---

## 三、B 类：管理面板 api-call — `internal/api/handlers/management/api_tools.go`

**函数 `APICall`**（处理 `POST /v0/management/api-call`）。原版逻辑：

1. 解析 body：`method` / `url` / `header`（map）/ `data` / `auth_index`。
2. `reqHeaders := body.Header`（**只来自 JSON body 的 `header` 字段**，不读 `c.Request.Header`，即与浏览器访问面板的 HTTP 头无关）。
3. 替换 `$TOKEN$` 占位为实际 token。
4. 构造 `http.NewRequestWithContext`，然后遍历 body.header：
   ```go
   for key, value := range reqHeaders {
       req.Header.Set(key, value)   // 约 169 行
   }
   ```
5. **原版没有任何 User-Agent 兜底**。7.2.71 与 7.2.77 官方 `api_tools.go` 中 `User-Agent` 仅出现在注释的 curl 示例里（约 94/105 行），代码路径里**不填 UA**。
6. 因此：若 body.header 未提供 `User-Agent`，`net/http` 自动发 **`Go-http-client/1.1`**。

### 前端（`static/management.html`）如何构造 body.header

前端各功能构造 header 的方式（基于 7.2.77 前端产物实证）：

- **拉取模型列表**（codex）：分发到 `Yp.fetchV1ModelsViaApiCall(baseUrl, apiKey, headerObj, authIndex)`。
  - `headerObj = cp(r)`：`cp`（前端函数，产物约 790671 字节处）**只把用户在 provider 配置页 `headers` 里填的行**转成对象，**不注入任何默认 UA**。
  - `fetchV1ModelsViaApiCall` 只补 `Authorization`，**不加 UA**。
  - → body.header 通常**没有 User-Agent** → 原版后端发 `Go-http-client/1.1`。
  - （gemini 走 `fetchGeminiModelsViaApiCall`、claude 走 `fetchClaudeModelsViaApiCall`、openai 兼容走 `fetchModelsViaApiCall`，模式相同：只补认证头，不注入 UA。）
  - **重要（行为指纹）**：`GET /v1/models` **不是 CPA 独有的动作**。真实 Codex CLI **启动时会硬编码发 `GET /v1/models`** 做 API 可达性探测（`codex doctor` 报 "API reachable / Failed to fetch models"），无法通过配置关闭。据 cc-switch issue [#3812](https://github.com/farion1231/cc-switch/issues/3812) 实测复现（`GET .../v1/models → 404`）。因此面板"拉取模型"打的端点与真实 Codex 一致，在中转/relay 场景下**不构成行为异常**；之前 401 纯粹是 UA（`Go-http-client/1.1`）被拦，与端点是否可疑无关。
    （更正记录：早前曾据 `client.rs` 判断"Codex 不拉 /v1/models"，那只覆盖推理路径 `/responses` 等，漏了 login crate 的启动探测，结论已更正。）
- **额度 / credits 查询**（codex）：走 `hE`（构造 `{...Bh}`）→ `gE`（发 `Fp.request`）。
  - 原版前端常量 `Bh`（产物约 836540 字节处）**硬编码**：
    ```js
    Bh = { Authorization:"Bearer $TOKEN$", "Content-Type":"application/json",
           "User-Agent":"codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal" }
    ```
  - `gE` 在此基础上额外加 `Accept: application/json`、`OpenAI-Beta: codex-1`、`Originator: Codex Desktop`（`Codex Desktop` 是 **Originator 头**，不是 UA）。
  - → 额度查询的 body.header **带 UA** `codex_cli_rs/0.76.0 ...`（原版前端写死）。

> **新版面板结构变化（v7.2.80，2026-07 记录）**：从某个版本起，管理面板 UI 不再作为
> `static/management.html` 编译产物随后端源码提交，而是**运行时**从独立仓库
> `router-for-me/Cli-Proxy-API-Management-Center` 下载、缓存到 `~/.cli-proxy-api/management.html`，
> 且每 3 小时自动更新一次（后端 `internal/managementasset/updater.go`）。因此改动 #6
> 不能再直接改后端仓里的 `static/management.html`（那个文件已不存在，且缓存文件会被自动更新覆盖），
> 必须改到**面板源码仓的 fork**（`Cli-Proxy-API-Management-Center`）里。
>
> 老 `Bh` 常量在面板源码里对应 `src/utils/quota/constants.ts` 的 **`CODEX_REQUEST_HEADERS`**
> （老 `Bh` 的新名字，同样写死 `User-Agent: codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal`）。
> 改动 #6 即把这里的 `User-Agent` 项删掉，让请求落到后端 `api_tools.go` 的 UA 兜底。
>
> **另一处关键差异（Originator 分流不再一致）**：新版面板把 Codex 额度这块**拆成了 3 个请求**，
> 都共用 `CODEX_REQUEST_HEADERS`（见 `src/components/quota/quotaConfigs.ts` 的 `buildCodexRequestHeader`）：
>
> | 请求 | URL | 是否带 `Originator: Codex Desktop` | 删 UA 后后端兜底给的 UA |
> |------|-----|:---:|:---:|
> | usage（主额度/用量查询） | `.../wham/usage` | ❌ 否 | **CLI UA**（`codex_cli_rs`） |
> | reset-credits（重置额度明细） | `.../wham/rate-limit-reset-credits` | ✅ 是 | **Desktop UA** |
> | consume（消费重置额度） | `.../rate-limit-reset-credits/consume` | ❌ 否 | **CLI UA**（`codex_cli_rs`） |
>
> 也就是说：老版本里"额度查询"是单个函数、带 `Originator: Codex Desktop`，删 UA 后统一拿 **Desktop UA**；
> 新版拆成 3 个后，只有 reset-credits 带 Desktop Originator，主查询 usage 和 consume 都**不带**，
> 因而删 UA 后走后端按 Originator 分流会拿到 **CLI UA**，与老版本"额度走 Desktop"的意图不再完全一致。
>
> **本次取舍（选 B：保持最小改动，不补 Originator）**：仅删掉 `CODEX_REQUEST_HEADERS` 里的 `User-Agent`，
> 不给 usage/consume 补 `Originator: Codex Desktop`。结果 reset-credits 走 Desktop UA、usage/consume 走 CLI UA
> （混着来）。两者都是真实 Codex 客户端 UA，上游都认，功能不受影响，只是伪装身份不统一。
> 已在 `quotaConfigs.ts` 的 usage、consume 两处 `buildCodexRequestHeader` 调用点加了说明注释。
>
> 关于 usage 为何不带 Desktop Originator：这是新版面板作者的写法，我没深究他的意图。真实的 Codex Desktop
> 应用查用量时到底带不带这个头，我没有实证（老版本的 `HEADERS_VANILLA.md` 记录的是老版本前端的行为，
> 新版拆成 3 个请求是新的结构）。如果想"最大程度贴近真实 Desktop 行为"，可能值得先抓一次真实 Codex Desktop
> 的额度请求看它的头再定。

### 其它 provider 前端 base header（原版硬编码）

- **Grok** `Gh`：`user-agent: grok-pager/0.2.91 grok-shell/0.2.91 (macos; aarch64)` + `x-xai-token-auth: xai-grok-cli` + `x-grok-client-version: 0.2.91` + `accept: */*`
- **Claude/antigravity** `Mh`：`User-Agent: antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)`（运行时由 `kh=1.0.13`/`Ah=aidev_client`/`jh={darwin,arm64}` 拼装）

---

## 四、一句话总览（原版）

| 路径 | 出站 UA（原版） | 模块 |
|------|----------------|------|
| Codex 转发（主路径） | 配置值 > 入站 UA > 兜底 `codex-tui/0.135.0 (Mac OS ...)`；入站 UA **不** Del | `codex_executor.go`·`applyCodexHeaders` |
| Codex 转发（图片 `/images/*`） | 配置值 >（入站已 Del，空）> 兜底同上 | `codex_executor.go`·`applyCodexDirectImageHeaders` |
| OpenAI 兼容转发 | 硬编码 `cli-proxy-openai-compat`（4 处） | `openai_compat_executor.go` |
| Claude 转发 | 参考入站 UA + 指纹升级 | `claude_executor.go` |
| Gemini/Vertex 转发 | 不设 UA → `Go-http-client/1.1` | `gemini_executor.go` / `gemini_vertex_executor.go` |
| 面板·拉模型 | body.header 无 UA → `Go-http-client/1.1` | `api_tools.go` + 前端 `fetchV1ModelsViaApiCall`/`cp` |
| 面板·查额度(codex) | 前端 `Bh` 写死 `codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal` | `api_tools.go` + 前端 `Bh`/`hE`/`gE` |
| 面板·查额度(grok) | 前端 `Gh` 写死 `grok-pager/... grok-shell/... (macos; aarch64)` | 前端 `Gh` |
| 面板·查额度(claude) | 前端 `Mh` 写死 `antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)` | 前端 `Mh` |

**关键结论**：原版“面板·拉模型”这条路径**不带 UA**，出站是 `Go-http-client/1.1` —— 这正是上游 ChatGPT / relay 返回 `401 unauthorized client detected` 的原因（该错误串在 CPA 代码库里搜不到，来自上游）。自定义改动通过在 `api_tools.go` 加 UA 兜底修复了这一点，详见 `CHANGES_CUSTOM.md`。

> 注意：`GET /v1/models` 这个**端点本身**不可疑——真实 Codex CLI 启动时也会发（见上文"拉取模型"条目的行为指纹说明）。问题只在原版没带像样的 UA。

---

## 五、真实 Codex CLI 的 User-Agent 格式（权威来源：openai/codex 源码）

供参考：若想把面板拉取请求的 UA 改成"真正的 Codex CLI 格式"，以下是官方构造逻辑。

**构造代码**：`codex-rs/login/src/auth/default_client.rs` 的 `get_codex_user_agent()`。

**格式**：
```
{originator}/{build_version} ({os_type} {os_version}; {arch}) {terminal}
```
- `originator`：默认常量 `DEFAULT_ORIGINATOR = "codex_cli_rs"`（可被环境变量 `CODEX_INTERNAL_ORIGINATOR_OVERRIDE` 或 `set_default_originator()` 覆盖）。
- `build_version`：`env!("CARGO_PKG_VERSION")`，即 Codex CLI 的版本号（如 `0.76.0`）。
- `os_type` / `os_version` / `arch`：由 `os_info` crate 探测。**关键：`os_type()` 对 Windows 只返回裸字符串 `"Windows"`，不带 "11"/"10"**（"Windows 11" 这类展示名是 `os_info` 的 `edition()` 方法产物，UA 根本不调用它）；`version()` 返回 build 号（如 `10.0.26200`）；`architecture()` 取不到则 `unknown`。故 Windows 上 os 段固定形如 `Windows 10.0.26200`。
- `terminal`：由 `codex-terminal-detection` 的 `user_agent()` 生成。**并非只读 `TERM_PROGRAM`**，而是按优先级探测多个环境变量（详见下方"终端段探测规则"），全都命中不到才返回 `unknown`。
- 可选后缀：若设置了 `USER_AGENT_SUFFIX`，追加 ` ({suffix})`。
- 最后经 `sanitize_user_agent()` 把非法 header 字符替换为 `_`。

**真实样例**（不同平台/终端各异）：
- macOS + iTerm：`codex_cli_rs/0.76.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10`
- Linux 无已知终端：`codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) unknown`
- Windows + Windows Terminal（设 `WT_SESSION`）：`codex_cli_rs/0.76.0 (Windows 10.0.26200; x86_64) WindowsTerminal`
- Windows + cmd/PowerShell 老窗口（无 `WT_SESSION`、无 `TERM_PROGRAM`）：`codex_cli_rs/0.76.0 (Windows 10.0.26200; x86_64) unknown`

> 对比几个已知伪装串：
> - 原版前端 `Bh`（额度查询）：`codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal` —— **格式完全标准**：`codex_cli_rs` originator + 末尾 `WindowsTerminal`（`WT_SESSION` 命中、无版本号，见终端段规则）。os 段是 `Debian` 说明这是在 **Windows Terminal 里跑 WSL Debian** 抓到的真实 codex UA（`WT_SESSION` 从宿主 Windows Terminal 继承进 WSL）。（早前文档误判此串"不标准"，此处更正。）
> - 原版 codex_executor 兜底：`codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)` —— 用的是 `codex-tui`（Codex 的 TUI originator），末尾带 `(codex-tui; 0.135.0)` 后缀。这是 **旧版本** 的形态，见下方版本变迁说明。
> - 自定义改动的本地探测 UA：`Codex Desktop/<...> (Windows <...>; x86_64) unknown (Codex Desktop; <...>)` —— 模拟的是 **Codex Desktop 应用**，不是 CLI。

### originator 版本变迁：`codex-tui` → `codex_cli_rs`（实证）

有说法称"codex 升级后 UA 从 codex-cli 变成 codex-tui"。经本机二进制实证，**方向相反且已过时**：早期版本（约 0.135.0，CPA 作者当时观察到并写进 `codex_executor.go` 兜底）交互式命令确实用过 `codex-tui` 作 originator/UA 前缀；而 **当前版本已统一回 `codex_cli_rs`**。

**实证来源**：本机 Codex Desktop 捆绑的 `codex.exe`（`%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe`，自报 `codex-cli 0.144.2`）二进制字符串：
- 含 `codex_cli_rs` 且紧邻 `login\src\auth\default_client.rs:103`（即 `originator()` 函数）与 `Unable to turn originator override` —— 证明 `DEFAULT_ORIGINATOR = "codex_cli_rs"` 就是当前默认。
- 含 `codex_exec` + `Failed to set codex exec originator override` —— 证明只有 `codex exec` 子命令会 override 成 `codex_exec`。
- `codex-tui` 在 0.144.2 里**不再是 HTTP UA 前缀**，只作三种用途：① `is_first_party_originator()` 白名单成员（源码 130-133 行：`codex_cli_rs || codex-tui || codex_vscode || starts_with("Codex ")`）② OTEL 服务名枚举 ③ 日志文件名 `codex-tui.log`。

**openai/codex 当前 main 源码交叉验证**：交互式 TUI 入口（`tui/src/lib.rs`、`tui/src/main.rs`、`cli/src/main.rs`、`arg0/src/lib.rs`）均**不调用** `set_default_originator`，故主 `codex` 命令走默认 `codex_cli_rs`。唯一 override 点是 `exec/src/lib.rs:246` 把 originator 设为 `codex_exec`。

**各 originator 与真实命令对应**：

| 命令 | originator | UA 前缀示例 |
|------|-----------|-------------|
| `codex`（交互 TUI，主命令） | `codex_cli_rs`（默认，不 override） | `codex_cli_rs/0.144.2 (...)` |
| `codex exec`（非交互） | `codex_exec`（override） | `codex_exec/0.144.2 (...)` |
| Codex VSCode 扩展 | `codex_vscode` | `codex_vscode/... (...)` |
| Codex Desktop 应用 | `codex_desktop` / `Codex Desktop` 系 | （桌面应用自身，非 CLI） |

### 本机（0.144.2 / Windows build 26200）真实 CLI UA

基于以上实证，本机真实 `codex` 交互命令发出的 UA 为（终端段取决于用哪个终端启动，见下方规则）：
```
codex_cli_rs/0.144.2 (Windows 10.0.26200; x86_64) unknown
```
- `codex_cli_rs` —— 二进制确认的 default originator（**非** `codex-tui`）
- `0.144.2` —— 捆绑 `codex.exe --version` 实测
- `Windows 10.0.26200` —— `os_info`：`os_type()`=`Windows`（**不带 "11"**）+ `version()`=build `10.0.26200`。已与 CPA 后台实测日志核对一致（Desktop 那条 `Codex Desktop/0.144.2 (Windows 10.0.26200; ...)` 的 os 段同样不带 "11"）。CLI 与 Desktop 同用一套 codex-rs + os_info，os 段规则完全相同。
- `x86_64` —— GOARCH=amd64 映射
- `unknown` —— 若在 Windows Terminal 里启动则为 `WindowsTerminal`；cmd/PowerShell 老窗口或后台进程（探不到 `WT_SESSION`）则为 `unknown`

### 终端段探测规则（`codex-terminal-detection` 权威源码 + 本机二进制实证）

`user_agent()` → `detect_terminal_info_from_env()` 按以下**优先级顺序**探测（命中即止）：

1. `TERM_PROGRAM` 非空 → 用它（如 `vscode`/`iTerm.app`/`tmux`）。**优先级最高，会遮蔽后面所有探测**，含 `WT_SESSION`。
2. `WEZTERM_VERSION` → WezTerm
3. `ITERM_SESSION_ID` / `ITERM_PROFILE` / `ITERM_PROFILE_NAME` → iTerm2
4. `TERM_SESSION_ID` → Apple Terminal
5. `KITTY_WINDOW_ID` / `ALACRITTY_SOCKET` / `KONSOLE_VERSION` / `GNOME_TERMINAL_SCREEN` / `VTE_VERSION` → 对应终端
6. **`WT_SESSION` → `WindowsTerminal`**（纯字符串，**无版本号、无斜杠**，不同于 `vscode/1.x`）
7. `TERM` 非空 → 原样返回（如 `xterm-256color`）
8. 全不命中 → `unknown`

**关键结论**：
- Windows Terminal（Win11 自带的现代终端）**是靠 `WT_SESSION` 识别，不是 `TERM_PROGRAM`**。在 WT 里跑 codex → 终端段 `WindowsTerminal`。
- 但若在 **VSCode 集成终端**跑（哪怕宿主是 WT），`TERM_PROGRAM=vscode` 先命中 → 终端段 `vscode/<版本>`，不是 WindowsTerminal。
- cmd/PowerShell 传统 conhost 窗口不设 `WT_SESSION`；若也没设 `TERM` → `unknown`。
- **CPA 代理若以后台/服务方式运行，进程环境里没有 `WT_SESSION`，永远探不到终端 → 只能是 `unknown`**。故伪装 UA 的终端段不能靠"自动探测"，需按真实使用场景写死。
- 本机当前 shell 实测：`TERM_PROGRAM`/`WT_SESSION` 均未设，`TERM=xterm-256color`。

**若要把面板拉取/额度请求 UA 改成 CLI 格式**（区别于现有 Desktop 格式），目标即上面这条：
`codex_cli_rs/<CLI版本> (Windows <Win版本>; x86_64) unknown`
（现有探测模块 `misc.codex_local_ua.go` 已能拿到 CLI 版本与 Win 版本；只需把拼装模板从 Desktop 格式换成 CLI 格式。改动记录见 `CHANGES_CUSTOM.md`。）

### 探测失败时版本号取什么（`codex_local_ua.go` 逻辑）

`buildLocalCodexUserAgent()` 是**全有或全无**：CLI 版本 / app 版本 / Win 版本三者任一探测失败（返回 `""`），
整个 build 立即返回空，`LocalCodexUserAgent()` 随即用**整条** `LocalCodexUAFallback` 常量顶替：
```
Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)
```
- 即：探测失败时版本号**不是"只补一个默认版本"**，而是整条 UA 换成 fallback，其中 CLI 版本位是**硬编码的 `0.144.2`**、app 版本位是 `26.707.72221`。
- 各组件探测来源：CLI 版本 = `codex.exe --version`（先找 `%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe`，再找 PATH）；app 版本 = `~/.codex/config.toml` 的 `BROWSER_USE_CODEX_APP_VERSION`；Win 版本 = 注册表 build 号。
- 本机实测（2026-07）：三项均成功（`0.144.2` / `26.707.72221` / `26200`），故走**真探测**，产出串恰好与 fallback 常量一字不差（当初 fallback 即照本机写死）。
- 隐患：若日后 codex 升级但 config.toml 仍缺 `BROWSER_USE_CODEX_APP_VERSION`，会整条回落到写死的旧 `0.144.2`，UA 版本会滞后于真实版本。改成 CLI 格式后同理，需注意 fallback 常量也要同步更新格式。
