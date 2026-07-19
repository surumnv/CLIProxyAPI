# 自定义改动记录 (基于 CLIProxyAPI 7.2.77)

本文件记录相对官方 7.2.77 版本的所有自定义改动，用于在后续升级到新版本时重新套用同样的修改。

**改动主题**：让代理发出的上游请求尽量“伪装”成真实的本地 Codex (ChatGPT) 客户端，
避免上游 relay / WAF 因为 `Go-http-client/1.1` 或 `cli-proxy-openai-compat` 这类明显非客户端的
User-Agent、或缺少客户端头部而拒绝请求。核心手段：

1. 新增本地 Codex UA 探测模块，产出**两种** UA，取值方法尽量对齐 openai/codex 源码：
   - **Codex Desktop UA**（`Codex Desktop/... unknown (Codex Desktop; <app-version>)`）：
     用于桌面版自身会发的请求（如额度/用量查询，前端标 `Originator: Codex Desktop`）。
   - **Codex CLI UA**（`codex_cli_rs/... WindowsTerminal`）：用于只有 CLI 会发的请求
     （如 provider `/v1/models` 可达性探测，即管理面板“拉取模型”）。
2. 新增 `CopyInboundHeaders` 工具，把入站客户端头部透传到出站上游请求。
3. 在多个 executor / management 调用点接入上述能力；管理面板 api-call 按出站
   `Originator` 头分流：含 “Desktop” → Desktop UA，否则 → CLI UA。
4. 新增一个管理端点用于刷新缓存的 UA（现同时返回 Desktop 与 CLI 两条）。

**取值方法对齐说明**：os 版本用 `RtlGetVersion`（os_info crate 在 Windows 上用的正是这个 NT API，
产出 `major.minor.build`），arch 映射到 os_info 词汇（amd64→`x86_64`, arm64→`aarch64`,
386→`i386`）。Desktop 因非开源，与 CLI 同名的字段（os 版本、arch、CLI 版本）取值方法与 CLI 源码保持一致，
仅 app-version 段为 Desktop 专有（读 config.toml）。

**依赖说明**：用到 `golang.org/x/sys/windows`（`RtlGetVersion`），该依赖官方已在 `go.mod` 中
（`golang.org/x/sys v0.38.0`），无需改动 `go.mod` / `go.sum`。

---

## 追加改动：Claude Desktop 启动探测本地短路

### 修改文件

- `internal/api/server.go`
- `internal/api/server_test.go`
- `sdk/api/handlers/claude/code_handlers.go`
- `sdk/api/handlers/claude/code_handlers_model_test.go`

### 背景

Claude Desktop 启动时会向 `/v1/messages` 发一个极小的可用性探测请求。该请求使用 Electron/浏览器风格
User-Agent，而不是后续真实调用使用的 `claude-cli` User-Agent。部分上游中转站会把浏览器风格 UA 视为
非 Claude CLI 客户端请求并拒绝，导致 Claude Desktop 误判供应商不可用。

Claude Desktop 还会向 base URL 发 `HEAD /` 可达性探测，请求头里可能只有 `User-Agent: Bun/...`，没有
`Anthropic-Version` 或鉴权信息。CPA 原先只注册了 `GET /`，所以 `HEAD /` 会返回 404。该请求不是模型调用，
只需要证明 CPA 根地址可达。

### 实现

在 `ClaudeMessages` 读取并完成模型 ID 解码后、进入流式/非流式转发分支前，新增一个很窄的
Claude Desktop 启动探测识别逻辑。只有同时满足以下条件时才本地返回成功：

- `POST /v1/messages`
- 存在 `Anthropic-Version`
- `User-Agent` 同时包含 `Claude/` 和 `Electron/`
- `User-Agent` 不包含 `claude-cli`
- `model` 以 `claude-` 开头
- `max_tokens` 等于 `1`
- `messages` 只有一条
- 唯一消息为 `role=user` 且 `content="."`
- `stream` 不存在或为 `false`
- 不存在 `tools`
- 不存在 `system`

命中后返回标准 Anthropic Messages 非流式 `Message` 对象，避免进入模型路由和上游转发：

```json
{
  "id": "msg_01CPAClaudeDesktopProbe",
  "type": "message",
  "role": "assistant",
  "model": "<request model>",
  "content": [{"type": "text", "text": "."}],
  "stop_reason": "max_tokens",
  "stop_sequence": null,
  "stop_details": null,
  "usage": {"input_tokens": 1, "output_tokens": 1}
}
```

### 边界

- 后续真实 Claude 调用的 `claude-cli` User-Agent 不会命中该逻辑。
- 普通对话请求因为 `max_tokens`、消息内容、消息数量或工具/系统字段不同，不会命中该逻辑。
- 本地成功只表示 CPA 放过 Claude Desktop 启动探测，不代表上游模型、额度或密钥真实可用；真实可用性仍由后续真实请求验证。
- `HEAD /` 只返回 `200 OK` 空响应；`GET /` 保持原有 JSON 根信息不变。

---

## 一、新增文件（3 个）

全部位于 `internal/misc/`。升级时直接把这三个文件复制过去即可（内容一般不受官方升级影响）。

### 1. `internal/misc/codex_local_ua.go`
本地 Codex UA 探测的主逻辑，`package misc`。**产出两种 UA**（对应两种真实 Codex 客户端）：

- **Desktop UA**（Codex 桌面应用发出的请求，如额度/用量查询）：
  `Codex Desktop/<cli-version> (Windows <win-version>; <arch>) unknown (Codex Desktop; <app-version>)`
  终端段固定 `unknown`（桌面应用是后台 GUI 进程，无 `TERM_PROGRAM`/`WT_SESSION`）。
- **CLI UA**（仅 Codex CLI 发出的请求，如 provider `/v1/models` 可达性探测 = 面板拉模型）：
  `codex_cli_rs/<cli-version> (Windows <win-version>; <arch>) WindowsTerminal`
  终端段固定 `WindowsTerminal`（模拟从 Windows Terminal 启动的 CLI；代理是后台进程无法自探终端，故写死）。

导出函数与常量：
- `LocalCodexUserAgent() string`：返回 Desktop UA，进程内缓存、加锁，空则用 `LocalCodexUAFallback`。
- `LocalCodexCLIUserAgent() string`：返回 CLI UA，独立缓存，空则用 `LocalCodexCLIUAFallback`。
- 常量 `LocalCodexUAFallback`：`Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)`
- 常量 `LocalCodexCLIUAFallback`：`codex_cli_rs/0.144.2 (Windows 10.0.26200; x86_64) WindowsTerminal`
- `RefreshLocalCodexUserAgents() (desktop, cli string)`：清两个缓存并重探，返回两值。
- `RefreshLocalCodexUserAgent() string`：向后兼容旧端点，内部调上者、返回 Desktop 值（同时也刷新了 CLI 缓存）。

组件探测函数（**取值方法尽量对齐 openai/codex 源码**）：
- `buildLocalCodexDesktopUserAgent()` / `buildLocalCodexCLIUserAgent()`：分别组装两种 UA；任一必需组件缺失返回空触发 fallback。CLI 版**不需要** app-version（不依赖 config.toml）。
- `detectCodexCLIVersion()`：运行 `codex --version` 正则解析；5s 超时。
- `locateCodexExecutable()`：优先 `%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe`，否则走 PATH。
- `detectCodexDesktopAppVersion()`：从 `~/.codex/config.toml` 逐行扫描 `BROWSER_USE_CODEX_APP_VERSION`（仅 Desktop UA 用）。
- `codexConfigTomlPath()`：优先 `CODEX_HOME`，否则 `~/.codex/config.toml`。
- `codexUAArch()`：**对齐 os_info 词汇**（amd64→`x86_64`, arm64→`aarch64`, 386→`i386`, arm→`arm`）。
  > 注意：arm64 是 `aarch64` 不是 `arm64`（os_info 用 `GetNativeSystemInfo` 的 `PROCESSOR_ARCHITECTURE_ARM64` 映射）。

### 2. `internal/misc/codex_local_ua_windows.go`
`//go:build windows`。实现 `detectWindowsVersion()`：调用 `RtlGetVersion`（NT API，
`golang.org/x/sys/windows` 已封装 `windows.RtlGetVersion()`），读取 `MajorVersion` /
`MinorVersion` / `BuildNumber` 三个数值字段，格式化为如 `10.0.26200`。

> **为什么用 `RtlGetVersion` 而不是读注册表**：Codex（CLI 与 Desktop 同源 codex-rs）的
> os 版本来自 `os_info` crate，而 `os_info` 在 Windows 上正是调 `RtlGetVersion` 取
> `major.minor.build`。为让伪装 UA 的取值方法与 Codex 源码一致，改用同一 API。
> 依赖 `golang.org/x/sys/windows`（`v0.38.0` 已含 `RtlGetVersion`，无需改 go.mod）。

### 3. `internal/misc/codex_local_ua_other.go`
`//go:build !windows`。`detectWindowsVersion()` 返回空（非 Windows 平台 UA 探测故意失败，走 fallback）。

---

## 二、修改文件（4 个）

### 1. `internal/util/header_helpers.go`
新增 `CopyInboundHeaders` 及其黑名单（在 `applyRequestHeaders`/`ApplyRequestHeaders` 之后插入）。

- 新增包级变量 `passthroughHeaderDenylist`（不可透传的头）：
  `Content-Length, Host, Connection, Proxy-Connection, Keep-Alive, Transfer-Encoding, Te, Trailer, Upgrade, Accept-Encoding`
- 新增函数：
  ```go
  func CopyInboundHeaders(r *http.Request, src http.Header, skip ...string)
  ```
  把 `src`（入站头）拷到出站请求 `r`，跳过黑名单和 `skip` 里的头；`r` 上已有值的头不覆盖；空值跳过。

> 注意：确保文件已 import `net/http` 和 `strings`（官方原文件已有）。

### 2. `internal/runtime/executor/codex_executor.go`
在设置完权威头部之后、构造 `attrs` 之前，加一行透传入站头：

```go
	// Preserve every remaining inbound Codex header verbatim (e.g. Session-Id,
	// Thread-Id, X-Codex-Window-Id, X-Codex-Turn-Metadata). Authoritative headers
	// set above are already present and will not be overwritten; hop-by-hop and
	// length/host headers are dropped by CopyInboundHeaders itself.
	util.CopyInboundHeaders(r, ginHeaders)
	var attrs map[string]string
```

（原代码此处紧接 `var attrs map[string]string` / `if auth != nil {`。变量名 `r` 为出站请求、
`ginHeaders` 为入站头，按当前版本实际变量名对应。）

### 3. `internal/runtime/executor/openai_compat_executor.go`
共有 **4 处** 相同模式的改动。每处把原来的：

```go
	httpReq.Header.Set("User-Agent", "cli-proxy-openai-compat")
```

替换为：

```go
	// Preserve inbound client headers (User-Agent, X-Codex-*, Session-Id, ...)
	// so the upstream sees a request that looks like the original client. The
	// authoritative Content-Type/Authorization set above are kept as-is;
	// Authorization intentionally carries the compat provider key rather than the
	// inbound token, and hop-by-hop/length headers are dropped by the copier.
	util.CopyInboundHeaders(httpReq, opts.Headers)
	if strings.TrimSpace(httpReq.Header.Get("User-Agent")) == "" {
		httpReq.Header.Set("User-Agent", "cli-proxy-openai-compat")
	}
```

> 4 处分别在不同的请求构造函数里（流式/非流式等）。升级后用
> `grep -n 'cli-proxy-openai-compat' openai_compat_executor.go` 找到所有点逐一替换。
> 确保 import 了 `strings`（官方原文件通常已有）。
>
> **注意（改动主题四）**：其中 2 处（`Execute` 与 `ExecuteStream` 的 chat 路径）的
> `CopyInboundHeaders` 调用现在带 skip 参数，用于在 Responses→Chat 转换时剥离
> Codex Responses-Lite 头，详见文末「改动主题四」。套用本节时按主题四的最终形态写。

### 4. `internal/api/handlers/management/api_tools.go`
三处改动：

**(a)** import 增加：
```go
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
```

**(b)** 在 `const defaultAPICallTimeout = 60 * time.Second` 之后新增默认 UA 辅助函数。
**注意本次改动**：它现在接收 `originator` 参数，按出站 `Originator` 头分流两个真实 Codex 客户端 UA：
```go
// defaultAPICallUserAgent 按请求的 Originator 选择伪装哪个真实 Codex 客户端：
//   - Originator 含 "desktop"（额度/rate-limit 查询，前端 gE 显式标 "Codex Desktop"）
//     → Desktop UA（misc.LocalCodexUserAgent）
//   - 其余（拉模型 = provider /v1/models 可达性探测，是 CLI 行为）
//     → CLI UA（misc.LocalCodexCLIUserAgent，终端段 WindowsTerminal）
func defaultAPICallUserAgent(originator string) string {
	if strings.Contains(strings.ToLower(originator), "desktop") {
		return misc.LocalCodexUserAgent()
	}
	return misc.LocalCodexCLIUserAgent()
}
```

**(c)** 在构造 API-call 请求、设置 `req.Host` 之后，补默认 UA（把出站 `Originator` 传进分流函数）：
```go
	// 调用方没给 UA 时补一个真实客户端 UA（否则 net/http 发 "Go-http-client/1.1"，
	// 会被部分 relay/WAF 拒绝）。伪装成 Desktop 还是 CLI 取决于 Originator：
	// 额度查询走 Desktop UA；拉模型（/v1/models 探测）走 CLI UA。
	if strings.TrimSpace(req.Header.Get("User-Agent")) == "" {
		req.Header.Set("User-Agent", defaultAPICallUserAgent(req.Header.Get("Originator")))
	}
```

**(d)** 新增管理端点 handler（在 `APICall` 相关代码之后）。**本次改动**：改为返回 Desktop + CLI 两个 UA：
```go
// RefreshAPICallUserAgent 清空缓存并重新探测两个本地 Codex UA。
// Endpoint: POST /v0/management/api-call/refresh-user-agent
func (h *Handler) RefreshAPICallUserAgent(c *gin.Context) {
	desktop, cli := misc.RefreshLocalCodexUserAgents()
	c.JSON(http.StatusOK, gin.H{"desktop_user_agent": desktop, "cli_user_agent": cli})
}
```

### 5. `internal/api/server.go`
在注册 `mgmt.POST("/api-call", s.mgmt.APICall)` 之后新增一行路由：

```go
		mgmt.POST("/api-call", s.mgmt.APICall)
		mgmt.POST("/api-call/refresh-user-agent", s.mgmt.RefreshAPICallUserAgent)
```

### 6. 管理面板前端（**架构已变**：不再是 `static/management.html`）

> **重大变化（7.2.80 起）**：官方已把管理面板从「随源码打包的 `static/management.html`
> 编译产物」改成「运行时从独立仓库下载、每 3 小时自动更新、缓存在
> `~/.cli-proxy-api/management.html` 的外部资源」（见 `internal/managementasset/updater.go`）。
> 因此**旧做法（直接改 `static/management.html` 里的 `Bh` 常量）已失效**：源码树里没有这个文件，
> 就算手改缓存文件也会在 3 小时内被自动更新覆盖。
>
> 正确做法：**改前端源码仓库**。已 fork 面板到
> `https://github.com/surumnv/Cli-Proxy-API-Management-Center`（本地 `D:\AIProject\Cli-Proxy-API-Management-Center`），
> 在源码里做等价改动，然后自己构建发布，让后端从自己的 fork 拉取
> （配置 `remote-management.panel-github-repository` 指向自己的 fork）。

**背景**：老版本前端硬编码 base header 常量 `Bh`（里面写死假 UA
`codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal`）。新面板里它改名叫
`CODEX_REQUEST_HEADERS`，位于 `src/utils/quota/constants.ts`。删掉其中的 `User-Agent` 行后，
出站 body.header 不再带 UA，正好落到 `api_tools.go` 的后端兜底逻辑（第 4 节 c 点）。

**结构变化（重要）**：老版本"额度查询"是**单个**前端函数（带 `Originator: Codex Desktop`）。
新面板把 Codex 额度**拆成 3 个请求**，共用 `CODEX_REQUEST_HEADERS`
（组装函数 `buildCodexRequestHeader`，见 `src/components/quota/quotaConfigs.ts`）：

| 请求 | URL | 是否带 `Originator: Codex Desktop` | 删 UA 后后端兜底给的 UA |
|------|-----|:---:|:---:|
| usage（主额度查询） | `.../wham/usage` | ❌ | **CLI UA** |
| reset-credits | `.../wham/rate-limit-reset-credits` | ✅（该调用点显式加） | **Desktop UA** |
| consume | `.../rate-limit-reset-credits/consume` | ❌ | **CLI UA** |

**本次决定（选 B / 最小改动）**：只删 `CODEX_REQUEST_HEADERS` 里的 `User-Agent` 行，**不**给
usage/consume 补 `Originator: Codex Desktop`。因此这两条走 CLI UA、reset-credits 走 Desktop UA
（混合）。理由：两种 UA 都是真实 Codex 客户端串，上游都认，功能不受影响；是否要统一成 Desktop
留待后续按真实抓包再定（详见 `HEADERS_VANILLA.md` 第三节的说明块）。

**已做的源码改动**（在 fork 仓库 `Cli-Proxy-API-Management-Center` 中）：
1. `src/utils/quota/constants.ts`：删除 `CODEX_REQUEST_HEADERS` 里的 `'User-Agent': ...` 行，并加注释说明原因。
2. `src/components/quota/quotaConfigs.ts`：在 usage 与 consume 两个调用点各加一段注释，说明
   它们**没有**显式 `Originator: Codex Desktop`（是新面板作者的写法，未深究其意图，也未实证真实
   Desktop 是否带此头），故走 CLI UA；如想统一成 Desktop 需在此补 `Originator`。

改前：
```ts
export const CODEX_REQUEST_HEADERS = {
  Authorization: 'Bearer $TOKEN$',
  'Content-Type': 'application/json',
  'User-Agent': 'codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal',
};
```
改后：
```ts
export const CODEX_REQUEST_HEADERS = {
  Authorization: 'Bearer $TOKEN$',
  'Content-Type': 'application/json',
};
```

> **重要提醒**：
> - 这是**独立仓库**的改动，不在 CLIProxyAPI 主仓库里。升级主仓库时不需要动它；升级面板
>   （rebase 自己的 fork 到官方 `upstream/main`）时才需要重新套用。
> - 由于面板会被后端自动更新覆盖缓存，务必让后端指向**自己 fork 的发布版**，否则会拉回官方原版
>   （带写死的假 UA）。
> - 影响范围：**只影响"额度查询"路径**。管理面板"拉取模型"走 `fetchV1ModelsViaApiCall`，
>   本来就不带前端 UA，一直靠 `api_tools.go` 兜底，与本改动无关。
> - 此 UA 只服务额度查询，不影响真正的 AI 请求转发（那条走 executor，见第 2/3 节）。

---

## 三、升级套用步骤（速查）

1. 解压新版本官方源码。
2. 复制 3 个新文件到 `internal/misc/`（见第一节）。
3. `header_helpers.go`：追加 `passthroughHeaderDenylist` + `CopyInboundHeaders`。
4. `codex_executor.go`：在权威头部设置后加 `util.CopyInboundHeaders(r, ginHeaders)`。
5. `openai_compat_executor.go`：`grep 'cli-proxy-openai-compat'`，4 处逐一替换为透传+兜底模式。
6. `api_tools.go`：加 misc import、`defaultAPICallUserAgent()`、req 默认 UA、`RefreshAPICallUserAgent` handler。
7. `server.go`：加 `refresh-user-agent` 路由。
8. 管理面板前端（**已改为独立仓库**）：在 fork 的 `Cli-Proxy-API-Management-Center` 里删
   `src/utils/quota/constants.ts` 的 `CODEX_REQUEST_HEADERS` 中 `User-Agent` 行（见第二节第 6 项）。
   这一步与主仓库升级解耦：升级主仓库时不用动它，只在 rebase 自己的面板 fork 时重做。
9. 编译验证：`go build ./...`（Windows 上验证 registry 分支）。
10. 变量名/函数签名如与新版本不同（如 `ginHeaders`、`opts.Headers`、`req`/`httpReq`），按新版本实际名字对应。

## 四、涉及文件清单

新增：
- `internal/misc/codex_local_ua.go`
- `internal/misc/codex_local_ua_windows.go`
- `internal/misc/codex_local_ua_other.go`

修改（本仓库 CLIProxyAPI）：
- `internal/util/header_helpers.go`
- `internal/runtime/executor/codex_executor.go`
- `internal/runtime/executor/openai_compat_executor.go`
- `internal/api/handlers/management/api_tools.go`
- `internal/api/server.go`

修改（独立面板仓库 `Cli-Proxy-API-Management-Center`，见第二节第 6 项）：
- `src/utils/quota/constants.ts`（删 `CODEX_REQUEST_HEADERS` 的 `User-Agent` 行）
- `src/components/quota/quotaConfigs.ts`（usage/consume 两处加说明注释）

无需改动：`go.mod` / `go.sum`（`golang.org/x/sys v0.38.0` 已存在）。

> 原版（vanilla）各类请求的请求头处理方式（未套用本文件改动的基线行为）见同目录
> `HEADERS_VANILLA.md`，与本文件配合阅读可快速判断某处 UA/头部到底是官方原有还是自定义加的。

---

## 五、本地构建（注入版本号/构建时间）

**问题**：直接 `go build ./cmd/server/` 出来的二进制，面板顶部显示版本 `dev`、构建时间 `未知`。

**原因**：`internal/buildinfo/buildinfo.go` 里 `Version`/`Commit`/`BuildDate` 的默认值就是
`"dev"`/`"none"`/`"unknown"`。官方 release 是在 CI（`.github/workflows/release.yaml`）里用
`-ldflags -X` 注入的，注入目标是 **`main.Version`**（不是 `buildinfo.Version`）——因为
`cmd/server/main.go` 里有 package 级变量 `Version`/`Commit`/`BuildDate`，在 `init()` 里再拷进
`buildinfo`。本地手动 build 不传 ldflags 就只能显示默认值。

**正确 build 命令**（Git Bash）：
```bash
cd /d/AIProject/CLIProxyAPI
VERSION="7.2.80-custom"                          # 随意，标记这是自己的改版
COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build \
  -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
  -o cli-proxy-api.exe ./cmd/server/
```
- 关键是三个 `-X main.xx=...`；`-s -w` 只是去符号表减小体积，可留可去。
- `main.Version`、`main.Commit`、`main.BuildDate` 三个名字必须与 `cmd/server/main.go` 的 package
  级变量一致（注入 `main.` 前缀，不是 `buildinfo.`）。

> **后端不会自我更新**：CLIProxyAPI 没有后端自动升级机制，build 出来的 exe 就是固定的，除非自己
> 重新 build。所以"后端不跟随官方"不需要任何配置，自己 build 即可。会自动更新的只有前端面板，见第六节。

---

## 六、控制前端面板更新（脱离官方自动更新）

**背景**：7.2.80 起面板是运行时下载、每 3 小时自动从官方仓库更新的外部资源（见第二节第 6 项）。
若不干预，自定义改动会被官方原版覆盖。相关配置项在 `config.yaml` 的 `remote-management:` 下：

- `panel-github-repository`：从哪个仓库拉面板（默认官方
  `router-for-me/Cli-Proxy-API-Management-Center`）。可指向自己的 fork。
- `disable-auto-update-panel`：`true` = 关掉定时后台更新。**注意**：即使为 `true`，缓存文件
  **缺失时仍会去 `panel-github-repository` 下载一次**（下载的是该仓库 GitHub Release 里的
  `management.html` 资源）。

### 方式 A：指向自己的 fork + 关自动更新
```yaml
remote-management:
  panel-github-repository: https://github.com/surumnv/Cli-Proxy-API-Management-Center
  disable-auto-update-panel: true
```
前提：自己的 fork 必须**发布带 `management.html` 构建产物的 Release**，否则缺文件时拉取失败会
回退到官方 fallback 页面（等于用回官方原版）。

### 方式 B（最省事、完全脱离官方）：手动放缓存文件 + 关自动更新
1. 自己 `bun run build`（在面板仓库）拿到构建产物 `dist/.../management.html`；
2. 手动覆盖缓存目录 `~/.cli-proxy-api/management.html`（Windows：`%USERPROFILE%\.cli-proxy-api\management.html`）；
3. 配置：
   ```yaml
   remote-management:
     disable-auto-update-panel: true
   ```
因为文件已存在且关了自动更新，后端**永远不会再去任何地方拉取**，一直用手动放的这份。
不需要发布 Release，也不用改 `panel-github-repository`。**推荐这个方式**。

> 面板缓存路径由 `internal/managementasset/updater.go` 的 `StaticDir()` 决定（默认
> `~/.cli-proxy-api/`）。重建面板后按方式 B 重新覆盖一次即可。

---

# 改动主题二：为 Gemini / Codex / Claude / Vertex 供应商增加“名称”字段

> 与上面的“伪装 UA”主题完全独立，可单独套用。

**背景**：管理面板里只有 “OpenAI 兼容” 供应商能设置“名称”（config 里的 `name` 字段，既作唯一标识又作显示名）。
Gemini / Codex / Claude / Vertex 这四类供应商没有 `name` 字段，识别靠 “api-key + base-url”，
列表里只能显示打码后的 API 密钥，多条同类凭据难以区分。

**本次改动**：给这四类供应商也加上可选的“名称”字段（纯显示标签，**不**参与识别，识别仍用
api-key + base-url，因此不影响任何既有匹配/去重/删除逻辑）。参考 OpenAI 兼容供应商的做法与外观保持一致。
xAI 因为 `XAIKey = CodexKey` 是类型别名，自动跟随支持。

**范围说明**：`claudeApi`（Claude 官方 API 专用枠，前端用固定显示名）**不在**本次范围内，保持原样。

---

## 一、结构体新增 `Name` 字段（`internal/config/`）

`Name` 字段统一用 `yaml:"name,omitempty" json:"name,omitempty"`，放在 `APIKey` 之后。

### 1. `internal/config/config.go`
- `GeminiKey`、`CodexKey`、`ClaudeKey` 三个结构体各加：
  ```go
  // Name is an optional human-readable label for this credential shown in the management panel.
  Name string `yaml:"name,omitempty" json:"name,omitempty"`
  ```
  > `XAIKey = CodexKey` 是别名，无需单独改动，xAI 自动获得 `Name`。
- 各 sanitize 函数里对 `Name` 做 `strings.TrimSpace`：
  - `sanitizeGeminiKeyEntries`（服务 Gemini 与 Interactions）：`entry.Name = strings.TrimSpace(entry.Name)`
  - `sanitizeCodexKeyEntries`（服务 Codex 与 xAI）：`e.Name = strings.TrimSpace(e.Name)`
  - `SanitizeClaudeKeys`：`entry.Name = strings.TrimSpace(entry.Name)`

### 2. `internal/config/vertex_compat.go`
- `VertexCompatKey` 加同样的 `Name` 字段。
- `SanitizeVertexCompatKeys` 循环里加 `entry.Name = strings.TrimSpace(entry.Name)`。

---

## 二、管理端 PATCH 接口透传 `Name`（`internal/api/handlers/management/config_lists.go`）

前端保存供应商是「整段数组 PUT」，仅靠结构体加字段即可持久化；但为了让**逐条 PATCH** 接口也一致，
给以下四个 handler 的内部 patch 结构体加 `Name *string \`json:"name"\``，并在应用字段处加：
```go
if body.Value.Name != nil {
    entry.Name = strings.TrimSpace(*body.Value.Name)
}
```
涉及 handler：
- `PatchGeminiKey`（内部 `geminiKeyPatch`）
- `PatchClaudeKey`（内部 `claudeKeyPatch`）
- `PatchCodexKey`（内部 `codexKeyPatch`）
- `PatchVertexCompatKey`（内部 `vertexCompatPatch`）

> `PatchInteractionsKey` 里也有一个同名 `geminiKeyPatch` 结构体，本次未加（Interactions 面板不暴露名称）；
> 如需要可照抄。

---

## 三、涉及文件清单（后端）

修改：
- `internal/config/config.go`（3 个结构体 + 3 处 sanitize）
- `internal/config/vertex_compat.go`（1 个结构体 + 1 处 sanitize）
- `internal/api/handlers/management/config_lists.go`（4 个 PATCH handler）

无需改动 `go.mod` / `go.sum`。

> 前端对应改动见面板仓库 `Cli-Proxy-API-Management-Center` 根目录的 `CHANGES_CUSTOM.md`
> “供应商名称” 章节。

---

## 四、验证

```bash
cd /d/AIProject/CLIProxyAPI
go build ./...
go test ./internal/config/... ./internal/api/handlers/management/...
```
两个包测试均通过。

---

# 改动主题三：按 CC Switch 思路保留 HTTP/1.1 请求头顺序

**背景**：Go 的 `net/http` 在入站解析后会把请求头放进 `http.Header` map，原始 wire 顺序会丢失；出站
HTTP/1.1 默认也会按标准库自己的规则写头。为了让 CPA 发往上游的 HTTP/1.1 请求尽量沿用真实客户端的
头部顺序，本次按 CC Switch 的思路增加“入站记录原始顺序 + 出站按该顺序写最终值”的链路。

**核心规则**：
- 入站只记录每条 HTTP/1.1 连接首个请求的 header 名顺序和原始大小写。
- 出站仍以 CPA 最终生成的 `http.Request.Header` 为值来源。
- 原始请求里有、但入站后被 CPA 丢弃并重新生成的字段，也用原始位置写最终值。例如 `Host` 写当前上游
  host，`Content-Length` 写当前 body 长度，`Authorization` / `Accept-Encoding` / `Content-Type`
  写 CPA 改写后的值。
- 原始请求里没有、但 CPA 新增的 header，追加在原始顺序之后。
- 出站 raw HTTP/1.1 transport 维护按 `scheme://host:port` 分组的空闲连接池；响应 body 读到 EOF 并
  关闭后，连接会回到池中供后续请求复用。若复用到已被上游关闭的旧连接，会自动丢弃并重试一次新连接。
- 空闲连接有 90s 超时；取出复用前会做 1ms 读探活，过期或半开连接直接丢弃再建新连接。
- 已知 `Content-Length` 的请求体按流式写出，不再整包 `ReadAll`；仅长度未知的 body 才缓冲后补
  `Content-Length`。
- dial / TLS handshake 跟随 `req.Context()` 取消；代理 dialer 优先走 `ContextDialer`，否则用
  goroutine + select 响应取消。
- `sharedOrderedH1RoundTripper` 的缓存键同时包含 proxyURL 与 fallback transport 身份，避免不同
  fallback 误共享同一连接池。
- 没有捕获到顺序信息时，继续走原有 transport，不改变原行为。

## 一、新增文件

- `internal/util/header_order.go`
  - 新增 `OriginalHeaderOrder` / `OriginalHeaderLine`。
  - 新增 `ParseOriginalHeaderOrder`，从原始 HTTP/1.x 请求头字节中提取 header 名顺序。
  - 新增 context 读写函数，供 `api` 捕获层和 executor 出站层共享。

- `internal/api/header_order_conn.go`
  - 新增 `headerOrderConn`，包装 `net.Conn.Read`。
  - 标准库读取入站请求时同步收集首个请求头块，解析完成后放进 `OriginalHeaderOrder`。

- `internal/runtime/executor/helps/ordered_h1_round_tripper.go`
  - 新增 HTTP/1.1 raw RoundTripper。
  - request context 中有原始顺序时，手写请求行和 header；再用 `http.ReadResponse` 读取上游响应。
  - 支持直接连接和现有 `proxyutil.BuildDialer` 支持的 HTTP / HTTPS / SOCKS5 代理。
  - 新增空闲连接池和 `CloseIdleConnections`，避免每次 ordered h1 请求都重新 TCP/TLS 握手。
  - 连接池增加 90s idle timeout + 复用前读探活。
  - 已知长度 body 流式写出；未知长度 body 才缓冲。
  - dial/handshake 响应 `req.Context()` 取消。
  - shared transport 缓存键 = proxyURL + fallback 身份。

## 二、修改文件

- `internal/api/server.go`
  - 给 `http.Server` 增加 `ConnContext`，把 `headerOrderConn` 中的 `OriginalHeaderOrder` 放入 request context。

- `internal/api/protocol_multiplexer.go`
  - HTTP/1.1 连接进入 `http.Server` 前包上 `headerOrderConn`。
  - TLS 入站时只对 ALPN 为 `http/1.1` 的连接记录顺序；HTTP/2 不走该逻辑。

- `internal/runtime/executor/helps/utls_client.go`
  - 把非 protected host 的 fallback transport 包成 ordered HTTP/1.1 transport。
  - `api.anthropic.com`、`chatgpt.com` 仍按原 protected host 逻辑走 utls/http2，不受本次 h1 顺序写入影响。

## 三、测试

新增：
- `internal/util/header_order_test.go`
- `internal/api/header_order_conn_test.go`
- `internal/runtime/executor/helps/ordered_h1_round_tripper_test.go`

覆盖：
- 原始 header 顺序和大小写解析。
- 连接包装在读取时捕获首个请求头顺序。
- 出站 raw HTTP/1.1 写入时，`Host`、`Authorization`、`Accept-Encoding`、`Content-Type`、`Content-Length`
  使用最终值但保留原始位置。
- 出站 ordered h1 transport 能在连续请求之间复用同一条上游 HTTP/1.1 连接。
- 过期空闲连接会被丢弃并新建连接。
- shared transport 在不同 fallback 下不会误共享。
- 已知长度请求体可流式写出到上游。
- dial 在 request context 取消时会失败返回。

---

# 改动主题三补充：ordered HTTP/1.1 transport 稳定性修复

针对出站 ordered H1 路径的四项修复（不改变“保留首个请求 header 顺序”的既定策略）：

1. **空闲连接超时 / 探活**：池中连接超过 90s 不再复用；取出时 1ms Peek 探活，半开连接丢弃。
2. **shared transport 缓存键**：由仅 proxyURL 改为 proxyURL + fallback 身份，避免不同 fallback
   共用错误连接池。
3. **请求体写出**：Content-Length >= 0 已知长度时流式写出；仅未知长度 body 才 ReadAll 缓冲。
4. **dial 取消**：直连 DialContext(req.Context())；代理 dialer 优先 ContextDialer，否则
   goroutine + ctx.Done()；HTTPS 握手改用 HandshakeContext。

涉及文件：
- internal/runtime/executor/helps/ordered_h1_round_tripper.go
- internal/runtime/executor/helps/ordered_h1_round_tripper_test.go
- CHANGES_CUSTOM.md（本文）

---

# 改动主题三补充二：ordered HTTP/1.1 transport 请求体与连接复用修复

本次只修两个 ordered H1 transport 问题，其他已知问题暂不处理。

1. **修复 `ContentLength == 0` 误判空 body**：
   `Body != nil && ContentLength == 0` 在 Go 客户端请求里表示“正文长度未知”，不能直接当成“没有正文”。
   `openOrderedH1RequestBody` 不再因为 `ContentLength == 0` 提前返回空 body；这类请求现在会进入未知长度 body 的缓冲路径，
   读取真实正文后补出正确的 `Content-Length`，避免流式或自定义 `Reader` 的请求体被静默丢弃。

2. **放宽空闲连接复用前探活**：
   原先复用空闲连接前每次都用 1ms read deadline 做 `Peek(1)` 探活。Windows localhost 等环境下 1ms 阈值偏紧，
   容易把可用连接误判为失活，导致复用率下降和额外重连。现在探活超时放宽到 25ms，并且刚入池不足 100ms 的连接
   在已满足 reader 无缓冲数据、未超过 idle timeout 的前提下直接复用；若连接实际已关闭，后续写入失败仍会走既有的一次重试逻辑。

测试补充：
- 新增 `TestOrderedH1RoundTripperPreservesZeroContentLengthBody`，覆盖 `Body != nil && ContentLength == 0` 时上游仍能收到正文。

涉及文件：
- internal/runtime/executor/helps/ordered_h1_round_tripper.go
- internal/runtime/executor/helps/ordered_h1_round_tripper_test.go
- CHANGES_CUSTOM.md（本文）

---

# 改动主题四：接通请求头顺序透传并完善 Claude 请求头处理

> 本主题包含三处相对独立的修复，但都围绕“让 Claude Desktop 经 CPA 转发到第三方中转的请求尽量贴近真实客户端”。第 1 条是对**改动主题三**（ae2216f，按 CC Switch 思路保留 HTTP/1.1 请求头顺序）的**补全**——那条 commit 建好了链路两端却漏接了中间一节，导致顺序透传从未真正生效。

## 1. 接通 HTTP/1.1 请求头顺序透传（补全 ae2216f / 改动主题三）

**问题**：改动主题三（commit ae2216f）建立了顺序透传的四个部件里的三个：

1. 入站捕获：`headerOrderConn`（`internal/api/header_order_conn.go`）
2. 挂到连接 context：`server.go` 的 `ConnContext`，挂到 **`c.Request.Context()`**
3. 出站按序写：`orderedH1RoundTripper`（`ordered_h1_round_tripper.go`），从 **`req.Context()`** 取顺序

但**漏接了第 4 节**：把顺序从 `c.Request.Context()` 传递到执行器出站请求所用的 ctx。

所有 provider handler 走 `h.GetContextWithCancel(h, c, context.Background())`（`sdk/api/handlers/handlers.go`），该函数把执行器 ctx 派生自传入的 `context.Background()`（`parentCtx`），只复制了 request ID，**捕获到的 `OriginalHeaderOrder` 在此丢失**。于是 `orderedH1RoundTripper.canUseOrderedH1` 恒为 false，出站一直回落到 Go 的字母序写头。

**因此顺序透传自 ae2216f 落地起对所有走主转发路径的 provider（含 Codex 主路径与 Claude）从未真正生效**。唯一例外是 `codexAlphaSearch` 旁路端点（`server.go`），它自行写了 `context.WithValue(c.Request.Context(), "gin", c)`，误打误撞派生自 `c.Request.Context()` 而侥幸可用——但那不是通用路径。测试之所以没暴露该问题，是因为 `ordered_h1_round_tripper_test.go` 用 `util.WithOriginalHeaderOrder(context.Background(), order)` 手工注入顺序，绕过了真实的 handler → executor context 传递，没有端到端覆盖。

**修改**：`sdk/api/handlers/handlers.go` 的 `GetContextWithCancel`，在构造 `newCtx` 之后，把入站顺序从 `c.Request.Context()` 传递到执行器 ctx：

```go
	// Propagate the inbound HTTP/1.1 header order captured on the downstream
	// connection (attached to c.Request.Context() by the server's ConnContext
	// hook) onto the executor context. newCtx is rooted at parentCtx, which is
	// context.Background() for provider handlers, so without this the ordered-h1
	// round tripper would never see the order and would fall back to Go's
	// alphabetical header writer. This makes header-order preservation work for
	// all providers (Claude included), not just the bespoke Codex path.
	if requestCtx != nil {
		if order := util.OriginalHeaderOrderFromContext(requestCtx); order != nil {
			newCtx = util.WithOriginalHeaderOrder(newCtx, order)
		}
	}
```

（`requestCtx` 即函数上文已取好的 `c.Request.Context()`。需确保该文件已 import `internal/util`——官方原文件已有。）

**效果**：一处修复让所有走主转发路径的 provider（含 Codex 主路径与 Claude）的顺序透传同时生效，不再需要每个 provider 各自接线。

## 2. Claude Desktop 入站请求头尽力透传

**问题**：Claude executor 此前是**纯白名单**（逐头 `misc.EnsureHeader` + 设备指纹），白名单外的入站头一律静默丢弃。Codex 早有 `util.CopyInboundHeaders`（见改动主题一第二节第 2 项），Claude 没有——Claude Desktop 升级后新增的任何头都会被吞掉，成为相对真实客户端的指纹缺口。

**修改**：`internal/runtime/executor/claude_executor.go` 的 `applyClaudeHeaders`，在设备指纹/UA（`ApplyClaudeDeviceProfileHeaders` / `ApplyClaudeLegacyDeviceHeaders`）之后、`util.ApplyCustomHeadersFromAttrs` 之前，加入透传：

```go
	util.CopyInboundHeaders(r, ginHeaders,
		"Authorization", "X-Api-Key",
		"Anthropic-Beta",
		"Accept", "Accept-Encoding",
		"Anthropic-Dangerous-Direct-Browser-Access",
	)
```

- 运行时机保证权威头（UA、鉴权、beta、Accept 等）先设好，`CopyInboundHeaders` 不覆盖 `r` 上已有值，故不会破坏它们。
- skip 列表让 CPA 对这些头保持权威：`Authorization`/`X-Api-Key`（必须用代理/provider 凭据，不能透传客户端 key）、`Anthropic-Beta`（本函数自行拼装，含 oauth 处理与 extra betas）、`Accept`/`Accept-Encoding`（流式强制 `identity`）、`Anthropic-Dangerous-Direct-Browser-Access`（仅 API-key 模式设置）。
- hop-by-hop / `Content-Length` / `Host` 等由 `CopyInboundHeaders` 内置的 `passthroughHeaderDenylist` 自动丢弃。

**效果**：Claude Desktop 后续升级新增的任何头自动透传，不必改代码追白名单。

## 3. 第三方 base 去掉 CPA 注入的 `oauth-2025-04-20`

**问题**：`applyClaudeHeaders` 在拼装 `Anthropic-Beta` 时无条件注入 `oauth-2025-04-20`。该 beta 只对 Anthropic 官方 OAuth 上游有意义；对以 API key 认证的第三方中转转发它，是真实 Claude Desktop 不会发送的多余指纹。

**修改**：同文件的 beta 拼装逻辑改为——仅对官方 `api.anthropic.com` 保留注入的 oauth beta；非官方 base 且客户端自己没带 oauth beta 时，剥离掉 CPA 注入的那个：

```go
	if !isAnthropicBase && !clientSuppliedOAuth {
		baseBetas = stripInjectedOAuthBetas(baseBetas)
	}
	r.Header.Set("Anthropic-Beta", baseBetas)
```

配套新增 `stripInjectedOAuthBetas`（逗号分隔、大小写不敏感地剔除含 `oauth` 的 token，保留其余顺序）与 `clientSuppliedOAuth`（记录入站 `Anthropic-Beta` 是否本来就含 oauth）。**客户端自带的 oauth beta 视为正常透传，保持不变**，只剥离 CPA 自己注入的那一个。

## 涉及文件清单（本主题）

修改：
- `sdk/api/handlers/handlers.go`（`GetContextWithCancel` 传递入站顺序——第 1 条，惠及所有 provider）
- `internal/runtime/executor/claude_executor.go`（`CopyInboundHeaders` 透传——第 2 条；`Anthropic-Beta` oauth 剥离 + `stripInjectedOAuthBetas` 辅助函数——第 3 条）

无需改动 `go.mod` / `go.sum`。

## 验证

```bash
cd /d/AIProject/CLIProxyAPI
go build ./...
go test ./internal/api/... ./internal/runtime/executor/... ./internal/util/...
```
构建通过，相关包测试全绿。

> **升级套用提醒**：第 1 条改的是公共层 `GetContextWithCancel`，与 provider 无关，务必在升级后确认这段顺序传递仍在——否则改动主题三的顺序透传会再次“装好但没通电”。第 2、3 条随 Claude executor 走。

---

# 改动主题五：管理面板拉取 Claude 模型列表的兜底 UA（跟随 Desktop 内嵌 claude-code 版本）

**背景**：管理面板"拉取模型列表"对 Claude provider 走前端 `fetchClaudeModelsViaApiCall`，它只设
`x-api-key` / `anthropic-version`，**不带 User-Agent**，因此出站 UA 落到后端 `api_tools.go` 的兜底。
而原兜底 `defaultAPICallUserAgent` 只在两个 **Codex** UA 之间按 `Originator` 分流——于是拉 Claude
模型时竟然带的是 Codex 的 UA（`codex_cli_rs/...`），对 Claude 上游是个明显不一致的指纹。

**目标**：给 Claude 请求单独兜底一个**真实的 Claude Code CLI UA**，且版本号跟随本机 **Claude Desktop
内嵌的 claude-code** 版本（方案 B，本地探测）。

**三个版本号的坑（务必分清，别拿错）**：本机同时装了独立 CLI 和 Desktop，存在三个不同版本号——
- 独立 Claude Code CLI：`claude --version`（PATH）→ 如 `2.1.201`。**不能用这个。**
- Desktop 的 MS Store 包版本：`Get-AppxPackage Claude` → 如 `1.22209.0.0`。**无关。**
- **Desktop 内嵌的 claude-code**：`%LOCALAPPDATA%\Claude-3p\claude-code\<版本>\` 目录名 → 如
  `2.1.209`。**这才是 Desktop UA `claude-cli/2.1.209 (...)` 里的版本，要用的就是它。**
  （`Claude-3p` 的 `3p` 对应 Desktop UA 里的 `claude-desktop-3p` 入口标记。）

**UA 形态（本次决定：纯 CLI 格式，entrypoint = `cli`）**：
```
claude-cli/<Desktop内嵌claude-code版本> (external, cli)
```
不用 Desktop 原始的 `(external, claude-desktop-3p, agent-sdk/x.y.z)` 后缀——拉模型本就是 CLI 风格的
可达性探测，用 `cli` 入口更自洽，也不暴露桌面内嵌标记。Claude Code CLI 的 UA **没有** OS/arch/终端段
（比 Codex 简单，Codex 那套 `(Windows x.y.z; x86_64) WindowsTerminal` 不适用）。

## 一、新增文件

### `internal/misc/claude_local_ua.go`
仿 `codex_local_ua.go` 结构，`package misc`。导出：
- `LocalClaudeCodeUserAgent() string`：进程内缓存 + 加锁；空则用 fallback；永不返回空。
- `RefreshLocalClaudeCodeUserAgent() string`：清缓存并重探，返回新值。
- 常量 `LocalClaudeCodeUAFallback = "claude-cli/2.1.209 (external, cli)"`：探测失败时用（本机实测的真实
  版本；宁可略滞后的真串，也不发合成串）。

内部：
- `buildLocalClaudeCodeUserAgent()`：探测到版本才拼 `claude-cli/<v> (external, cli)`，否则返回空触发 fallback。
- `detectClaudeDesktopEmbeddedVersion()`：枚举 `%LOCALAPPDATA%\Claude-3p\claude-code\` 子目录，
  **只认同时有 `.verified` 标记文件和 `claude.exe` 的目录**，按版本号数值比较取最高，返回目录名当版本号。
  用目录名而非跑 `claude.exe --version`：目录名即版本号（本机已验证与 `--version` 输出一致），省一次
  进程调用和超时。非 Windows / Desktop 未装 / 目录不存在 → 返回空 → 走 fallback。
- `compareClaudeVersions(a, b)`：点分版本逐段数值比较（`2.1.209` > `2.1.60`）。

> 无需 windows/other 拆分文件：探测只读 `LOCALAPPDATA` 目录，非 Windows 上该环境变量为空，自然回落 fallback。

## 二、修改文件

### `internal/api/handlers/management/api_tools.go`
**(a)** `APICall` 里补 UA 兜底处，改为先判定 Claude 请求：
```go
if strings.TrimSpace(req.Header.Get("User-Agent")) == "" {
    if strings.TrimSpace(req.Header.Get("Anthropic-Version")) != "" {
        req.Header.Set("User-Agent", misc.LocalClaudeCodeUserAgent())
    } else {
        req.Header.Set("User-Agent", defaultAPICallUserAgent(req.Header.Get("Originator")))
    }
}
```
判定信号用 **`Anthropic-Version` 头是否存在**：前端 `fetchClaudeModelsViaApiCall` 一定设它，Codex 路径
从不设，比按 URL 匹配可靠（第三方 base 域名各异）。Codex 分支逻辑保持不变。

**(b)** `RefreshAPICallUserAgent` 端点额外清 Claude UA 缓存并在响应里返回（key: `claude`），方便升级
Desktop 后手动刷新，无需重启代理。

## 三、测试

### `internal/misc/claude_local_ua_test.go`（新增）
用临时目录模拟 `Claude-3p\claude-code\<版本>\{.verified,claude.exe}` 结构，覆盖：
- 多版本取最高、缺 `.verified` 或缺 `claude.exe` 的目录被跳过；
- 版本号数值序（`2.1.209` > `2.1.60`，非字典序）；
- 根目录不存在 / `LOCALAPPDATA` 为空 → 探测失败；
- UA 拼装格式；探测失败回落 fallback；`compareClaudeVersions` 各情形。

## 涉及文件清单（本主题）

新增：
- `internal/misc/claude_local_ua.go`
- `internal/misc/claude_local_ua_test.go`

修改：
- `internal/api/handlers/management/api_tools.go`（Claude 请求 UA 分流 + refresh 端点带 Claude UA）

无需改动 `go.mod` / `go.sum`；前端仓库**无需改代码**（前端本就不带 UA，靠本兜底）——但前端与后端之间
有一条隐含契约：**前端拉 Claude 模型必须带 `Anthropic-Version` 头**，后端据此判定走 Claude UA。前端
`CHANGES_CUSTOM.md` 已记此契约。

## 验证

```bash
cd /d/AIProject/CLIProxyAPI
go build ./...
go test ./internal/misc/... ./internal/api/handlers/management/...
```
构建通过，相关包测试全绿。

> **升级套用提醒**：Desktop 升级后内嵌 claude-code 版本会变，`detectClaudeDesktopEmbeddedVersion` 会
> 自动跟随（取 `Claude-3p\claude-code\` 下最高的已验证版本）；只有探测彻底失败才回落到写死的
> `LocalClaudeCodeUAFallback`，届时该常量的版本需手动跟一下。

---

# 改动主题六：审查修复（透传安全 + ordered H1 稳定性/性能 + Claude beta 修正）

> 本主题是对前述主题一~五的一轮代码审查后的修复集合。**核心原则不变**：尽量如实透传真实
> Codex / Claude Desktop 的入站请求头、保留其顺序、不捏造字段；这里只是堵住"会误伤真实请求"或
> "会泄漏/损坏/泄漏内存"的漏洞，并在不改变既定透传行为的前提下降低延迟。

## 1. `CopyInboundHeaders` 透传黑名单补充（`internal/util/header_helpers.go`）

`passthroughHeaderDenylist` 新增四个头，全部是"不该原样转发给上游"的：

- `Content-Encoding`：描述**入站** body 的编码。所有 executor 都会把请求体重新序列化成明文 JSON
  （或重建 multipart），若把入站的 `Content-Encoding: gzip` 转发出去，会让上游以为 body 是 gzip 而
  实际是明文，直接损坏请求。
- `Expect`（如 `100-continue`）：对我们已知长度、直接写出的 body 没有意义，可能拖慢或困惑上游。
- `Cookie` / `Proxy-Authorization`：入站 hop 的会话/凭据材料，转发给第三方上游既泄漏会话又是指纹异常
  （真实 Codex/Claude 客户端不会往上游发这两个）。

> **说明**：这四个头在实测抓到的真实 Claude Desktop / Codex 请求里**都没有出现**（Claude Desktop
> 抓包只有 `X-Stainless-*`、`Anthropic-*`、`X-App`、`X-Claude-Code-Session-Id`、`User-Agent`、
> `Accept`、`Accept-Encoding`、`Authorization`、`Connection`、`Content-Type`、`Content-Length`），
> 因此加入黑名单**不会误伤**当前真实请求；这是预防性加固，防止将来客户端偶发带上这些头时被原样透传
> 造成损坏/泄漏。已在代码注释中标注"目前真实请求未遇到"。

## 2. openai-compat 无 api-key 时会泄漏入站 Authorization（`internal/runtime/executor/openai_compat_executor.go`）

**问题**：compat executor 四处出站都只在 `apiKey != ""` 时才 `Set("Authorization", "Bearer "+key)`。
而 `opts.Headers` 是入站客户端请求的完整克隆（含客户端**向 CPA 鉴权用的 token**）。当某个 compat
provider **没配 api-key**（本地 Ollama/LM Studio、无鉴权中转常见）时，`CopyInboundHeaders` 会把入站
`Authorization` 原样拷给第三方上游——泄漏代理凭据。Codex 主路径不受影响（它总会 `Set` Authorization，
即使空 token 也是非空的 `"Bearer "`，挡住拷贝）。

**修改**：把原 `openAICompatChatHeaderSkips` 改名为 `openAICompatHeaderSkips`，**无条件**把
`Authorization`、`X-Api-Key` 放进 skip 列表（`/chat/completions` 额外再 skip Codex Responses-Lite 头，
逻辑不变），并把全部 4 处调用点（含两个 images 站点，原先**完全没传 skip**）都换成它。这样无论是否配
provider key，入站凭据都不会被透传。

## 3. ordered H1：重试时静默丢弃请求体（`ordered_h1_round_tripper.go`，最严重）

**问题**：对 `Body != nil && ContentLength == 0`（流式/未知长度）请求，`openOrderedH1RequestBody`
首次会缓冲 body、把 `req.Body` 换成 `http.NoBody` 并装好 `GetBody`。但任何一次重试重新进入该函数时，
第一行 `req.Body == http.NoBody` 卫语句直接命中返回空 body——**不看刚装好的 `GetBody`**，于是重试用
空 body 重发上游（例如变成没有 messages 的请求），且不报错。恰好击穿了当初 commit 9c801050 想修的场景。

**修改**：调整 `openOrderedH1RequestBody` 的判断顺序——**先查 `GetBody`**（它每次返回全新 reader，正是
重试所需），再走 `http.NoBody` 短路。这样首发和重试都能拿到完整 body。已知长度且无 GetBody 的流式路径
行为不变（写出 body 后仍拒绝重试，因为单次 reader 无法回绕）。

新增测试 `TestOpenOrderedH1RequestBodyReplaysOnRetry`：对同一请求连续调用两次（首发+重试），断言第二次
仍产出完整 body。

## 4. ordered H1：配代理时连接池失效 + `sync.Map` 无界增长（内存泄漏）

**问题**：`sharedOrderedH1CacheKey` 把 fallback transport 指针 `%p` 编进缓存 key。而 `NewUtlsHTTPClient`
是**每请求调用一次**，配代理时 `buildProxyTransport` 每次都 `new` 一个新的 `*http.Transport`。于是每个
请求产生唯一 key → `LoadOrStore` 插入一条**永不删除**的条目（进程级内存泄漏），且每请求都是全新空闲池
→ 连接复用从未发生，抵消 c89ca2b8 的性能目标。

**修改**：ordered transport 的缓存键**只用 `proxyURL`**（`sharedOrderedH1CacheKey(proxyURL string)`）。
理由：在真实调用路径里 fallback 完全由 proxyURL 决定——空 proxyURL 恒为 `http.DefaultTransport`，非空
则是由**同一** proxyURL 构建的代理 transport，行为一致；原来掺 `%p` 是过度修正，正是泄漏根因。
同 proxyURL 现在稳定复用同一个 ordered transport（含其空闲池）。

原测试 `TestSharedOrderedH1RoundTripperSeparatesFallbackTransports`（断言不同 fallback 实例分开）编码的
是错误意图，改写为 `TestSharedOrderedH1RoundTripperKeyedByProxyURL`：同 proxyURL 复用同一实例、不同
proxyURL 得不同实例。

## 5. ordered H1：ReadResponse 失败重试增加幂等判断

**问题**：head+body 已完整写出后若 `ReadResponse` 失败，原代码对任何可重建 body 的请求都重试，不看
method。若上游其实已收到并处理了这个 POST，只是响应没读到，重试会**重复副作用**。

**修改**：新增 `orderedH1RequestReplayable`，**对齐 net/http 的 `(*Request).isReplayable`**：body 必须
可重建（nil/NoBody/GetBody），且 method 为 GET/HEAD/OPTIONS/TRACE，或带 `Idempotency-Key` /
`X-Idempotency-Key`。仅这类请求才在读响应失败后重试；POST 等非幂等请求直接把错误返回给调用方。
（head 写失败、body 写失败两处重试保持不变——那是"上游尚未实质收到"的场景，重试任何 method 都安全，
与 stdlib 一致。）

新增测试 `TestOrderedH1RequestReplayable` 覆盖 GET/HEAD 可重试、POST/PATCH 不可重试、带幂等 key 的 POST
可重试。

## 6. ordered H1：非阻塞探活，去掉每次复用的固定延迟

**问题**：复用空闲连接前用 `Peek(1)` + 25ms 读超时探活。健康连接因无待读数据会**阻塞满 25ms** 才返回
（探活只在有数据/EOF 时提前返回），于是每次复用 >100ms 的连接都多付最多 25ms 延迟。

**修改**：把读探活的 deadline 设成**过去时刻**（`time.Now().Add(-time.Second)`），使 `Peek` 立即返回：
健康连接立刻拿到 deadline-exceeded（判活），已关闭/半开连接立刻拿到 EOF/RST（判死），**不再阻塞**。
删除不再使用的 `orderedH1ProbeTimeout` 常量。`<100ms` 的热路径直接复用捷径保留；万一半开连接漏网，
现在有第 5 条收紧后的安全重试兜底。

## 7. Claude `Anthropic-Beta`：body 里的 oauth beta 不再被误剥（`claude_executor.go`）

**问题**（对主题四第 3 条的补全）：`clientSuppliedOAuth` 原来只看入站 `Anthropic-Beta` **请求头**。但
客户端也能通过请求体 `betas` 数组带 oauth beta（经 `extractAndRemoveBetas` 变成 `extraBetas`）。若客户端
用 body 带 oauth beta 发往第三方 base，`clientSuppliedOAuth` 仍为 false → `stripInjectedOAuthBetas` 会
把客户端**自己真实带的** oauth beta 也剥掉，违背"客户端自带的照常透传"。

**修改**：`clientSuppliedOAuth` 的判定同时检查请求头**和** `extraBetas`——任一含 oauth 即视为客户端自带，
不再剥离。CPA 自己注入的 `oauth-2025-04-20`（第三方 base 且客户端未自带 oauth 时）仍按原逻辑剥离。

## 涉及文件清单（本主题）

修改：
- `internal/util/header_helpers.go`（denylist 加 4 个头 + 注释标注"真实请求未遇到"）
- `internal/runtime/executor/openai_compat_executor.go`（`openAICompatHeaderSkips` 无条件 skip 凭据头，4 处调用点）
- `internal/runtime/executor/helps/ordered_h1_round_tripper.go`（body 重放、缓存键、幂等重试、非阻塞探活）
- `internal/runtime/executor/helps/ordered_h1_round_tripper_test.go`（重写 1 个测试 + 新增 3 个测试）
- `internal/runtime/executor/claude_executor.go`（`clientSuppliedOAuth` 兼顾 body betas）

无需改动 `go.mod` / `go.sum`。前端仓库无需改动。

## 验证

```bash
cd /d/AIProject/CLIProxyAPI
go build ./...
go test ./internal/util/... ./internal/runtime/executor/... ./internal/api/... \
  ./internal/api/handlers/management/... ./internal/config/... ./internal/misc/... \
  ./sdk/api/handlers/...
```
构建通过，相关包测试全绿。（竞态检测器 `-race` 需要 cgo/C 编译器，本机 Windows 环境缺失，未跑；
ordered H1 并发部分靠人工审查连接池加锁纪律。）

> **升级套用提醒**：本主题全是对既有自定义代码的修补，随对应文件走。第 3、4 条是 ordered H1 的正确性/
> 内存关键修复，升级后务必确认仍在。

---

## 追加改动：可选 SChannel 出站 TLS，使 JA3 与 Codex CLI 一致

### 修改 / 新增文件

新增：
- `internal/schannel/schannel_windows.go`（常量、`SCHANNEL_CRED` 结构体含 amd64 显式对齐、`Config`）
- `internal/schannel/conn_windows.go`（SSPI 握手 + 收发的 `net.Conn` 实现、ALPN 缓冲构造）
- `internal/runtime/executor/helps/ordered_h1_tls_windows.go`（Windows 分支：可选走 SChannel）
- `internal/runtime/executor/helps/ordered_h1_tls_other.go`（非 Windows 分支：始终标准 crypto/tls）
- `internal/runtime/executor/helps/ordered_h1_schannel_ja3_windows_test.go`（实弹 JA3 匹配测试，`RUN_SCHANNEL_JA3=1` 触发）
- `cmd/schannelprobe/main.go`（独立 JA3 探针，用于抓取/比对）

修改：
- `internal/config/config.go`（新增顶层开关 `schannel-tls`，默认 false）
- `internal/runtime/executor/helps/ordered_h1_round_tripper.go`（`getConn` 的握手抽出为 `handshakeOrderedH1TLS`）
- `internal/runtime/executor/helps/utls_client.go`（`NewUtlsHTTPClient` 按 `cfg.SChannelTLS` 置位开关）

### 背景

主题四（伪装成真实 Codex 客户端）此前只覆盖到**应用层**：UA、请求头、头顺序透传。但 **TLS 层**仍是短板——
CPA 出站用 Go `crypto/tls`，其 JA3 与 Codex 属不同族。Codex CLI 用 reqwest + native-tls，在 Windows 上即
SChannel（legacy `SCHANNEL_CRED`，故最高 TLS 1.2、无 GREASE）。上游 relay 若比对 JA3，会发现「UA 自称
Codex、TLS 指纹却是 Go」这一矛盾。本改动补齐 TLS 层，使出站 ClientHello / JA3 与本机 Codex 逐位一致。

### 实现（路径 1：SChannel 只做加密层）

以 SSPI（`secur32.dll`）手写一个由 SChannel 支撑的 `net.Conn`：`AcquireCredentialsHandleW` +
`InitializeSecurityContextW` 完成握手（产出与 Codex 一致的 ClientHello），`EncryptMessage` /
`DecryptMessage` 负责收发。它**只替换 TLS 加密层**——HTTP/1.1 请求头仍由 ordered-h1 按入站顺序写到这个
加密 conn 上，**头顺序透传行为完全不变**。

`getConn` 原先内联的 `tls.Client` 抽成 `handshakeOrderedH1TLS`，按 build tag 分流：Windows 且
`schannel-tls: true` 时走 SChannel，否则回退标准 `crypto/tls`。开关默认关闭，非 Windows 平台忽略。
anthropic / chatgpt 仍走既有 utls 路径，不受影响。

### 指纹校验

Codex v0.144.5 实测 JA3（经 check.ja3.zone 直连抓取）：
```
771,49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47,0-10-11-13-35-23-65281,29-23-24,0
hash: 6a5d235ee78c6aede6a61448b4e9ff1e
```
密码套件、椭圆曲线（`29-23-24`）、版本（`771`）在同机 SChannel 下天然一致；唯一差异是扩展 `16`（ALPN）——
Codex **不发** ALPN，故 `ALPNProtocols` 留空即逐位对齐。经 `NewUtlsHTTPClient(SChannelTLS:true)` →
ordered-h1 → SChannel 的**完整生产路径**实测复现同一 hash。

### 依赖说明

用到 `golang.org/x/sys/windows`，官方已在 `go.mod`（`golang.org/x/sys v0.47.0`），无需改动 `go.mod` / `go.sum`。

### 前端配套

管理面板「配置面板 → 高级 → Codex 请求头伪装」子区新增「SChannel 出站 TLS（匹配 Codex JA3）」开关，
对应顶层 YAML 键 `schannel-tls`。详见前端仓库 `CHANGES_CUSTOM.md`。

### 验证

```bash
cd /d/AIProject/CLIProxyAPI
GOOS=windows go build ./...          # Windows
GOOS=linux   go build ./...          # 非 Windows 分支
go vet ./internal/schannel/... ./internal/runtime/executor/helps/...
go test ./internal/runtime/executor/helps/...     # ordered-h1 单测全绿，头顺序保护未受影响
RUN_SCHANNEL_JA3=1 go test ./internal/runtime/executor/helps/ -run SChannelMatchesCodexJA3  # 实弹匹配（需联网）
```
Windows + Linux 均编译通过，`go vet` 仅一处良性 `unsafe.Pointer`（OS 持有的缓冲），ordered-h1 单测全绿。

> **升级套用提醒**：SChannel 层默认关闭，是纯增量。`getConn` 的握手已改为 `handshakeOrderedH1TLS`，升级后
> 若官方重写该函数，需把这一层重新接回。

---

# 改动主题七：OpenAI 兼容出站保留请求头顺序 + SChannel 收窄到仅 Codex 源

> 本主题两处改动作用域不同：
> - **A（头顺序）**：作用于**所有** OpenAI 兼容出站，无条件启用（靠 ctx 里有无捕获的头顺序自动生效/回退）。
> - **B（SChannel 收窄）**：只作用于 **Codex 源**（含 Codex→OpenAI 兼容路径），把原先的进程级全局开关改为**按请求**在 context 上打标。

## A. OpenAI 兼容出站接入 ordered HTTP/1.1 头顺序

### 背景

改动主题三/四建好了「入站捕获头顺序 → context 透传 → ordered-h1 出站按序写入」链路，但 Codex/Claude executor
走的是 `NewUtlsHTTPClient`（内部包了 ordered-h1），而 **OpenAI 兼容 executor 走的是 `NewProxyAwareHTTPClient`**
（普通 `http.Transport`，HTTP/2 + 字母序头），因此经 OpenAI 兼容供应商转发时头顺序**从未被保留**。

### 实现

新增 `helps.NewOrderedH1ProxyClient(ctx, cfg, auth, timeout)`（`internal/runtime/executor/helps/proxy_helpers.go`）：
代理优先级与 `NewProxyAwareHTTPClient` 完全一致（`auth.ProxyURL` → `cfg.ProxyURL` → ctx roundtripper），
但把 transport 用 `sharedOrderedH1RoundTripper` 包一层，强制 HTTP/1.1 并按 context 里捕获的顺序写头。
**不含 utls 指纹层**（OpenAI 兼容供应商打的是任意第三方 base，从不打 utls 保护的
`api.anthropic.com` / `chatgpt.com`）。context 里无捕获顺序时，ordered-h1 透明回退到被包的 transport，
因此对每个请求都安全。

`openai_compat_executor.go` 中 **5 处** `NewProxyAwareHTTPClient` 全部替换为 `NewOrderedH1ProxyClient`
（Execute / executeImages / ExecuteStream / executeImagesStream / HttpRequest），`reporter.TrackHTTPClient`
包裹保持不变。

### 取舍

这些出站从可能的 HTTP/2 降级为 HTTP/1.1（头顺序保留只在 h1.1 成立；Codex/Claude 本就如此）。

## B. SChannel 开关从进程级全局改为按请求 context 门控

### 背景

改动主题六追加的 SChannel 出站 TLS，原实现是在 `NewUtlsHTTPClient` 里按 `cfg.SChannelTLS` 置一个**进程级全局**
原子标志，ordered-h1 握手时读它。问题：这会让**所有**经 ordered-h1 出站的源（Claude、Gemini 等）都套用
Codex 的 SChannel JA3，指纹张冠李戴；且是全局状态，非按请求。

### 实现

1. `sdk/cliproxy/executor/context.go`：新增 `WithSChannelTLS(ctx)` / `SChannelTLSFromContext(ctx)`
   （照搬既有 `WithDownstreamWebsocket` 模式）。
2. `internal/runtime/executor/helps/utls_client.go`：删除 `NewUtlsHTTPClient` 里的全局 `setSchannelTLSEnabled`。
3. `internal/runtime/executor/helps/ordered_h1_tls_windows.go` / `..._other.go`：`handshakeOrderedH1TLS` 去掉全局
   原子标志，改从 `req.Context()`（已作为参数传入）读 `SChannelTLSFromContext`。非 Windows 分支忽略该标记。
4. `internal/runtime/executor/schannel_gate.go`（新增）：`maybeMarkSChannelTLS(ctx, cfg, opts)`，
   仅当 `cfg.SChannelTLS` 为真**且** `opts.SourceFormat == "codex"` 时给 ctx 打标。
5. 打标点：`codex_executor.go` 的 Execute / executeCompact / ExecuteStream，以及 `openai_compat_executor.go`
   的 Execute / executeImages / ExecuteStream / executeImagesStream（覆盖 Codex→OpenAI 兼容路径）。
   `HttpRequest` 转发打的是 `chatgpt.com`（走 utls，非 ordered-h1），无需打标。

结果：SChannel 指纹只落在 Codex 源流量上；Claude/Gemini 等仍走标准 `crypto/tls`。前端开关文案与 YAML 键
（`schannel-tls`）不变。

## 涉及文件清单（本主题）

新增：
- `sdk/cliproxy/executor/context.go`（新增两个 helper，追加到既有文件）
- `internal/runtime/executor/schannel_gate.go`
- `internal/runtime/executor/schannel_gate_test.go`
- `internal/runtime/executor/helps/ordered_h1_proxy_client_test.go`

修改：
- `internal/runtime/executor/helps/proxy_helpers.go`（新增 `NewOrderedH1ProxyClient`）
- `internal/runtime/executor/helps/utls_client.go`（删除全局 SChannel 置位）
- `internal/runtime/executor/helps/ordered_h1_tls_windows.go` / `ordered_h1_tls_other.go`（改从 ctx 读标记）
- `internal/runtime/executor/helps/ordered_h1_schannel_ja3_windows_test.go`（实弹测试改为在 ctx 上打 `WithSChannelTLS`）
- `internal/runtime/executor/openai_compat_executor.go`（5 处出站换 client + 打标）
- `internal/runtime/executor/codex_executor.go`（3 处执行入口打标）

## 验证

```bash
cd /d/AIProject/CLIProxyAPI
GOOS=windows go build ./...
GOOS=linux   go build ./...
go vet ./internal/runtime/executor/... ./sdk/cliproxy/executor/...
go test ./internal/runtime/executor/...   # 含新增：compat 头顺序保留 + 回退、SChannel 仅 codex 源打标
```
Windows + Linux 均编译通过，`go vet` 干净，全部单测绿。

> **升级套用提醒**：A 的核心是「compat 5 处 `NewProxyAwareHTTPClient` → `NewOrderedH1ProxyClient`」，
> 升级后用 `grep 'NewProxyAwareHTTPClient' openai_compat_executor.go` 复核是否被官方改回。
> B 依赖 `handshakeOrderedH1TLS` 从 `req.Context()` 读标记，与主题六的「握手已改为 handshakeOrderedH1TLS」联动，
> 若官方重写握手需一并接回 ctx 读取。

---

## 追加改动：可选的 Claude JA3 自动刷新（后端）

### 背景

管理面板 AI 供应商页需要在打开 Claude 供应商时，检测本机内置 Claude Desktop CLI
（`%LOCALAPPDATA%\Claude-3p\claude-code\<版本>\claude.exe`）的版本号，并在版本升级时
自动重采集 JA3 指纹。为此后端补两件事：一个只读的版本探测端点，一个总开关。

### 修改文件

- `internal/fingerprint/capture.go`（新增导出函数 `DetectClaudeVersion`）
- `internal/api/handlers/management/claude_ja3.go`（新增 `GetClaudeCLIVersion` handler）
- `internal/api/server.go`（注册 `GET /v0/management/claude-ja3/cli-version`）
- `internal/config/config.go`（新增顶层布尔 `claude-ja3-auto-refresh`，默认 false）

### 实现

1. `DetectClaudeVersion()` 复用既有 `defaultClaudePath()`，只读安装布局、**不启动进程**，
   返回最新版本目录名；非 Windows 返回 unsupported 错误（与自动探测采集一致）。
2. `GetClaudeCLIVersion` 端点始终返回 200：探测成功 `{"detected":true,"version":"x.y.z"}`，
   失败 `{"detected":false,"error":"..."}`（前端据此静默跳过）。
3. 新增顶层布尔 `claude-ja3-auto-refresh`（`yaml:"claude-ja3-auto-refresh"`），默认 false。
   前端据此决定是否显示「刷新 JA3」按钮与是否自动刷新；关闭时前端不渲染任何相关 UI，
   也不发探测请求。该字段随 `/config` 原样透传（顶层布尔与 `schannel-tls` 同族）。

### 验证

```bash
cd /d/AIProject/CLIProxyAPI
GOOS=windows go build ./...   # ok
GOOS=linux   go build ./...   # ok
go vet ./internal/...         # clean
```

---

## 追加改动：Claude JA3 采集在服务进程下挂起的修复（capture.go 加固）

### 背景

管理面板点「刷新 JA3」后，后端 `POST /v0/management/claude-ja3/capture` 会启动本机
`claude.exe`、抓取其 ClientHello 后立即断开。实际部署时反馈：采集**必现超时**（服务日志
`502 | 1m0s`），而在开发者终端里手动跑同样的采集却每次秒成功。

### 根因

内置的 Claude Desktop CLI 装在 `%LOCALAPPDATA%\Claude-3p\claude-code\<版本>\claude.exe`，
它是**第三方（3p）构建**，设计上作为 Claude Desktop 的子进程运行——Claude Desktop 启动它时
**总会传 `CLAUDE_CODE_ENTRYPOINT=claude-desktop-3p`**。缺这个环境变量时，该构建会在启动阶段
**静默挂起**：既不打印 stderr，也不向外拨号，直到超时被杀。

采集代码用 `append(os.Environ(), ...)` 继承父进程环境。开发者在终端里跑过一次 `claude`，
shell 便继承了这个变量，于是子进程也拿得到、采集成功；而 CPA 作为独立服务启动时环境里
**没有**这个变量（实测该变量既未写入 HKCU\Environment 也未写入系统环境，只存在于
交互式会话的进程内存），子进程拿不到，必现挂起。定位方法：对完整环境做二分/逐删，
`CLAUDE_CODE_ENTRYPOINT=claude-desktop-3p` 单独一项即可让采集从「挂起 6/6」变为「成功 5/5」，
确定性复现。

### 修改文件

- `internal/fingerprint/capture.go`

### 实现

1. **根因修复**：`proc.Env` 显式注入 `CLAUDE_CODE_ENTRYPOINT=claude-desktop-3p`，使采集
   不再依赖服务进程恰好继承到该变量。同时补 `CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1`、
   `CI=1`、`IS_DEMO=1`，并给 stdin 喂 EOF（`strings.NewReader("")`），压掉首次运行/标题等
   交互路径。
2. **受控工作目录**：`CaptureOptions` 新增 `WorkDir` 字段；为空时创建一个受控空临时目录并
   把 `proc.Dir` 指向它，采集后带重试删除（`removeWithRetry`，容忍 Windows 下刚被杀的子进程
   仍短暂占用 cwd 句柄）。这样采集不再继承服务器 cwd，也不会因该目录未受信而卡「trust this
   folder?」。
3. **预置信任/审批**：原 `approveAPIKey` 扩展为 `prepareClaudeJSON(key, workDir)`，在**同一次**
   读写 `~/.claude.json` 里既预批 dummy key，又把 workDir 标记为已信任/已引导
   （`hasTrustDialogAccepted` 等，合并而非覆盖已有条目），配对的 restore 采集后逐字节还原。
4. **诊断日志与错误分类**：保留 stderr 并跟踪子进程是否曾拨号（`dialed`）、是否已退出
   （非阻塞查 `exitCh`）。超时/早退时按 logrus `Warn` 输出 `pid/elapsed/connected/exited/stderr`，
   并把返回错误区分为三类可行动的原因：已连接但无可读 ClientHello（读/TLS 问题）、从未连接且
   仍在运行（卡交互提示/冷启动）、从未连接且已退出（静默死亡，附 stderr）。

### 验证

```bash
cd /d/AIProject/CLIProxyAPI
GOOS=windows go build ./...   # ok
GOOS=linux   go build ./...   # ok
go vet ./internal/...         # clean
```

在**剥离全部 `CLAUDE_CODE_*` 的干净环境**下运行真实采集（模拟服务进程），现可稳定拿到
JA3（`e97f5146a7009cc2918b50e903b6ff8d`），exit=0；`~/.claude.json` 采集后逐字节还原、
无残留临时目录。
