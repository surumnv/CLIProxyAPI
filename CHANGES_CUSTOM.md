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

