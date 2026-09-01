package executor

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// codexSourceFormats lists the inbound protocol labels that mark a request as
// Codex-originated.
//
// FormatCodex is the native label, kept for SDK and plugin callers that set it
// explicitly. FormatOpenAIResponse is the label real Codex traffic actually
// carries: the Codex client posts to /v1/responses, whose handler reports
// HandlerType() == constant.OpenaiResponse, and that value is what reaches the
// executor as opts.SourceFormat. Matching only FormatCodex therefore never
// fired for a real inbound request. The same pair is treated as one family in
// sdk/cliproxy/session/identity.go.
var codexSourceFormats = []sdktranslator.Format{
	sdktranslator.FormatCodex,
	sdktranslator.FormatOpenAIResponse,
}

// isCodexSourceFormat reports whether the inbound protocol label of opts marks
// the request as Codex-originated. An empty label never matches.
func isCodexSourceFormat(opts cliproxyexecutor.Options) bool {
	for _, candidate := range codexSourceFormats {
		if sourceFormatEqual(opts.SourceFormat, candidate) {
			return true
		}
	}
	return false
}

// codexClientOS reports the OS family of the Codex client that sent the inbound
// request, read from its User-Agent.
//
// The client OS matters because CPA runs on Windows while the Codex client may
// run inside WSL2/Linux, and the two Codex builds emit different TLS
// ClientHellos: the Codex HTTP client keeps reqwest's default TLS backend
// (codex-rs/http-client/client_builder.rs), which is native-tls, and native-tls
// maps to SChannel on Windows and to OpenSSL on Linux. CPA cannot inspect the
// client machine, so the inbound UA is the only available signal.
//
// opts.Headers carries the real inbound headers: the API layer fills it from the
// gin request (sdk/api/handlers/model_execution.go, modelExecutionHeaders).
func codexClientOS(opts cliproxyexecutor.Options) helps.CodexClientOS {
	if opts.Headers == nil {
		return helps.CodexClientOSUnknown
	}
	return helps.CodexClientOSFromUserAgent(opts.Headers.Get("User-Agent"))
}

// maybeMarkSChannelTLS opts the outbound request context into the SChannel-backed
// ordered-HTTP/1.1 TLS handshake (matching the Windows Codex CLI JA3) when all of
// these hold:
//   - the schannel-tls config toggle is on,
//   - the inbound request originated from a Codex client (opts.SourceFormat is
//     one of codexSourceFormats), and
//   - that client is not known to be non-Windows.
//
// This keeps the SChannel fingerprint confined to Codex traffic — including the
// Codex→OpenAI-compatible (Responses→Chat) path — while Claude and other sources
// keep the standard crypto/tls handshake. Ignored on non-Windows platforms.
//
// A client that reports a non-Windows OS is excluded because SChannel would
// advertise the wrong fingerprint for it; those requests are routed to the
// declared OpenSSL-shaped ClientHello by maybeMarkCodexLinuxFingerprint instead. An
// unknown/absent UA keeps the historical SChannel behaviour, since CPA itself
// runs on Windows.
func maybeMarkSChannelTLS(ctx context.Context, cfg *config.Config, opts cliproxyexecutor.Options) context.Context {
	if cfg == nil || !cfg.SChannelTLS {
		return ctx
	}
	if !isCodexSourceFormat(opts) {
		return ctx
	}
	if codexClientOS(opts) == helps.CodexClientOSNonWindows {
		return ctx
	}
	return cliproxyexecutor.WithSChannelTLS(ctx)
}

// maybeMarkCodexLinuxFingerprint opts the outbound request context into using
// the declared Linux Codex ClientHello shape (OpenSSL shaped, JA3
// 0b85eb0d4981e69064e40753e4f0ac5f) on the ordered-HTTP/1.1 path when all of
// these hold:
//   - the schannel-tls config toggle is on,
//   - the inbound request originated from a Codex client, and
//   - that client reported a non-Windows OS in its User-Agent.
//
// It is the exact complement of maybeMarkSChannelTLS: for any given request at
// most one of the two markers is set, so a Codex client gets the fingerprint of
// the platform it actually runs on. The shared toggle keeps one operator-facing
// switch meaning "align Codex outbound TLS with the real Codex client" rather
// than splitting it per platform.
func maybeMarkCodexLinuxFingerprint(ctx context.Context, cfg *config.Config, opts cliproxyexecutor.Options) context.Context {
	if cfg == nil || !cfg.SChannelTLS {
		return ctx
	}
	if !isCodexSourceFormat(opts) {
		return ctx
	}
	if codexClientOS(opts) != helps.CodexClientOSNonWindows {
		return ctx
	}
	return cliproxyexecutor.WithCodexLinuxFingerprint(ctx)
}

// maybeMarkClaudeFingerprint opts the outbound request context into the captured
// Claude Code ClientHello (JA3) when both hold:
//   - the claude-ja3-auto-refresh config toggle is on, and
//   - a fingerprint has been configured via the management API.
//
// The marker is used by:
//   - the ordered-HTTP/1.1 (third-party relay) handshake helper, and
//   - the official api.anthropic.com HTTP/2 utls path, which only applies the
//     captured ClientHello when this opt-in is present.
//
// It is called from the Claude executor, so every request it marks is
// Claude-bound. When the toggle is off or no fingerprint is configured the
// marker is not set and handshakes fall back to the default TLS path.
func maybeMarkClaudeFingerprint(ctx context.Context, cfg *config.Config) context.Context {
	if cfg == nil || !cfg.ClaudeJA3AutoRefresh {
		return ctx
	}
	if !fingerprint.HasClaudeSpec() {
		return ctx
	}
	return cliproxyexecutor.WithClaudeFingerprint(ctx)
}

// maybeMarkLowercaseHeaders opts the outbound request into lowercase header
// names in the ordered-HTTP/1.1 writer when the inbound request originated from
// a Codex client (opts.SourceFormat is one of codexSourceFormats). Real Codex
// (reqwest/hyper) emits lowercase header names on the wire, so CPA-generated
// headers must match.
//
// This is intentionally Codex-only: Claude (undici) sends mixed-case header
// names on the wire, and lowercasing them would create a fingerprint mismatch.
// Unlike maybeMarkSChannelTLS there is no config toggle — lowercasing is always
// the correct wire image for Codex.
func maybeMarkLowercaseHeaders(ctx context.Context, opts cliproxyexecutor.Options) context.Context {
	if !isCodexSourceFormat(opts) {
		return ctx
	}
	return cliproxyexecutor.WithLowercaseHeaders(ctx)
}
