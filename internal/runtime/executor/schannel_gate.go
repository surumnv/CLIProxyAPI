package executor

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
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

// maybeMarkSChannelTLS opts the outbound request context into the SChannel-backed
// ordered-HTTP/1.1 TLS handshake (matching the Codex CLI JA3) when both hold:
//   - the schannel-tls config toggle is on, and
//   - the inbound request originated from a Codex client (opts.SourceFormat is
//     one of codexSourceFormats).
//
// This keeps the SChannel fingerprint confined to Codex traffic — including the
// Codex→OpenAI-compatible (Responses→Chat) path — while Claude and other sources
// keep the standard crypto/tls handshake. Ignored on non-Windows platforms.
func maybeMarkSChannelTLS(ctx context.Context, cfg *config.Config, opts cliproxyexecutor.Options) context.Context {
	if cfg == nil || !cfg.SChannelTLS {
		return ctx
	}
	if !isCodexSourceFormat(opts) {
		return ctx
	}
	return cliproxyexecutor.WithSChannelTLS(ctx)
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
