package executor

import (
	"context"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// codexSourceFormat is the inbound protocol label for Codex-originated requests.
const codexSourceFormat = "codex"

// maybeMarkSChannelTLS opts the outbound request context into the SChannel-backed
// ordered-HTTP/1.1 TLS handshake (matching the Codex CLI JA3) when both hold:
//   - the schannel-tls config toggle is on, and
//   - the inbound request originated from a Codex client (opts.SourceFormat == "codex").
//
// This keeps the SChannel fingerprint confined to Codex traffic — including the
// Codex→OpenAI-compatible (Responses→Chat) path — while Claude and other sources
// keep the standard crypto/tls handshake. Ignored on non-Windows platforms.
func maybeMarkSChannelTLS(ctx context.Context, cfg *config.Config, opts cliproxyexecutor.Options) context.Context {
	if cfg == nil || !cfg.SChannelTLS {
		return ctx
	}
	if !strings.EqualFold(strings.TrimSpace(opts.SourceFormat.String()), codexSourceFormat) {
		return ctx
	}
	return cliproxyexecutor.WithSChannelTLS(ctx)
}

// maybeMarkClaudeFingerprint opts the outbound request context into the captured
// Claude Code ClientHello (JA3) for the ordered-HTTP/1.1 (third-party relay)
// path, when a fingerprint has been configured via the management API. The
// official api.anthropic.com HTTP/2 path is gated by host inside the utls
// transport and does not need this marker.
//
// It is called from the Claude executor, so every request it marks is
// Claude-bound. When no fingerprint is configured the marker is harmless: the
// handshake helper falls back to the default TLS path.
func maybeMarkClaudeFingerprint(ctx context.Context) context.Context {
	if !fingerprint.HasClaudeSpec() {
		return ctx
	}
	return cliproxyexecutor.WithClaudeFingerprint(ctx)
}

// maybeMarkLowercaseHeaders opts the outbound request into lowercase header
// names in the ordered-HTTP/1.1 writer when the inbound request originated from
// a Codex client (opts.SourceFormat == "codex"). Real Codex (reqwest/hyper)
// emits lowercase header names on the wire, so CPA-generated headers must match.
//
// This is intentionally Codex-only: Claude (undici) sends mixed-case header
// names on the wire, and lowercasing them would create a fingerprint mismatch.
// Unlike maybeMarkSChannelTLS there is no config toggle — lowercasing is always
// the correct wire image for Codex.
func maybeMarkLowercaseHeaders(ctx context.Context, opts cliproxyexecutor.Options) context.Context {
	if !strings.EqualFold(strings.TrimSpace(opts.SourceFormat.String()), codexSourceFormat) {
		return ctx
	}
	return cliproxyexecutor.WithLowercaseHeaders(ctx)
}
