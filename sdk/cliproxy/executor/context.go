package executor

import "context"

type downstreamWebsocketContextKey struct{}

// WithDownstreamWebsocket marks the current request as coming from a downstream websocket connection.
func WithDownstreamWebsocket(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, downstreamWebsocketContextKey{}, true)
}

// DownstreamWebsocket reports whether the current request originates from a downstream websocket connection.
func DownstreamWebsocket(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	raw := ctx.Value(downstreamWebsocketContextKey{})
	enabled, ok := raw.(bool)
	return ok && enabled
}

type schannelTLSContextKey struct{}

// WithSChannelTLS marks the current outbound request to perform its
// ordered-HTTP/1.1 TLS handshake via the Windows SChannel provider (matching
// the Codex CLI JA3). It is only set for Codex-originated requests when the
// schannel-tls config toggle is on; other sources keep the standard crypto/tls
// path. Ignored on non-Windows platforms.
func WithSChannelTLS(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, schannelTLSContextKey{}, true)
}

// SChannelTLSFromContext reports whether the current request opted into the
// SChannel-backed TLS handshake via WithSChannelTLS.
func SChannelTLSFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, ok := ctx.Value(schannelTLSContextKey{}).(bool)
	return ok && enabled
}

type claudeFingerprintContextKey struct{}

// WithClaudeFingerprint marks the current outbound request so Claude TLS
// handshakes reproduce the captured Claude Code ClientHello (JA3) via utls,
// instead of the default Chrome / crypto/tls path. It is set for Claude-
// originated upstream traffic when claude-ja3-auto-refresh is on and a
// fingerprint is configured. The marker is consumed by:
//   - the official api.anthropic.com HTTP/2 utls path, and
//   - third-party ordered-HTTP/1.1 hosts, where the host alone is not a
//     reliable signal that the request is Claude-bound.
// Mirrors WithSChannelTLS.
func WithClaudeFingerprint(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, claudeFingerprintContextKey{}, true)
}

// ClaudeFingerprintFromContext reports whether the current request opted into
// the captured Claude ClientHello via WithClaudeFingerprint.
func ClaudeFingerprintFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, ok := ctx.Value(claudeFingerprintContextKey{}).(bool)
	return ok && enabled
}

type lowercaseHeadersContextKey struct{}

// WithLowercaseHeaders marks the current outbound request so the ordered-HTTP/1.1
// writer lowercases every emitted header name. The real Codex client
// (reqwest/hyper) stores header names in http::HeaderMap lowercase and writes
// them to the wire verbatim, so any header CPA generates itself (e.g. via the
// fallback branch, or Host/Content-Length) must also be lowercased to match.
//
// It is only set for Codex-originated requests. It must NOT be set for Claude
// (undici) traffic: real Claude header names are mixed-case (X-Stainless-*,
// User-Agent Title-Case; anthropic-*, x-app lowercase), so lowercasing them
// would diverge from the genuine client. See WithSChannelTLS for the sibling
// per-source gating pattern.
func WithLowercaseHeaders(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, lowercaseHeadersContextKey{}, true)
}

// LowercaseHeadersFromContext reports whether the current request opted into
// lowercase outbound header names via WithLowercaseHeaders.
func LowercaseHeadersFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, ok := ctx.Value(lowercaseHeadersContextKey{}).(bool)
	return ok && enabled
}
