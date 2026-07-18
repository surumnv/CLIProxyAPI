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
