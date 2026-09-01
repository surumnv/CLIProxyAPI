//go:build windows

package helps

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/schannel"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// handshakeOrderedH1TLS performs the outbound TLS handshake for an ordered-h1
// connection. When the request context opted into SChannel mode (via
// executor.WithSChannelTLS, set only for Codex-originated requests when the
// schannel-tls toggle is on) it hands the raw connection to the Windows
// SChannel provider so CPA's ClientHello (JA3) matches the Codex CLI, which
// also uses SChannel via native-tls. A Codex client running under WSL2/Linux
// links OpenSSL instead, so it opts into executor.WithCodexLinuxFingerprint and
// is served by handshakeCodexLinuxH1TLS. Otherwise it falls back to Go's
// crypto/tls. The returned net.Conn is the encrypted stream; ordered-h1
// continues to write the HTTP/1.1 head and body onto it in captured order, so
// header-order preservation is unaffected.
func handshakeOrderedH1TLS(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	// A Codex client running under WSL2/Linux uses OpenSSL, not SChannel, so its
	// fingerprint branch is checked first. The two markers are mutually exclusive
	// (the gate picks one from the inbound User-Agent), but ordering makes that
	// explicit rather than incidental.
	if c, err, ok := handshakeCodexLinuxH1TLS(ctx, conn, serverName); ok {
		return c, err
	}
	if cliproxyexecutor.SChannelTLSFromContext(ctx) {
		// EnabledProtocols=0 → SChannel default (legacy struct: TLS 1.2 max, no
		// GREASE). ALPNProtocols empty → no ALPN extension. This exactly
		// reproduces the Codex CLI JA3 6a5d235ee78c6aede6a61448b4e9ff1e.
		return schannel.Client(conn, schannel.Config{ServerName: serverName})
	}
	if c, err, ok := handshakeClaudeH1TLS(ctx, conn, serverName); ok {
		return c, err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
