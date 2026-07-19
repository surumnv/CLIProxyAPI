package helps

import (
	"context"
	"net"

	utls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// handshakeClaudeH1TLS performs the ordered-HTTP/1.1 TLS handshake using the
// captured Claude Code ClientHello (JA3) via utls, ALPN forced to http/1.1 to
// match the third-party relay path. It only acts when the request opted in via
// executor.WithClaudeFingerprint (set by the Claude executor for its upstream
// traffic) and a fingerprint is actually configured; ok=false means the caller
// should fall through to its default handshake (SChannel or crypto/tls).
//
// This is the Claude sibling of the SChannel branch used for Codex: same
// per-source gating, same "encrypted stream returned; ordered-h1 writes the
// HTTP/1.1 head onto it afterwards" contract, so header-order preservation is
// unaffected.
func handshakeClaudeH1TLS(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error, bool) {
	if !cliproxyexecutor.ClaudeFingerprintFromContext(ctx) {
		return nil, nil, false
	}
	spec := fingerprint.ClaudeSpecH1()
	if spec == nil {
		return nil, nil, false
	}
	uconn := utls.UClient(conn, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, err, true
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err, true
	}
	return uconn, nil, true
}
