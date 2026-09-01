package helps

import (
	"context"
	"net"

	utls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// handshakeCodexLinuxH1TLS performs the ordered-HTTP/1.1 TLS handshake using the
// declared Linux Codex CLI ClientHello shape (JA3 0b85eb0d4981e69064e40753e4f0ac5f)
// via utls. It only acts when the request opted in via
// executor.WithCodexLinuxFingerprint, which the Codex gate sets when the inbound
// User-Agent reports a non-Windows OS; ok=false means the caller should fall
// through to its default handshake (SChannel on Windows, crypto/tls elsewhere).
//
// No ALPN is advertised, because the real client advertises none: reqwest's
// default TLS backend resolves to OpenSSL on Linux and Codex configures no ALPN,
// so the genuine wire image negotiates no protocol and speaks HTTP/1.1. That is
// exactly what the ordered-h1 transport writes onto the returned connection, so
// header-order preservation is unaffected.
//
// This is the Linux sibling of the SChannel branch used for Windows Codex
// clients: same per-request gating, same "encrypted stream returned; ordered-h1
// writes the HTTP/1.1 head onto it afterwards" contract. It is platform
// independent by design — CPA runs on Windows while the Codex client runs under
// WSL2, so the Linux-shaped handshake must be available in the Windows build.
func handshakeCodexLinuxH1TLS(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error, bool) {
	if !cliproxyexecutor.CodexLinuxFingerprintFromContext(ctx) {
		return nil, nil, false
	}
	spec := fingerprint.CodexLinuxSpecH1()
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
