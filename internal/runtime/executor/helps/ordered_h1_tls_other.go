//go:build !windows

package helps

import (
	"context"
	"crypto/tls"
	"net"
)

// handshakeOrderedH1TLS performs the TLS handshake for an ordered-h1
// connection using the standard library. The windows build tag provides a
// variant that can use SChannel instead when the request context opts in via
// executor.WithSChannelTLS. SChannel does not exist on non-Windows platforms,
// so the context flag is ignored here.
func handshakeOrderedH1TLS(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	if c, err, ok := handshakeClaudeH1TLS(ctx, conn, serverName); ok {
		return c, err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
