package api

import (
	"io"
	"net"
	"testing"
)

func TestHeaderOrderConnCapturesFirstRequestHeaderOrder(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	conn := newHeaderOrderConn(serverConn)
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("POST / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: codex\r\nContent-Length: 2\r\n\r\n{}"))
	}()

	_, _ = io.ReadAll(conn)
	lines := conn.OriginalHeaderOrder().Lines()
	if len(lines) != 3 {
		t.Fatalf("captured %d header lines, want 3: %#v", len(lines), lines)
	}
	if lines[0].RawName != "Host" || lines[1].RawName != "User-Agent" || lines[2].RawName != "Content-Length" {
		t.Fatalf("captured order = %#v", lines)
	}
}
