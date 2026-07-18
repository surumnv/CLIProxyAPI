package helps

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

// rawHeadServer accepts a single HTTP/1.1 request on a raw TCP socket, captures
// the exact header lines as received on the wire (order preserved), replies
// 200, and reports the captured order on headCh.
func rawHeadServer(t *testing.T, headCh chan<- []string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var lines []string
		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			lines = append(lines, trimmed)
		}
		headCh <- lines
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	return ln
}

func TestNewOrderedH1ProxyClientPreservesHeaderOrder(t *testing.T) {
	t.Parallel()

	headCh := make(chan []string, 1)
	ln := rawHeadServer(t, headCh)
	defer ln.Close()

	client := NewOrderedH1ProxyClient(context.Background(), &config.Config{}, nil, 0)

	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "user-agent", RawName: "User-Agent"},
		{LowerName: "x-codex-marker", RawName: "X-Codex-Marker"},
		{LowerName: "content-length", RawName: "Content-Length"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/v1/chat", strings.NewReader("hi"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", "ordered-h1-proxy-test")
	req.Header.Set("X-Codex-Marker", "codex")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	head := <-headCh
	want := []string{
		"POST /v1/chat HTTP/1.1",
		"Host: " + ln.Addr().String(),
		"User-Agent: ordered-h1-proxy-test",
		"X-Codex-Marker: codex",
		"Content-Length: 2",
	}
	if len(head) != len(want) {
		t.Fatalf("head line count = %d, want %d\ngot: %v", len(head), len(want), head)
	}
	for i := range want {
		if head[i] != want[i] {
			t.Fatalf("head[%d] = %q, want %q\nfull: %v", i, head[i], want[i], head)
		}
	}
}

// Without a captured header order the ordered-h1 transport must transparently
// fall back to the standard transport, so the request still succeeds.
func TestNewOrderedH1ProxyClientFallsBackWithoutOrder(t *testing.T) {
	t.Parallel()

	headCh := make(chan []string, 1)
	ln := rawHeadServer(t, headCh)
	defer ln.Close()

	client := NewOrderedH1ProxyClient(context.Background(), &config.Config{}, nil, 0)

	req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/v1/chat", strings.NewReader("hi"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", "fallback-test")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", string(body), "ok")
	}
	// Drain the captured head so the server goroutine can finish.
	<-headCh
}
