package helps

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

func TestBuildOrderedH1RequestUsesOriginalPositionsWithFinalValues(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://upstream.example/v1/messages?beta=true", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "target.example"
	req.Header.Set("User-Agent", "claude-cli/2.1.63")
	req.Header.Set("Authorization", "Bearer regenerated")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Client", "kept")
	req.Header.Set("X-New", "appended")

	lines := []util.OriginalHeaderLine{
		{LowerName: "host", RawName: "host"},
		{LowerName: "user-agent", RawName: "user-agent"},
		{LowerName: "authorization", RawName: "authorization"},
		{LowerName: "content-type", RawName: "content-type"},
		{LowerName: "accept-encoding", RawName: "accept-encoding"},
		{LowerName: "content-length", RawName: "content-length"},
		{LowerName: "x-client", RawName: "x-client"},
	}

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	head := string(raw[:strings.Index(string(raw), "\r\n\r\n")])
	gotLines := strings.Split(head, "\r\n")
	wantLines := []string{
		"POST /v1/messages?beta=true HTTP/1.1",
		"host: target.example",
		"user-agent: claude-cli/2.1.63",
		"authorization: Bearer regenerated",
		"content-type: application/json",
		"accept-encoding: identity",
		"content-length: 11",
		"x-client: kept",
		"X-New: appended",
	}
	if len(gotLines) != len(wantLines) {
		t.Fatalf("header lines = %#v, want %#v", gotLines, wantLines)
	}
	for i := range wantLines {
		if gotLines[i] != wantLines[i] {
			t.Fatalf("line[%d] = %q, want %q\nall lines: %#v", i, gotLines[i], wantLines[i], gotLines)
		}
	}
}

func TestOrderedH1RoundTripperReusesIdleConnection(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	var requests atomic.Int32
	go func() {
		for {
			conn, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					req, errRead := http.ReadRequest(reader)
					if errRead != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
					body := fmt.Sprintf("ok-%d", requests.Add(1))
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(body), body)
				}
			}(conn)
		}
	}()

	rt := newOrderedH1RoundTripper("", nil).(*orderedH1RoundTripper)
	defer rt.CloseIdleConnections()
	client := &http.Client{Transport: rt}
	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "user-agent", RawName: "User-Agent"},
		{LowerName: "content-length", RawName: "Content-Length"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)

	for i := 1; i <= 2; i++ {
		req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/reuse", strings.NewReader("body"))
		if errReq != nil {
			t.Fatalf("NewRequest %d: %v", i, errReq)
		}
		req.Header.Set("User-Agent", "ordered-h1-test")
		resp, errDo := client.Do(req)
		if errDo != nil {
			t.Fatalf("Do %d: %v", i, errDo)
		}
		data, errRead := io.ReadAll(resp.Body)
		if errRead != nil {
			t.Fatalf("ReadAll %d: %v", i, errRead)
		}
		if errClose := resp.Body.Close(); errClose != nil {
			t.Fatalf("Body.Close %d: %v", i, errClose)
		}
		if got, want := string(data), fmt.Sprintf("ok-%d", i); got != want {
			t.Fatalf("response %d = %q, want %q", i, got, want)
		}
	}

	if got := accepts.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want 1", got)
	}
}
