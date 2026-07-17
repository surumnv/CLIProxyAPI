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
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

func TestBuildOrderedH1RequestUsesOriginalPositionsWithFinalValues(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://upstream.example/v1/messages?beta=true", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer final-token")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ordered-h1-test")
	req.Header.Set("X-Extra", "added-by-proxy")

	lines := []util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "user-agent", RawName: "User-Agent"},
		{LowerName: "authorization", RawName: "Authorization"},
		{LowerName: "accept-encoding", RawName: "Accept-Encoding"},
		{LowerName: "content-type", RawName: "Content-Type"},
		{LowerName: "content-length", RawName: "Content-Length"},
	}

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	head := string(raw[:strings.Index(string(raw), "\r\n\r\n")])
	gotLines := strings.Split(head, "\r\n")
	want := []string{
		"POST /v1/messages?beta=true HTTP/1.1",
		"Host: upstream.example",
		"User-Agent: ordered-h1-test",
		"Authorization: Bearer final-token",
		"Accept-Encoding: gzip",
		"Content-Type: application/json",
		"Content-Length: 11",
		"X-Extra: added-by-proxy",
	}
	if len(gotLines) != len(want) {
		t.Fatalf("line count = %d, want %d\n%s", len(gotLines), len(want), head)
	}
	for i := range want {
		if gotLines[i] != want[i] {
			t.Fatalf("line[%d] = %q, want %q\nfull:\n%s", i, gotLines[i], want[i], head)
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

func TestOrderedH1RoundTripperDropsExpiredIdleConnection(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var accepts atomic.Int32
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
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
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
		{LowerName: "content-length", RawName: "Content-Length"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)

	doOnce := func() {
		req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/expire", strings.NewReader("x"))
		if errReq != nil {
			t.Fatalf("NewRequest: %v", errReq)
		}
		resp, errDo := client.Do(req)
		if errDo != nil {
			t.Fatalf("Do: %v", errDo)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	doOnce()
	if got := accepts.Load(); got != 1 {
		t.Fatalf("accepted connections after first request = %d, want 1", got)
	}

	key := "http://" + ln.Addr().String()
	rt.mu.Lock()
	idle := rt.idle[key]
	if len(idle) != 1 {
		rt.mu.Unlock()
		t.Fatalf("idle connections = %d, want 1", len(idle))
	}
	idle[0].idleAt = time.Now().Add(-orderedH1IdleTimeout - time.Second)
	rt.mu.Unlock()

	doOnce()
	if got := accepts.Load(); got != 2 {
		t.Fatalf("accepted connections after expired idle = %d, want 2", got)
	}
}

func TestSharedOrderedH1RoundTripperSeparatesFallbackTransports(t *testing.T) {
	t.Parallel()

	fallbackA := &http.Transport{}
	fallbackB := &http.Transport{}
	rtA1 := sharedOrderedH1RoundTripper("", fallbackA)
	rtA2 := sharedOrderedH1RoundTripper("", fallbackA)
	rtB := sharedOrderedH1RoundTripper("", fallbackB)

	if rtA1 != rtA2 {
		t.Fatal("expected same shared transport for identical proxyURL+fallback")
	}
	if rtA1 == rtB {
		t.Fatal("expected different shared transports for different fallback instances")
	}
}

func TestOrderedH1RoundTripperStreamsKnownLengthBody(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return
		}
		defer conn.Close()
		req, errRead := http.ReadRequest(bufio.NewReader(conn))
		if errRead != nil {
			return
		}
		data, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		received <- string(data)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	rt := newOrderedH1RoundTripper("", nil).(*orderedH1RoundTripper)
	defer rt.CloseIdleConnections()
	client := &http.Client{Transport: rt}
	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "content-length", RawName: "Content-Length"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)

	payload := strings.Repeat("stream-body-", 1024)
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/stream", strings.NewReader(payload))
	if errReq != nil {
		t.Fatalf("NewRequest: %v", errReq)
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		t.Fatalf("Do: %v", errDo)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case got := <-received:
		if got != payload {
			t.Fatalf("upstream body length = %d, want %d", len(got), len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream body")
	}
}

func TestOrderedH1RoundTripperPreservesZeroContentLengthBody(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return
		}
		defer conn.Close()
		req, errRead := http.ReadRequest(bufio.NewReader(conn))
		if errRead != nil {
			return
		}
		data, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		received <- string(data)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	rt := newOrderedH1RoundTripper("", nil).(*orderedH1RoundTripper)
	defer rt.CloseIdleConnections()
	client := &http.Client{Transport: rt}
	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "content-length", RawName: "Content-Length"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)

	payload := "zero-content-length-still-has-body"
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/unknown", nil)
	if errReq != nil {
		t.Fatalf("NewRequest: %v", errReq)
	}
	req.Body = io.NopCloser(strings.NewReader(payload))
	req.ContentLength = 0

	resp, errDo := client.Do(req)
	if errDo != nil {
		t.Fatalf("Do: %v", errDo)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case got := <-received:
		if got != payload {
			t.Fatalf("upstream body = %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream body")
	}
}

func TestOrderedH1DialRespectsContextCancel(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Accept but never complete the HTTP exchange; we only care that dial itself is cancelable
	// before connecting to a black hole. Use a non-routable address with a short canceled context.
	rt := newOrderedH1RoundTripper("", nil).(*orderedH1RoundTripper)
	defer rt.CloseIdleConnections()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, "http://203.0.113.1:9/", nil)
	if errReq != nil {
		t.Fatalf("NewRequest: %v", errReq)
	}
	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{{LowerName: "host", RawName: "Host"}})
	req = req.WithContext(util.WithOriginalHeaderOrder(req.Context(), order))

	_, errDial := rt.dial(req)
	if errDial == nil {
		t.Fatal("expected canceled dial to fail")
	}
	if !strings.Contains(errDial.Error(), "canceled") && ctx.Err() == nil {
		t.Fatalf("expected context cancellation error, got %v", errDial)
	}
}
