package management

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestIsCodexModelsFetch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		method  string
		rawURL  string
		headers map[string]string
		want    bool
	}{
		{name: "v1 models get", method: "GET", rawURL: "https://api.example.com/v1/models", want: true},
		{name: "bare models get", method: "GET", rawURL: "https://api.example.com/models", want: true},
		{name: "models with query", method: "GET", rawURL: "https://api.example.com/v1/models?client_version=0.145.0", want: true},
		{name: "trailing slash", method: "GET", rawURL: "https://api.example.com/v1/models/", want: true},
		{name: "not get", method: "POST", rawURL: "https://api.example.com/v1/models", want: false},
		{name: "not models path", method: "GET", rawURL: "https://api.example.com/v1/chat/completions", want: false},
		{name: "claude excluded", method: "GET", rawURL: "https://api.anthropic.com/v1/models", headers: map[string]string{"Anthropic-Version": "2023-06-01"}, want: false},
		{name: "gemini excluded", method: "GET", rawURL: "https://x/v1/models", headers: map[string]string{"X-Goog-Api-Key": "k"}, want: false},
		{name: "grok excluded", method: "GET", rawURL: "https://x/v1/models", headers: map[string]string{"X-Xai-Token-Auth": "t"}, want: false},
		{name: "x-api-key excluded", method: "GET", rawURL: "https://x/v1/models", headers: map[string]string{"X-Api-Key": "k"}, want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			hdr := http.Header{}
			for k, v := range tc.headers {
				hdr.Set(k, v)
			}
			if got := isCodexModelsFetch(tc.method, parsed, hdr); got != tc.want {
				t.Fatalf("isCodexModelsFetch = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyCodexModelsHeadersStripsExtras(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Custom", "should-be-dropped")

	applyCodexModelsHeaders(req)

	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("authorization = %q, want preserved", got)
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Fatalf("accept = %q, want */*", got)
	}
	if got := req.Header.Get("Originator"); got != codexCLIOriginator {
		t.Fatalf("originator = %q, want %q", got, codexCLIOriginator)
	}
	if req.Header.Get("User-Agent") == "" {
		t.Fatal("user-agent must be set")
	}
	for _, dropped := range []string{"Content-Type", "Accept-Encoding", "X-Custom"} {
		if v := req.Header.Get(dropped); v != "" {
			t.Fatalf("%s = %q, want dropped", dropped, v)
		}
	}
}

func TestApplyCodexModelsHeadersPreservesProvidedOriginatorAndUA(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Originator", "codex_cli_rs")
	req.Header.Set("User-Agent", "custom-ua/1.0")

	applyCodexModelsHeaders(req)

	if got := req.Header.Get("User-Agent"); got != "custom-ua/1.0" {
		t.Fatalf("user-agent = %q, want preserved", got)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("authorization must be absent when not provided")
	}
}

// TestCodexModelsWireHeadMatchesCapture drives a request through the exact
// production transport wiring (applyCodexModelsHeaders + synthetic order +
// lowercase context + shared ordered-h1) and asserts the on-wire head equals a
// real codex_cli_rs GET /v1/models capture: lowercase names, codex order, no
// accept-encoding, no content-type.
func TestCodexModelsWireHeadMatchesCapture(t *testing.T) {
	headCh := make(chan []string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
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

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/v1/models?client_version=0.145.0", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("User-Agent", "codex_cli_rs/0.145.0 (Windows 10.0.26200; x86_64) WindowsTerminal")

	applyCodexModelsHeaders(req)

	order := &util.OriginalHeaderOrder{}
	order.Set(codexModelsWireOrder())
	ctx := util.WithOriginalHeaderOrder(req.Context(), order)
	ctx = cliproxyexecutor.WithLowercaseHeaders(ctx)
	req = req.WithContext(ctx)

	client := &http.Client{Transport: helps.SharedOrderedH1RoundTripper("", buildOrderedH1Fallback(""))}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	head := <-headCh
	want := []string{
		"GET /v1/models?client_version=0.145.0 HTTP/1.1",
		"accept: */*",
		"originator: codex_cli_rs",
		"user-agent: codex_cli_rs/0.145.0 (Windows 10.0.26200; x86_64) WindowsTerminal",
		"authorization: Bearer sk-test",
		"host: " + ln.Addr().String(),
	}
	if len(head) != len(want) {
		t.Fatalf("head line count = %d, want %d\ngot: %v", len(head), len(want), head)
	}
	for i := range want {
		if head[i] != want[i] {
			t.Fatalf("head[%d] = %q, want %q\nfull: %v", i, head[i], want[i], head)
		}
	}
	// Guard against Go's stdlib auto-injections that must not appear.
	for _, line := range head {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "accept-encoding:") {
			t.Fatalf("accept-encoding must not be sent, got %q", line)
		}
		if strings.HasPrefix(lower, "content-type:") {
			t.Fatalf("content-type must not be sent on GET, got %q", line)
		}
	}
}
