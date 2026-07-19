package helps

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// JA4H's `a` segment counts the request headers and its `b` segment hashes the
// ordered list of header NAMES (excluding Cookie/Referer). So an upstream relay
// computing JA4H sees a different hash the moment CPA emits even one header the
// genuine client does not send, or drops one it does. These tests lock the
// outbound header-NAME set to exactly what the real client puts on the wire:
// every name the client sent must survive to the wire, and CPA must not inject
// any extra name of its own. They are the HTTP-layer analogue of the JA3/JA4
// TLS-replay guarantee — a byte-for-byte match is worthless if the header set
// leaks the proxy.
//
// These operate on buildOrderedH1Request (the single funnel where every outbound
// header name is finalized) so they cover replayed inbound names, CPA-generated
// fallback names, and the transport-managed Host/Content-Length uniformly.

// outboundHeaderNames parses a built HTTP/1.1 request head and returns the
// lowercased set of header names on the wire (request line excluded). Lowercased
// so the assertion is about the NAME SET (JA4H's concern), independent of the
// casing policy that the mixed-case/lowercase tests already cover separately.
func outboundHeaderNames(t *testing.T, raw []byte) map[string]struct{} {
	t.Helper()
	sep := strings.Index(string(raw), "\r\n\r\n")
	if sep < 0 {
		t.Fatalf("no header terminator in built request:\n%s", raw)
	}
	head := string(raw[:sep])
	lines := strings.Split(head, "\r\n")
	if len(lines) < 1 {
		t.Fatalf("empty head")
	}
	names := make(map[string]struct{}, len(lines)-1)
	for _, line := range lines[1:] { // skip request line
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			t.Fatalf("malformed header line %q", line)
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		if _, dup := names[name]; dup {
			// A duplicate NAME changes JA4H's header count and hash too; surface it.
			t.Fatalf("duplicate header name %q on the wire\nfull:\n%s", name, head)
		}
		names[name] = struct{}{}
	}
	return names
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertHeaderNameSet fails with a symmetric diff (missing + unexpected) so a
// regression names exactly which header leaked or vanished.
func assertHeaderNameSet(t *testing.T, got map[string]struct{}, want []string) {
	t.Helper()
	wantSet := make(map[string]struct{}, len(want))
	for _, w := range want {
		wantSet[strings.ToLower(w)] = struct{}{}
	}
	var missing, unexpected []string
	for w := range wantSet {
		if _, ok := got[w]; !ok {
			missing = append(missing, w)
		}
	}
	for g := range got {
		if _, ok := wantSet[g]; !ok {
			unexpected = append(unexpected, g)
		}
	}
	if len(missing) > 0 || len(unexpected) > 0 {
		sort.Strings(missing)
		sort.Strings(unexpected)
		t.Fatalf("outbound header-name set mismatch (JA4H would differ)\n  missing (client sent, CPA dropped): %v\n  unexpected (CPA injected, client never sends): %v\n  got:  %v\n  want: %v",
			missing, unexpected, sortedKeys(got), func() []string { sort.Strings(want); return want }())
	}
}

// TestOrderedH1ClaudeHeaderNameSetMatchesClient models a genuine Claude Code
// (undici) request and asserts the outbound name set equals the inbound one. The
// inbound set here mirrors the 2026-07-19 bypass-CPA wire capture, including the
// undici transport tail (Connection, Host, Accept-Encoding, Content-Length).
func TestOrderedH1ClaudeHeaderNameSetMatchesClient(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://relay.example/v1/messages?beta=true", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	// The header NAMES a real Claude Code client puts on the wire.
	clientNames := []string{
		"Accept",
		"Authorization",
		"Content-Type",
		"User-Agent",
		"X-Claude-Code-Session-Id",
		"X-Stainless-Arch",
		"X-Stainless-Lang",
		"X-Stainless-OS",
		"X-Stainless-Package-Version",
		"X-Stainless-Retry-Count",
		"X-Stainless-Runtime",
		"X-Stainless-Runtime-Version",
		"X-Stainless-Timeout",
		"anthropic-beta",
		"anthropic-dangerous-direct-browser-access",
		"anthropic-version",
		"x-app",
		"Connection",
		"Host",
		"Accept-Encoding",
		"Content-Length",
	}

	// Replay lines carry the inbound order/casing; the executor sets the same
	// names on req.Header as authoritative values. We populate both so the build
	// funnel behaves exactly as in the live path.
	lines := make([]util.OriginalHeaderLine, 0, len(clientNames))
	for _, n := range clientNames {
		lines = append(lines, util.OriginalHeaderLine{LowerName: strings.ToLower(n), RawName: n})
		switch strings.ToLower(n) {
		case "host", "content-length":
			// Managed by the transport; not set on req.Header.
			continue
		default:
			req.Header.Set(n, "x")
		}
	}

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	got := outboundHeaderNames(t, raw)
	assertHeaderNameSet(t, got, clientNames)
}

// TestOrderedH1CodexHeaderNameSetMatchesClient does the same for a Codex
// (reqwest/hyper) request: lowercase names, NO Connection, NO Accept-Encoding.
// If a future change re-adds Connection or Accept-Encoding on the Codex path,
// or drops one of Codex's own headers, this fails before it ships.
func TestOrderedH1CodexHeaderNameSetMatchesClient(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://relay.example/v1/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req = req.WithContext(cliproxyexecutor.WithLowercaseHeaders(req.Context()))

	// Codex on-wire names (2026-07-19 capture order). Note: no connection,
	// no accept-encoding — reqwest with no decompression feature sends neither.
	clientNames := []string{
		"x-codex-beta-features",
		"originator",
		"x-codex-window-id",
		"x-codex-turn-metadata",
		"x-client-request-id",
		"session-id",
		"thread-id",
		"accept",
		"content-type",
		"authorization",
		"user-agent",
		"host",
		"content-length",
	}

	lines := make([]util.OriginalHeaderLine, 0, len(clientNames))
	for _, n := range clientNames {
		lines = append(lines, util.OriginalHeaderLine{LowerName: n, RawName: n})
		switch n {
		case "host", "content-length":
			continue
		default:
			req.Header.Set(n, "x")
		}
	}

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	got := outboundHeaderNames(t, raw)
	assertHeaderNameSet(t, got, clientNames)

	// Explicit belt-and-suspenders: the two headers a naive Go proxy is most
	// likely to inject and that real Codex never sends.
	for _, forbidden := range []string{"connection", "accept-encoding"} {
		if _, bad := got[forbidden]; bad {
			t.Fatalf("Codex path leaked %q — real reqwest/hyper never sends it (JA4H mismatch)", forbidden)
		}
	}
}

// TestOrderedH1RejectsInjectedHeaderNotSentByClient is the core JA4H guard: it
// proves the assertion actually catches a proxy-injected header. We add one
// header to req.Header that is NOT in the client's line set and confirm it
// surfaces on the wire as an unexpected name (i.e. the earlier passing tests are
// not vacuous).
func TestOrderedH1RejectsInjectedHeaderNotSentByClient(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://relay.example/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	clientNames := []string{"Authorization", "Content-Type", "Host", "Content-Length"}
	lines := []util.OriginalHeaderLine{
		{LowerName: "authorization", RawName: "Authorization"},
		{LowerName: "content-type", RawName: "Content-Type"},
		{LowerName: "host", RawName: "Host"},
		{LowerName: "content-length", RawName: "Content-Length"},
	}
	req.Header.Set("Authorization", "x")
	req.Header.Set("Content-Type", "application/json")
	// A header a relay/middleware might inject that no real client sends.
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	got := outboundHeaderNames(t, raw)
	if _, leaked := got["x-forwarded-for"]; !leaked {
		t.Fatal("expected the injected X-Forwarded-For to reach the wire; if the funnel now drops unknown req.Header names, update the JA4H tests' assumptions")
	}
	// And prove the assertion helper flags it (negative control run inline).
	wantSet := map[string]struct{}{}
	for _, n := range clientNames {
		wantSet[strings.ToLower(n)] = struct{}{}
	}
	if _, ok := wantSet["x-forwarded-for"]; ok {
		t.Fatal("test setup error: x-forwarded-for must not be in the client set")
	}
}
