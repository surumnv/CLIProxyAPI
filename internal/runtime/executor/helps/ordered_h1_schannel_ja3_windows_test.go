//go:build windows

package helps

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// codexJA3 is the JA3 hash produced by the Codex CLI (reqwest + native-tls →
// SChannel, legacy SCHANNEL_CRED, no ALPN) captured on Windows against
// check.ja3.zone. CPA's SChannel-backed ordered-h1 path must reproduce it.
const codexJA3 = "6a5d235ee78c6aede6a61448b4e9ff1e"

// TestOrderedH1SChannelMatchesCodexJA3 drives a real HTTPS request through the
// production NewUtlsHTTPClient → ordered-h1 → SChannel path with SChannelTLS
// enabled, and asserts the JA3 echoed back matches the Codex CLI fingerprint.
//
// Network + Windows required; gated behind CPA_JA3_LIVE=1 so normal test runs
// (CI, other machines) skip it.
func TestOrderedH1SChannelMatchesCodexJA3(t *testing.T) {
	if os.Getenv("CPA_JA3_LIVE") != "1" {
		t.Skip("set CPA_JA3_LIVE=1 to run the live JA3 match test (needs network on Windows)")
	}

	cfg := &config.Config{}
	cfg.SChannelTLS = true

	// Attach a captured inbound header order so the ordered-h1 path is exercised
	// exactly as in production (this is what makes canUseOrderedH1 return true).
	order := &util.OriginalHeaderOrder{}
	order.Set([]util.OriginalHeaderLine{
		{LowerName: "host", RawName: "Host"},
		{LowerName: "user-agent", RawName: "User-Agent"},
		{LowerName: "accept", RawName: "Accept"},
	})
	ctx := util.WithOriginalHeaderOrder(context.Background(), order)
	// SChannel mode is now decided per-request from the context (only Codex
	// sources opt in via executor.WithSChannelTLS), so mark the ctx here to
	// exercise the SChannel handshake exactly as the codex executor does.
	ctx = cliproxyexecutor.WithSChannelTLS(ctx)

	client := NewUtlsHTTPClient(ctx, cfg, nil, 30*time.Second)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.ja3.zone/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", "cpa-schannel-test")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through SChannel ordered-h1 failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var echo struct {
		Hash        string `json:"hash"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &echo); err != nil {
		t.Fatalf("decode JA3 echo: %v\nbody: %s", err, string(body))
	}

	t.Logf("CPA JA3 via ordered-h1+SChannel: hash=%s fingerprint=%s", echo.Hash, echo.Fingerprint)
	if echo.Hash != codexJA3 {
		t.Fatalf("JA3 mismatch: got %s, want %s (Codex)\nfingerprint=%s", echo.Hash, codexJA3, echo.Fingerprint)
	}
}
