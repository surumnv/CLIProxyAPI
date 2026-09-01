package helps

import (
	"context"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// TestOrderedH1ConnKeySeparatesTLSModes pins the invariant that makes per-source
// TLS fingerprints meaningful: the idle-connection pool must not hand a
// connection established with one ClientHello to a request that would have sent a
// different one. A TLS handshake happens once per connection, so reuse across
// modes would silently emit the wrong JA3.
func TestOrderedH1ConnKeySeparatesTLSModes(t *testing.T) {
	t.Parallel()

	newRequest := func(ctx context.Context, rawURL string) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		return req
	}

	const target = "https://relay.example.com/v1/responses"
	base := context.Background()

	plain := orderedH1ConnKey(newRequest(base, target))
	codexLinux := orderedH1ConnKey(newRequest(cliproxyexecutor.WithCodexLinuxFingerprint(base), target))
	schannel := orderedH1ConnKey(newRequest(cliproxyexecutor.WithSChannelTLS(base), target))
	claude := orderedH1ConnKey(newRequest(cliproxyexecutor.WithClaudeFingerprint(base), target))

	keys := map[string]string{
		"plain":       plain,
		"codex-linux": codexLinux,
		"schannel":    schannel,
		"claude":      claude,
	}
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if other, ok := seen[key]; ok {
			t.Fatalf("modes %q and %q share pool key %q", other, name, key)
		}
		seen[key] = name
	}

	// The default path keeps its historical key so plain traffic pools exactly as
	// before this split was introduced.
	if plain != "https://relay.example.com:443" {
		t.Fatalf("default pool key = %q, want the historical scheme://host:port form", plain)
	}
}

// TestOrderedH1ConnKeyIgnoresTLSModeForPlaintext documents that the suffix is
// TLS-only: an http:// request performs no handshake, so its pool key must not be
// split by markers that would otherwise be irrelevant.
func TestOrderedH1ConnKeyIgnoresTLSModeForPlaintext(t *testing.T) {
	t.Parallel()

	const target = "http://relay.example.com/v1/responses"
	build := func(ctx context.Context) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		return orderedH1ConnKey(req)
	}

	plain := build(context.Background())
	marked := build(cliproxyexecutor.WithCodexLinuxFingerprint(context.Background()))
	if plain != marked {
		t.Fatalf("plaintext pool keys diverged: %q vs %q", plain, marked)
	}
}
