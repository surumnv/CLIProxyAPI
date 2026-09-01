package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestMaybeMarkSChannelTLS(t *testing.T) {
	t.Parallel()

	opts := func(source string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString(source)}
	}

	cases := []struct {
		name    string
		cfg     *config.Config
		opts    cliproxyexecutor.Options
		wantSet bool
	}{
		{
			name:    "codex source with toggle on marks context",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts("codex"),
			wantSet: true,
		},
		{
			// Real Codex traffic arrives as openai-response: the client posts to
			// /v1/responses and that handler reports HandlerType() ==
			// constant.OpenaiResponse. No inbound path ever produces the literal
			// "codex", so this case is the one that matters in production.
			name:    "openai-response source with toggle on marks context",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts("openai-response"),
			wantSet: true,
		},
		{
			name:    "openai-response source but toggle off leaves context untouched",
			cfg:     &config.Config{SChannelTLS: false},
			opts:    opts("openai-response"),
			wantSet: false,
		},
		{
			name:    "codex source but toggle off leaves context untouched",
			cfg:     &config.Config{SChannelTLS: false},
			opts:    opts("codex"),
			wantSet: false,
		},
		{
			name:    "non-codex source with toggle on is not marked",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts("claude"),
			wantSet: false,
		},
		{
			name:    "openai source with toggle on is not marked",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts("openai"),
			wantSet: false,
		},
		{
			name:    "gemini source with toggle on is not marked",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts("gemini"),
			wantSet: false,
		},
		{
			name:    "empty source is not marked",
			cfg:     &config.Config{SChannelTLS: true},
			opts:    opts(""),
			wantSet: false,
		},
		{
			name:    "nil config is a no-op",
			cfg:     nil,
			opts:    opts("codex"),
			wantSet: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := maybeMarkSChannelTLS(context.Background(), tc.cfg, tc.opts)
			if got := cliproxyexecutor.SChannelTLSFromContext(ctx); got != tc.wantSet {
				t.Fatalf("SChannelTLSFromContext = %v, want %v", got, tc.wantSet)
			}
		})
	}
}

func TestMaybeMarkLowercaseHeaders(t *testing.T) {
	t.Parallel()

	opts := func(source string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString(source)}
	}

	cases := []struct {
		name    string
		opts    cliproxyexecutor.Options
		wantSet bool
	}{
		{
			name:    "codex source is marked (no config toggle required)",
			opts:    opts("codex"),
			wantSet: true,
		},
		{
			// The label real Codex traffic carries; see TestMaybeMarkSChannelTLS.
			name:    "openai-response source is marked",
			opts:    opts("openai-response"),
			wantSet: true,
		},
		{
			// Critical: Claude wire header names are mixed-case; lowercasing
			// them would create a fingerprint mismatch, so it must stay unset.
			name:    "claude source is never marked",
			opts:    opts("claude"),
			wantSet: false,
		},
		{
			name:    "openai source is not marked",
			opts:    opts("openai"),
			wantSet: false,
		},
		{
			name:    "empty source is not marked",
			opts:    opts(""),
			wantSet: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := maybeMarkLowercaseHeaders(context.Background(), tc.opts)
			if got := cliproxyexecutor.LowercaseHeadersFromContext(ctx); got != tc.wantSet {
				t.Fatalf("LowercaseHeadersFromContext = %v, want %v", got, tc.wantSet)
			}
		})
	}
}

// Measured Codex User-Agents used by the client-OS routing tests.
//
// The WSL2 value was captured from Codex CLI 0.151.0 running under Debian 13 in
// WSL2. Its terminal token is legitimately "WindowsTerminal" because WSL2
// inherits WT_SESSION, which is precisely why the OS segment inside the
// parentheses -- not the terminal token -- is the discriminator.
const (
	debianCodexUA  = "codex_cli_rs/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	debianExecUA   = "codex_exec/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal (codex_exec; 0.151.0)"
	windowsCodexUA = "codex_cli_rs/0.151.0 (Windows 10.0.26200; x86_64) WindowsTerminal"
	desktopCodexUA = "Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)"
)

// codexOptsWithUA builds executor options carrying a source format and an inbound
// User-Agent, which is how the gate learns the client platform. An empty
// userAgent leaves Headers nil, matching SDK callers that pass no headers.
func codexOptsWithUA(source, userAgent string) cliproxyexecutor.Options {
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString(source)}
	if userAgent != "" {
		opts.Headers = http.Header{"User-Agent": []string{userAgent}}
	}
	return opts
}

// TestCodexTLSFingerprintRoutingByClientOS is the core matrix for WSL2 support: a
// Codex client running on Windows keeps the SChannel path, while one running under
// Debian/WSL2 is routed to the replayed OpenSSL ClientHello. The two markers are
// mutually exclusive, so at most one fingerprint is applied per request.
func TestCodexTLSFingerprintRoutingByClientOS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		cfg            *config.Config
		opts           cliproxyexecutor.Options
		wantSChannel   bool
		wantCodexLinux bool
	}{
		{
			name:           "windows cli keeps the schannel path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", windowsCodexUA),
			wantSChannel:   true,
			wantCodexLinux: false,
		},
		{
			name:           "windows desktop keeps the schannel path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", desktopCodexUA),
			wantSChannel:   true,
			wantCodexLinux: false,
		},
		{
			name:           "debian cli takes the linux fingerprint path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", debianCodexUA),
			wantSChannel:   false,
			wantCodexLinux: true,
		},
		{
			// The originator differs per subcommand (codex_exec vs codex_cli_rs)
			// and must not affect the decision.
			name:           "debian exec originator also takes the linux path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", debianExecUA),
			wantSChannel:   false,
			wantCodexLinux: true,
		},
		{
			// Backward compatibility: CPA runs on Windows, so an unidentifiable
			// client keeps the historical behaviour.
			name:           "missing user agent keeps the schannel path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", ""),
			wantSChannel:   true,
			wantCodexLinux: false,
		},
		{
			name:           "non codex user agent keeps the schannel path",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("openai-response", "Go-http-client/1.1"),
			wantSChannel:   true,
			wantCodexLinux: false,
		},
		{
			// The shared toggle gates both paths, preserving the original
			// "off means stock crypto/tls" semantics.
			name:           "toggle off disables both paths for a debian client",
			cfg:            &config.Config{SChannelTLS: false},
			opts:           codexOptsWithUA("openai-response", debianCodexUA),
			wantSChannel:   false,
			wantCodexLinux: false,
		},
		{
			name:           "toggle off disables both paths for a windows client",
			cfg:            &config.Config{SChannelTLS: false},
			opts:           codexOptsWithUA("openai-response", windowsCodexUA),
			wantSChannel:   false,
			wantCodexLinux: false,
		},
		{
			name:           "nil config disables both paths",
			cfg:            nil,
			opts:           codexOptsWithUA("openai-response", debianCodexUA),
			wantSChannel:   false,
			wantCodexLinux: false,
		},
		{
			// A Claude client on Debian must not receive the Codex ClientHello.
			name:           "non codex source is never marked",
			cfg:            &config.Config{SChannelTLS: true},
			opts:           codexOptsWithUA("claude", debianCodexUA),
			wantSChannel:   false,
			wantCodexLinux: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := maybeMarkSChannelTLS(context.Background(), tc.cfg, tc.opts)
			ctx = maybeMarkCodexLinuxFingerprint(ctx, tc.cfg, tc.opts)
			gotSChannel := cliproxyexecutor.SChannelTLSFromContext(ctx)
			gotCodexLinux := cliproxyexecutor.CodexLinuxFingerprintFromContext(ctx)
			if gotSChannel != tc.wantSChannel {
				t.Fatalf("SChannelTLSFromContext = %v, want %v", gotSChannel, tc.wantSChannel)
			}
			if gotCodexLinux != tc.wantCodexLinux {
				t.Fatalf("CodexLinuxFingerprintFromContext = %v, want %v", gotCodexLinux, tc.wantCodexLinux)
			}
			if gotSChannel && gotCodexLinux {
				t.Fatal("both TLS fingerprint markers set; they must be mutually exclusive")
			}
		})
	}
}

// TestMaybeMarkCodexLinuxFingerprintWithNilHeaders guards the nil-map path: SDK
// and plugin callers may build Options without headers, which must not be read as
// a non-Windows client.
func TestMaybeMarkCodexLinuxFingerprintWithNilHeaders(t *testing.T) {
	t.Parallel()

	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex")}
	cfg := &config.Config{SChannelTLS: true}
	if ctx := maybeMarkCodexLinuxFingerprint(context.Background(), cfg, opts); cliproxyexecutor.CodexLinuxFingerprintFromContext(ctx) {
		t.Fatal("nil headers were treated as a non-Windows client")
	}
	if ctx := maybeMarkSChannelTLS(context.Background(), cfg, opts); !cliproxyexecutor.SChannelTLSFromContext(ctx) {
		t.Fatal("nil headers must keep the historical SChannel behaviour")
	}
}

// TestMaybeMarkLowercaseHeadersIgnoresClientOS pins a deliberate asymmetry:
// lowercase header names are correct for every Codex client because both the
// Windows and the Linux build use reqwest/hyper. Verified against a raw capture
// of Debian Codex traffic, whose header names are all lowercase.
func TestMaybeMarkLowercaseHeadersIgnoresClientOS(t *testing.T) {
	t.Parallel()

	for _, userAgent := range []string{debianCodexUA, windowsCodexUA, ""} {
		ctx := maybeMarkLowercaseHeaders(context.Background(), codexOptsWithUA("openai-response", userAgent))
		if !cliproxyexecutor.LowercaseHeadersFromContext(ctx) {
			t.Fatalf("LowercaseHeadersFromContext = false for UA %q, want true", userAgent)
		}
	}
}
