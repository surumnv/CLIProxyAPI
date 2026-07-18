package executor

import (
	"context"
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
