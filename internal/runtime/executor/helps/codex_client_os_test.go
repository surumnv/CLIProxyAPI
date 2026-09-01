package helps

import "testing"

// TestCodexClientOSFromUserAgent covers the real UA shapes measured from Codex
// clients plus the malformed inputs the parser must survive. The Debian values
// are verbatim captures from Codex CLI 0.151.0 running in WSL2.
func TestCodexClientOSFromUserAgent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		userAgent string
		want      CodexClientOS
	}{
		{
			// Measured: `codex mcp-server` inside WSL2/Debian 13. Note the
			// terminal token is WindowsTerminal (WT_SESSION is inherited from the
			// Windows host) while the OS segment is Debian, which is exactly the
			// case that must not be misclassified as Windows.
			name:      "codex cli on debian in wsl2",
			userAgent: "codex_cli_rs/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal",
			want:      CodexClientOSNonWindows,
		},
		{
			// Measured: `codex exec` in the same environment. The originator
			// differs and a suffix is appended, neither of which may matter.
			name:      "codex exec on debian with suffix",
			userAgent: "codex_exec/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal (codex_exec; 0.151.0)",
			want:      CodexClientOSNonWindows,
		},
		{
			name:      "codex desktop on windows",
			userAgent: "Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)",
			want:      CodexClientOSWindows,
		},
		{
			name:      "codex cli on windows",
			userAgent: "codex_cli_rs/0.144.2 (Windows 10.0.26200; x86_64) WindowsTerminal",
			want:      CodexClientOSWindows,
		},
		{
			// The built-in cloaking constant, so the gate stays predictable if it
			// ever reaches this parser.
			name:      "codex tui on macos",
			userAgent: "codex-tui/0.146.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.146.0)",
			want:      CodexClientOSNonWindows,
		},
		{
			name:      "other os_info distro names are non windows",
			userAgent: "codex_cli_rs/0.151.0 (Ubuntu 24.04.0; x86_64) WindowsTerminal",
			want:      CodexClientOSNonWindows,
		},
		{
			name:      "multi word distro names are non windows",
			userAgent: "codex_cli_rs/0.151.0 (Arch Linux rolling; x86_64) Alacritty",
			want:      CodexClientOSNonWindows,
		},
		{
			name:      "os segment is matched case insensitively",
			userAgent: "codex_cli_rs/0.151.0 (windows 10.0.26200; x86_64) WindowsTerminal",
			want:      CodexClientOSWindows,
		},
		{
			// The terminal token sits outside the parentheses and must never be
			// mistaken for the OS segment.
			name:      "windows terminal token alone is not windows",
			userAgent: "codex_cli_rs/0.151.0 (Alpine Linux 3.21.0; x86_64) WindowsTerminal",
			want:      CodexClientOSNonWindows,
		},
		{
			// A word boundary is required after the OS name.
			name:      "os name merely prefixed with windows is not windows",
			userAgent: "codex_cli_rs/0.151.0 (WindowsLike 1.0.0; x86_64) unknown",
			want:      CodexClientOSNonWindows,
		},
		{
			name:      "empty user agent is unknown",
			userAgent: "",
			want:      CodexClientOSUnknown,
		},
		{
			name:      "user agent without parentheses is unknown",
			userAgent: "Go-http-client/1.1",
			want:      CodexClientOSUnknown,
		},
		{
			name:      "unterminated parenthesis is unknown",
			userAgent: "codex_cli_rs/0.151.0 (Debian 13.0.0; x86_64",
			want:      CodexClientOSUnknown,
		},
		{
			name:      "empty parenthetical is unknown",
			userAgent: "codex_cli_rs/0.151.0 () WindowsTerminal",
			want:      CodexClientOSUnknown,
		},
		{
			name:      "os segment without version still classifies",
			userAgent: "codex_cli_rs/0.151.0 (Windows; x86_64) WindowsTerminal",
			want:      CodexClientOSWindows,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CodexClientOSFromUserAgent(tc.userAgent); got != tc.want {
				t.Fatalf("CodexClientOSFromUserAgent(%q) = %v, want %v", tc.userAgent, got, tc.want)
			}
		})
	}
}
