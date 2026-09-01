package helps

import "strings"

// CodexClientOS identifies the operating system family of the Codex client that
// issued an inbound request. It is derived from the inbound User-Agent because
// CPA cannot observe the client machine directly: the proxy runs on Windows while
// the Codex CLI may run inside WSL2/Linux, and the two builds emit different TLS
// ClientHellos (SChannel vs OpenSSL) that outbound traffic has to match.
type CodexClientOS int

const (
	// CodexClientOSUnknown means the User-Agent was absent or not shaped like a
	// Codex UA, so the OS could not be determined.
	CodexClientOSUnknown CodexClientOS = iota
	// CodexClientOSWindows means the client reported a Windows OS segment.
	CodexClientOSWindows
	// CodexClientOSNonWindows means the client reported an OS segment that is
	// definitely not Windows (Debian, Ubuntu, Mac OS, ...).
	CodexClientOSNonWindows
)

// windowsOSToken is the only os_info OS name that denotes Windows.
const windowsOSToken = "Windows"

// CodexClientOSFromUserAgent reports the OS family encoded in a Codex
// User-Agent.
//
// Every Codex client builds its UA as
//
//	{originator}/{version} ({os_type} {os_version}; {arch}) {terminal}
//
// (codex-rs/login/src/auth/default_client.rs, get_codex_user_agent), where
// os_type and os_version come from the os_info crate. Measured examples:
//
//	codex_cli_rs/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal
//	codex_exec/0.151.0 (Debian 13.0.0; x86_64) WindowsTerminal (codex_exec; 0.151.0)
//	Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)
//	codex-tui/0.146.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.146.0)
//
// Only the first parenthesised group is inspected, and only its first
// semicolon-separated field, which is the OS segment. The originator prefix is
// deliberately ignored: it varies per subcommand (codex_cli_rs, codex_exec,
// codex-tui, Codex Desktop) and carries no OS information.
//
// The discriminator is "does the OS segment name Windows", not "does it name a
// known Linux distro". The os_info vocabulary embedded in the real Codex binary
// lists ~50 OS names (Debian, Ubuntu, Alpine Linux, Arch Linux, Fedora, Mac OS,
// FreeBSD, ...) of which exactly one means Windows, so this stays correct if the
// user later switches distribution.
//
// A trailing word boundary is required so a hypothetical OS name that merely
// starts with "Windows" is not misread. Note the terminal token
// "WindowsTerminal" lives outside the parentheses and is never considered; a
// genuine WSL2 UA legitimately reports "(Debian 13.0.0; x86_64) WindowsTerminal".
func CodexClientOSFromUserAgent(userAgent string) CodexClientOS {
	segment := codexUserAgentOSSegment(userAgent)
	if segment == "" {
		return CodexClientOSUnknown
	}
	if isWindowsOSSegment(segment) {
		return CodexClientOSWindows
	}
	return CodexClientOSNonWindows
}

// codexUserAgentOSSegment extracts the OS segment (os_type plus os_version) from
// a Codex User-Agent, or "" when the UA does not carry one.
func codexUserAgentOSSegment(userAgent string) string {
	openIdx := strings.IndexByte(userAgent, '(')
	if openIdx < 0 {
		return ""
	}
	rest := userAgent[openIdx+1:]
	closeIdx := strings.IndexByte(rest, ')')
	if closeIdx < 0 {
		return ""
	}
	inner := rest[:closeIdx]
	if idx := strings.IndexByte(inner, ';'); idx >= 0 {
		inner = inner[:idx]
	}
	return strings.TrimSpace(inner)
}

// isWindowsOSSegment reports whether an OS segment names Windows, matching the
// leading OS-name token case-insensitively and requiring a word boundary after
// it.
func isWindowsOSSegment(segment string) bool {
	if len(segment) < len(windowsOSToken) {
		return false
	}
	if !strings.EqualFold(segment[:len(windowsOSToken)], windowsOSToken) {
		return false
	}
	remainder := segment[len(windowsOSToken):]
	if remainder == "" {
		return true
	}
	return remainder[0] == ' ' || remainder[0] == '\t'
}
