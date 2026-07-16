//go:build !windows

package misc

// detectWindowsVersion is a no-op on non-Windows platforms. The Codex Desktop UA
// this proxy mimics is Windows-specific, so on other platforms local detection
// intentionally fails and callers fall back to LocalCodexUAFallback.
func detectWindowsVersion() string {
	return ""
}
