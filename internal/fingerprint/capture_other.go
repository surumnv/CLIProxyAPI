//go:build !windows

package fingerprint

// defaultClaudePath is unsupported off Windows: the bundled Claude Code CLI
// install layout (%LOCALAPPDATA%\Claude-3p\claude-code) is Windows-specific.
// Callers must supply an explicit CaptureOptions.ClaudePath instead.
func defaultClaudePath() (path string, version string, err error) {
	return "", "", errAutoDetectUnsupported
}
