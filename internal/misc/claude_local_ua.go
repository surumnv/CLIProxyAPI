// Package misc: local Claude Code User-Agent detection.
//
// This file builds a User-Agent string that mimics the real Claude Code CLI so
// that outbound management api-call requests (notably the panel's "fetch model
// list" probe against a Claude provider) are not rejected by upstream
// relays/WAFs that block generic values like "Go-http-client/1.1", and so they
// do not carry a mismatched Codex UA.
//
// Shape produced (Claude Code CLI form, entrypoint "cli"):
//
//	claude-cli/<version> (external, cli)
//
// The version tracks the Claude Code embedded in the locally installed Claude
// Desktop app, NOT the standalone Claude Code CLI. These are different builds
// with different versions (e.g. Desktop-embedded 2.1.209 vs standalone CLI
// 2.1.201), so we deliberately read the Desktop-embedded install location:
//
//	%LOCALAPPDATA%\Claude-3p\claude-code\<version>\claude.exe
//
// The "Claude-3p" directory ("3p" == the "claude-desktop-3p" entrypoint the
// Desktop app reports in its own UA) holds one subdirectory per installed
// version, each carrying a ".verified" marker and a claude.exe. The
// subdirectory name IS the version string used in the UA (verified on-machine
// to match `claude.exe --version`), so we read the directory name rather than
// spawning the executable — it is faster and avoids a process-launch timeout.
//
// The Claude Code CLI UA has no OS/arch/terminal segments (unlike Codex), so the
// build only needs the version. Detection is Windows-oriented (it reads
// LOCALAPPDATA); on other platforms LOCALAPPDATA is empty, detection fails, and
// the caller falls back to LocalClaudeCodeUAFallback. Results are cached
// process-wide after the first successful build;
// RefreshLocalClaudeCodeUserAgent() clears the cache so the next call
// re-detects.
package misc

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// LocalClaudeCodeUAFallback is returned when local detection of the Claude Code
// CLI UA fails. It is a real, recent Claude Code UA (entrypoint "cli"); a
// slightly stale but genuine client string is far less likely to be blocked
// than a synthetic one. Keep the version in sync with a known-good Claude
// Desktop embedded claude-code version when bumping.
const LocalClaudeCodeUAFallback = "claude-cli/2.1.209 (external, cli)"

var (
	claudeLocalUAMu     sync.Mutex
	claudeLocalUACached string
)

// LocalClaudeCodeUserAgent returns a User-Agent string mimicking the local
// Claude Code CLI, with the version taken from the Claude Desktop embedded
// claude-code install. The value is cached after the first call; use
// RefreshLocalClaudeCodeUserAgent to force re-detection. It never returns an
// empty string — on failure it falls back to LocalClaudeCodeUAFallback.
func LocalClaudeCodeUserAgent() string {
	claudeLocalUAMu.Lock()
	defer claudeLocalUAMu.Unlock()
	if claudeLocalUACached != "" {
		return claudeLocalUACached
	}
	ua := buildLocalClaudeCodeUserAgent()
	if strings.TrimSpace(ua) == "" {
		ua = LocalClaudeCodeUAFallback
	}
	claudeLocalUACached = ua
	log.Debugf("claude local CLI UA resolved: %s", ua)
	return ua
}

// RefreshLocalClaudeCodeUserAgent clears the cached Claude Code UA so the next
// LocalClaudeCodeUserAgent call re-detects, and returns the freshly built value.
func RefreshLocalClaudeCodeUserAgent() string {
	claudeLocalUAMu.Lock()
	claudeLocalUACached = ""
	claudeLocalUAMu.Unlock()
	return LocalClaudeCodeUserAgent()
}

// buildLocalClaudeCodeUserAgent assembles the Claude Code CLI UA from the local
// Desktop-embedded claude-code version. If the version cannot be resolved the
// build fails (returns ""), so the caller substitutes the fallback rather than
// emitting a half-real UA.
func buildLocalClaudeCodeUserAgent() string {
	version := detectClaudeDesktopEmbeddedVersion()
	if version == "" {
		return ""
	}
	// Entrypoint "cli": present the request as a normal Claude Code CLI probe
	// rather than exposing the "claude-desktop-3p" embedded marker.
	return "claude-cli/" + version + " (external, cli)"
}

// detectClaudeDesktopEmbeddedVersion returns the highest installed version of
// the Claude Code embedded in Claude Desktop, read from the subdirectory names
// under %LOCALAPPDATA%\Claude-3p\claude-code\. Only directories that carry both
// a ".verified" marker and a claude.exe are considered usable. Returns "" if the
// directory does not exist or has no usable version (e.g. non-Windows, or Claude
// Desktop not installed).
func detectClaudeDesktopEmbeddedVersion() string {
	localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if localAppData == "" {
		return ""
	}
	root := filepath.Join(localAppData, "Claude-3p", "claude-code")
	entries, err := os.ReadDir(root)
	if err != nil {
		log.Debugf("claude local UA: read %s failed: %v", root, err)
		return ""
	}

	var versions []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" {
			continue
		}
		dir := filepath.Join(root, name)
		// A usable version directory has both a ".verified" marker and claude.exe.
		if fi, statErr := os.Stat(filepath.Join(dir, ".verified")); statErr != nil || fi.IsDir() {
			continue
		}
		if fi, statErr := os.Stat(filepath.Join(dir, "claude.exe")); statErr != nil || fi.IsDir() {
			continue
		}
		versions = append(versions, name)
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareClaudeVersions(versions[i], versions[j]) < 0
	})
	return versions[len(versions)-1]
}

// compareClaudeVersions compares two dotted version strings numerically
// segment-by-segment (e.g. "2.1.209" vs "2.1.60"), so 209 > 60. Non-numeric or
// missing segments compare as lower. Returns -1, 0, or 1.
func compareClaudeVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(aParts) {
			ai, _ = strconv.Atoi(strings.TrimSpace(aParts[i]))
		}
		if i < len(bParts) {
			bi, _ = strconv.Atoi(strings.TrimSpace(bParts[i]))
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}
