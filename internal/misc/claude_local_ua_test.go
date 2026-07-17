package misc

import (
	"os"
	"path/filepath"
	"testing"
)

// writeClaudeVersionDir creates a Claude-3p/claude-code/<version> directory under
// root, optionally with a .verified marker and a claude.exe, mirroring the
// on-disk layout of the Desktop-embedded claude-code install.
func writeClaudeVersionDir(t *testing.T, root, version string, verified, hasExe bool) {
	t.Helper()
	dir := filepath.Join(root, "Claude-3p", "claude-code", version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if verified {
		if err := os.WriteFile(filepath.Join(dir, ".verified"), []byte("ok"), 0o644); err != nil {
			t.Fatalf("write .verified: %v", err)
		}
	}
	if hasExe {
		if err := os.WriteFile(filepath.Join(dir, "claude.exe"), []byte("MZ"), 0o644); err != nil {
			t.Fatalf("write claude.exe: %v", err)
		}
	}
}

func TestDetectClaudeDesktopEmbeddedVersionPicksHighestVerified(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)

	// Highest verified+exe version should win over a lower one.
	writeClaudeVersionDir(t, root, "2.1.60", true, true)
	writeClaudeVersionDir(t, root, "2.1.209", true, true)
	// A higher number that is NOT verified must be ignored.
	writeClaudeVersionDir(t, root, "2.1.300", false, true)
	// A verified dir missing claude.exe must be ignored.
	writeClaudeVersionDir(t, root, "2.1.400", true, false)

	got := detectClaudeDesktopEmbeddedVersion()
	if got != "2.1.209" {
		t.Fatalf("detectClaudeDesktopEmbeddedVersion() = %q, want %q", got, "2.1.209")
	}
}

func TestDetectClaudeDesktopEmbeddedVersionNumericOrdering(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)

	// Numeric (not lexicographic) comparison: 209 > 60 even though "60" > "209"
	// as strings.
	writeClaudeVersionDir(t, root, "2.1.209", true, true)
	writeClaudeVersionDir(t, root, "2.1.60", true, true)

	got := detectClaudeDesktopEmbeddedVersion()
	if got != "2.1.209" {
		t.Fatalf("detectClaudeDesktopEmbeddedVersion() = %q, want %q", got, "2.1.209")
	}
}

func TestDetectClaudeDesktopEmbeddedVersionMissingRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	// No Claude-3p directory created at all.
	if got := detectClaudeDesktopEmbeddedVersion(); got != "" {
		t.Fatalf("detectClaudeDesktopEmbeddedVersion() = %q, want empty", got)
	}
}

func TestDetectClaudeDesktopEmbeddedVersionEmptyLocalAppData(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	if got := detectClaudeDesktopEmbeddedVersion(); got != "" {
		t.Fatalf("detectClaudeDesktopEmbeddedVersion() = %q, want empty", got)
	}
}

func TestBuildLocalClaudeCodeUserAgentFormat(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	writeClaudeVersionDir(t, root, "2.1.209", true, true)

	got := buildLocalClaudeCodeUserAgent()
	want := "claude-cli/2.1.209 (external, cli)"
	if got != want {
		t.Fatalf("buildLocalClaudeCodeUserAgent() = %q, want %q", got, want)
	}
}

func TestBuildLocalClaudeCodeUserAgentFailsWithoutVersion(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	// No usable version dir -> build returns empty so caller uses fallback.
	if got := buildLocalClaudeCodeUserAgent(); got != "" {
		t.Fatalf("buildLocalClaudeCodeUserAgent() = %q, want empty", got)
	}
}

func TestLocalClaudeCodeUserAgentFallsBackWhenDetectionFails(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	// Reset the process-wide cache so this test sees a fresh detection.
	claudeLocalUAMu.Lock()
	claudeLocalUACached = ""
	claudeLocalUAMu.Unlock()

	got := LocalClaudeCodeUserAgent()
	if got != LocalClaudeCodeUAFallback {
		t.Fatalf("LocalClaudeCodeUserAgent() = %q, want fallback %q", got, LocalClaudeCodeUAFallback)
	}

	// Clean up the cache so we do not leak state into other tests.
	claudeLocalUAMu.Lock()
	claudeLocalUACached = ""
	claudeLocalUAMu.Unlock()
}

func TestCompareClaudeVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.1.209", "2.1.60", 1},
		{"2.1.60", "2.1.209", -1},
		{"2.1.209", "2.1.209", 0},
		{"2.2.0", "2.1.999", 1},
		{"1.0.0", "2.0.0", -1},
		{"2.1", "2.1.0", 0},
	}
	for _, tc := range cases {
		if got := compareClaudeVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareClaudeVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
