//go:build windows

package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// defaultClaudePath returns the newest claude.exe under
// %LOCALAPPDATA%\Claude-3p\claude-code and the version-dir name it came from.
// The version segment is discovered at runtime (never hard-coded) so upgrades of
// the bundled CLI are picked up automatically.
func defaultClaudePath() (path string, version string, err error) {
	base := filepath.Join(os.Getenv("LOCALAPPDATA"), "Claude-3p", "claude-code")
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", "", err
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return "", "", fmt.Errorf("no version dirs under %s", base)
	}
	sort.Slice(versions, func(i, j int) bool { return compareVersion(versions[i], versions[j]) < 0 })
	newest := versions[len(versions)-1]
	exe := filepath.Join(base, newest, "claude.exe")
	if _, statErr := os.Stat(exe); statErr != nil {
		return "", "", fmt.Errorf("claude.exe not found in newest version dir %s: %w", newest, statErr)
	}
	return exe, newest, nil
}

// compareVersion does a numeric-aware compare of dotted version strings.
func compareVersion(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
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
