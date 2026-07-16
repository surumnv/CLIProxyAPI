// Package misc: local Codex User-Agent detection.
//
// This file builds User-Agent strings that mimic the real Codex (ChatGPT)
// clients running on this machine, so that outbound requests made by the proxy
// on the user's behalf are not rejected by upstream relays/WAFs that block
// generic values like "Go-http-client/1.1".
//
// Two shapes are produced, matching the two real Codex clients:
//
//   - Codex Desktop (the ChatGPT desktop app):
//     Codex Desktop/<cli-version> (Windows <win-version>; <arch>) unknown (Codex Desktop; <app-version>)
//     Used for requests the Desktop app itself makes (e.g. quota / rate-limit
//     lookups, which the management frontend tags with Originator "Codex Desktop").
//
//   - Codex CLI (codex_cli_rs, the terminal client):
//     codex_cli_rs/<cli-version> (Windows <win-version>; <arch>) WindowsTerminal
//     Used for requests only the CLI makes (e.g. provider /v1/models
//     reachability probes triggered by the management model-list fetch).
//
// The field-extraction methods mirror the openai/codex source as closely as
// possible so the forged UA matches what the real client would emit:
//   - cli-version : `codex.exe --version` -> "codex-cli 0.144.2"
//   - win-version : RtlGetVersion (the NT API os_info uses) -> "major.minor.build"
//   - arch        : mapped to os_info's vocabulary (amd64->x86_64, arm64->aarch64)
//   - app-version : ~/.codex/config.toml key BROWSER_USE_CODEX_APP_VERSION (Desktop only)
//
// The Desktop UA is Windows-only in shape (it embeds an app version the CLI has
// no analogue for); the CLI UA is the cross-platform codex_cli_rs form. Results
// are cached process-wide after the first successful build.
// RefreshLocalCodexUserAgents() clears the caches so the next call re-detects.
// If any component cannot be determined, a static fallback UA is returned so
// callers always get a usable value.
package misc

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// LocalCodexUAFallback is returned when local detection of the Desktop UA fails.
// It is a real, recent Codex Desktop UA observed on Windows; a slightly stale
// but genuine client string is far less likely to be blocked than a synthetic one.
const LocalCodexUAFallback = "Codex Desktop/0.144.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.707.72221)"

// LocalCodexCLIUAFallback is returned when local detection of the CLI UA fails.
// The terminal segment is "WindowsTerminal" (the token codex-terminal-detection
// emits when WT_SESSION is set) to match the intended Windows Terminal profile.
const LocalCodexCLIUAFallback = "codex_cli_rs/0.144.2 (Windows 10.0.26200; x86_64) WindowsTerminal"

// codexLocalUACLIProbeTimeout bounds how long we wait for `codex.exe --version`.
const codexLocalUACLIProbeTimeout = 5 * time.Second

var (
	codexLocalUAMu        sync.Mutex
	codexLocalUACached    string // Desktop UA
	codexLocalCLIUACached string // CLI UA
)

// LocalCodexUserAgent returns a User-Agent string mimicking the local Codex
// Desktop client. The value is cached after the first call; use
// RefreshLocalCodexUserAgents to force re-detection. It never returns an empty
// string — on failure it falls back to LocalCodexUAFallback.
func LocalCodexUserAgent() string {
	codexLocalUAMu.Lock()
	defer codexLocalUAMu.Unlock()
	if codexLocalUACached != "" {
		return codexLocalUACached
	}
	ua := buildLocalCodexDesktopUserAgent()
	if strings.TrimSpace(ua) == "" {
		ua = LocalCodexUAFallback
	}
	codexLocalUACached = ua
	log.Debugf("codex local Desktop UA resolved: %s", ua)
	return ua
}

// LocalCodexCLIUserAgent returns a User-Agent string mimicking the local Codex
// CLI (codex_cli_rs) client, with the terminal segment fixed to
// "WindowsTerminal". The value is cached after the first call; use
// RefreshLocalCodexUserAgents to force re-detection. It never returns an empty
// string — on failure it falls back to LocalCodexCLIUAFallback.
func LocalCodexCLIUserAgent() string {
	codexLocalUAMu.Lock()
	defer codexLocalUAMu.Unlock()
	if codexLocalCLIUACached != "" {
		return codexLocalCLIUACached
	}
	ua := buildLocalCodexCLIUserAgent()
	if strings.TrimSpace(ua) == "" {
		ua = LocalCodexCLIUAFallback
	}
	codexLocalCLIUACached = ua
	log.Debugf("codex local CLI UA resolved: %s", ua)
	return ua
}

// RefreshLocalCodexUserAgents clears both cached UAs so the next
// LocalCodexUserAgent / LocalCodexCLIUserAgent call re-detects, and returns the
// freshly built Desktop and CLI values.
func RefreshLocalCodexUserAgents() (desktop string, cli string) {
	codexLocalUAMu.Lock()
	codexLocalUACached = ""
	codexLocalCLIUACached = ""
	codexLocalUAMu.Unlock()
	return LocalCodexUserAgent(), LocalCodexCLIUserAgent()
}

// RefreshLocalCodexUserAgent clears the cached Desktop UA and returns the
// freshly built value. Retained for backward compatibility with the existing
// management refresh endpoint; also refreshes the CLI UA.
func RefreshLocalCodexUserAgent() string {
	desktop, _ := RefreshLocalCodexUserAgents()
	return desktop
}

// buildLocalCodexDesktopUserAgent assembles the Desktop UA from local sources.
// Any component that cannot be resolved makes the whole build fail (returns ""),
// so the caller substitutes the fallback rather than emitting a half-real UA.
func buildLocalCodexDesktopUserAgent() string {
	cliVersion := detectCodexCLIVersion()
	if cliVersion == "" {
		return ""
	}
	appVersion := detectCodexDesktopAppVersion()
	if appVersion == "" {
		return ""
	}
	winVersion := detectWindowsVersion()
	if winVersion == "" {
		return ""
	}
	arch := codexUAArch()
	// Terminal segment "unknown": the Desktop app is a background GUI process
	// with no TERM_PROGRAM/WT_SESSION, so codex-terminal-detection yields
	// "unknown" (confirmed against real captured Desktop UAs).
	return "Codex Desktop/" + cliVersion + " (Windows " + winVersion + "; " + arch + ") unknown (Codex Desktop; " + appVersion + ")"
}

// buildLocalCodexCLIUserAgent assembles the CLI (codex_cli_rs) UA. It needs no
// app version — only the CLI version, Windows version, and arch — so it does not
// depend on config.toml. The terminal segment is fixed to "WindowsTerminal".
func buildLocalCodexCLIUserAgent() string {
	cliVersion := detectCodexCLIVersion()
	if cliVersion == "" {
		return ""
	}
	winVersion := detectWindowsVersion()
	if winVersion == "" {
		return ""
	}
	arch := codexUAArch()
	// Terminal segment "WindowsTerminal": codex-terminal-detection emits this
	// exact token (no version, no slash) when WT_SESSION is set. We hardcode it
	// because the proxy runs as a background process and cannot itself detect a
	// terminal; this mimics a CLI launched from Windows Terminal.
	return "codex_cli_rs/" + cliVersion + " (Windows " + winVersion + "; " + arch + ") WindowsTerminal"
}

var codexCLIVersionRe = regexp.MustCompile(`(\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.]+)?)`)

// detectCodexCLIVersion runs `codex --version` and parses the version token.
// It first tries the known Codex Desktop install location, then falls back to
// whatever `codex` resolves to on PATH.
func detectCodexCLIVersion() string {
	exe := locateCodexExecutable()
	if exe == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), codexLocalUACLIProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "--version").Output()
	if err != nil {
		log.Debugf("codex local UA: `%s --version` failed: %v", exe, err)
		return ""
	}
	// Expected output: "codex-cli 0.144.2"
	m := codexCLIVersionRe.FindString(strings.TrimSpace(string(out)))
	return strings.TrimSpace(m)
}

// locateCodexExecutable returns a path to the Codex CLI executable, preferring
// the Codex Desktop bundled bin under %LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\
// and falling back to PATH lookup.
func locateCodexExecutable() string {
	name := "codex"
	if runtime.GOOS == "windows" {
		name = "codex.exe"
	}
	if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
		binRoot := filepath.Join(localAppData, "OpenAI", "Codex", "bin")
		if entries, err := os.ReadDir(binRoot); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				candidate := filepath.Join(binRoot, entry.Name(), name)
				if fi, statErr := os.Stat(candidate); statErr == nil && !fi.IsDir() {
					return candidate
				}
			}
		}
	}
	if resolved, err := exec.LookPath(name); err == nil {
		return resolved
	}
	return ""
}

// detectCodexDesktopAppVersion reads BROWSER_USE_CODEX_APP_VERSION from
// ~/.codex/config.toml. A lightweight line scan is used rather than a full TOML
// parser to avoid a new dependency and to tolerate the file's mixed contents.
func detectCodexDesktopAppVersion() string {
	path := codexConfigTomlPath()
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		log.Debugf("codex local UA: open %s failed: %v", path, err)
		return ""
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Debugf("codex local UA: close %s failed: %v", path, errClose)
		}
	}()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "BROWSER_USE_CODEX_APP_VERSION") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		value = strings.Trim(value, "\"'")
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

// codexConfigTomlPath returns the absolute path to ~/.codex/config.toml.
func codexConfigTomlPath() string {
	if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
		return filepath.Join(codexHome, "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".codex", "config.toml")
}

// codexUAArch maps Go's GOARCH to the architecture token os_info emits, which is
// what the real Codex UA carries. os_info derives this from GetNativeSystemInfo:
// AMD64 -> "x86_64", ARM64 -> "aarch64", INTEL -> "i386", ARM -> "arm".
func codexUAArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i386"
	case "arm":
		return "arm"
	default:
		return runtime.GOARCH
	}
}
