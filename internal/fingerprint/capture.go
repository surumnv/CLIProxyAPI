package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// dummyAPIKey is passed to claude.exe so it walks the request path even when the
// user is not logged in. The request itself fails (we drop the connection after
// the ClientHello), but the handshake bytes are emitted first. claude.exe
// interactively prompts before using an unknown custom API key; under `-p` with
// piped stdout that prompt cannot render and the process hangs, so we
// pre-approve this key in ~/.claude.json (see prepareClaudeJSON).
const dummyAPIKey = "sk-ant-capture-dummy"

// CaptureOptions controls a ClientHello capture run.
type CaptureOptions struct {
	// ClaudePath is the claude.exe to launch. Empty means auto-detect the newest
	// installed version (platform-specific; unsupported off Windows).
	ClaudePath string
	// Prompt is passed to `claude -p` to trigger a request. Defaults to "hi".
	Prompt string
	// Timeout bounds the whole capture (waiting for the first connection).
	// Defaults to 30s.
	Timeout time.Duration
	// ApproveAPIKey, when true, pre-approves the dummy key in ~/.claude.json
	// (with backup/restore) so `claude -p` does not hang on the approval prompt.
	// It also pre-marks the working directory as trusted/onboarded so claude
	// never blocks on a trust or first-run prompt tied to that directory.
	ApproveAPIKey bool
	// WorkDir is the working directory for the launched claude process. Empty
	// means create (and remove afterward) a fresh empty temp dir that CPA
	// controls. Running in a controlled, pre-trusted empty dir means the capture
	// does not depend on wherever the server itself was started from — claude
	// cannot block on a "trust this folder?" prompt for the server's cwd.
	WorkDir string
}

// CaptureResult is the outcome of a successful capture.
type CaptureResult struct {
	Raw           []byte
	ClaudeVersion string // version dir name, when auto-detected
}

// Capture launches claude.exe against a throwaway local listener and returns the
// raw ClientHello it emits. It does not touch the persisted fingerprint; callers
// pass the result to Store.Set to make it active.
func Capture(opts CaptureOptions) (*CaptureResult, error) {
	prompt := opts.Prompt
	if strings.TrimSpace(prompt) == "" {
		prompt = "hi"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	exe := strings.TrimSpace(opts.ClaudePath)
	version := ""
	if exe == "" {
		detected, ver, err := defaultClaudePath()
		if err != nil {
			return nil, fmt.Errorf("locate claude executable: %w", err)
		}
		exe, version = detected, ver
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = ln.Close() }()
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)

	// Determine the working directory for claude. Default to a fresh empty temp
	// dir under CPA's control so the capture never inherits the server's cwd and
	// cannot stall on a trust/onboarding prompt tied to that directory.
	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		tmp, terr := os.MkdirTemp("", "claude-ja3-capture-")
		if terr != nil {
			return nil, fmt.Errorf("create capture work dir: %w", terr)
		}
		workDir = tmp
		// Remove the temp dir on exit. On Windows a just-killed claude.exe may
		// briefly still hold a handle to its cwd, so retry a few times before
		// giving up (an empty temp dir left behind is harmless, not fatal).
		defer func() { removeWithRetry(tmp) }()
		// claude also writes a session transcript under
		// ~/.claude/projects/<encoded-cwd>/ keyed by the cwd it launched with.
		// That directory is NOT covered by the ~/.claude.json restore, so remove
		// it too or repeated captures would slowly accumulate transcript dirs.
		// We only do this for the temp dir we created — its name always contains
		// the unique "claude-ja3-capture-<n>" marker, so it can never collide with
		// a real project's transcript directory.
		defer func() { removeCaptureTranscriptDir(tmp) }()
	}

	if opts.ApproveAPIKey {
		restore, aerr := prepareClaudeJSON(dummyAPIKey, workDir)
		if aerr != nil {
			return nil, fmt.Errorf("prepare claude config: %w", aerr)
		}
		defer restore()
	}

	proc := exec.Command(exe, "-p", prompt)
	proc.Dir = workDir
	proc.Env = append(os.Environ(),
		"ANTHROPIC_BASE_URL="+baseURL,
		"ANTHROPIC_API_KEY="+dummyAPIKey,
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		// Skip the first-run trust/onboarding prompt. Without a TTY that prompt
		// cannot render and `claude -p` blocks forever, so the child never
		// reaches the request path and no ClientHello is emitted.
		"CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1",
		"CI=1",
		"IS_DEMO=1",
		// The bundled Claude Desktop CLI (installed under Claude-3p\claude-code)
		// is meant to run as a child of Claude Desktop, which always passes this
		// marker. Without it that build silently hangs at startup before ever
		// dialing out — it never emits stderr or a ClientHello. A normal
		// interactive shell that launched `claude` once inherits the value, which
		// is why the capture works from a terminal but hangs when spawned by the
		// CPA service (whose environment lacks it). Set it explicitly so the
		// capture does not depend on the server's inherited environment.
		"CLAUDE_CODE_ENTRYPOINT=claude-desktop-3p",
	)
	// Feed EOF on stdin so any interactive read returns immediately instead of
	// blocking forever (there is no TTY behind a spawned management request).
	proc.Stdin = strings.NewReader("")
	// Discard stdout, but keep stderr so a failed launch (bad cwd, trust prompt,
	// onboarding) surfaces in the timeout error instead of an opaque hang.
	proc.Stdout = nil
	var stderr strings.Builder
	proc.Stderr = &stderr
	started := time.Now()
	if err = proc.Start(); err != nil {
		return nil, fmt.Errorf("start claude: %w", err)
	}
	pid := 0
	if proc.Process != nil {
		pid = proc.Process.Pid
	}
	log.WithFields(log.Fields{
		"exe":     exe,
		"version": version,
		"pid":     pid,
		"baseURL": baseURL,
		"timeout": timeout.String(),
	}).Debug("claude-ja3 capture: launched claude.exe, waiting for ClientHello")
	defer func() {
		if proc.Process != nil {
			_ = proc.Process.Kill()
		}
	}()

	// Watch for early child exit so we fail fast with its stderr rather than
	// waiting out the full timeout when claude.exe never dials the listener.
	exitCh := make(chan error, 1)
	go func() { exitCh <- proc.Wait() }()

	// dialed flips to true the moment the child opens a TCP connection to the
	// listener. It lets the timeout branch distinguish "claude never connected"
	// (likely blocked on an interactive prompt) from "connected but sent no
	// readable ClientHello" (a protocol/read problem).
	var dialed atomic.Bool

	type readOut struct {
		raw []byte
		err error
	}
	ch := make(chan readOut, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- readOut{err: aerr}
			return
		}
		dialed.Store(true)
		log.WithField("remote", conn.RemoteAddr().String()).
			Debug("claude-ja3 capture: claude.exe connected, reading ClientHello")
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, rerr := readTLSRecord(conn)
		ch <- readOut{raw: raw, err: rerr}
	}()

	childErr := func(exitErr error) string {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		switch {
		case msg != "" && exitErr != nil:
			return fmt.Sprintf("%v; claude stderr: %s", exitErr, msg)
		case msg != "":
			return "claude stderr: " + msg
		case exitErr != nil:
			return exitErr.Error()
		default:
			return ""
		}
	}

	for {
		select {
		case r := <-ch:
			if r.err != nil {
				if detail := childErr(nil); detail != "" {
					return nil, fmt.Errorf("read ClientHello: %w (%s)", r.err, detail)
				}
				return nil, fmt.Errorf("read ClientHello: %w", r.err)
			}
			if _, _, err = ComputeJA3(r.raw); err != nil {
				return nil, fmt.Errorf("parse ClientHello: %w", err)
			}
			if _, err = SpecFromRaw(r.raw); err != nil {
				return nil, fmt.Errorf("validate ClientHello: %w", err)
			}
			log.WithFields(log.Fields{
				"pid":     pid,
				"version": version,
				"elapsed": time.Since(started).Round(time.Millisecond).String(),
				"bytes":   len(r.raw),
			}).Debug("claude-ja3 capture: ClientHello captured")
			return &CaptureResult{Raw: r.raw, ClaudeVersion: version}, nil
		case exitErr := <-exitCh:
			// claude.exe exited before dialing the listener. Give the Accept
			// goroutine a brief grace window in case the connection landed
			// just before exit, then fail with whatever the child reported.
			select {
			case r := <-ch:
				if r.err == nil {
					if _, _, e := ComputeJA3(r.raw); e == nil {
						if _, e = SpecFromRaw(r.raw); e == nil {
							return &CaptureResult{Raw: r.raw, ClaudeVersion: version}, nil
						}
					}
				}
			case <-time.After(500 * time.Millisecond):
			}
			detail := childErr(exitErr)
			log.WithFields(log.Fields{
				"pid":     pid,
				"elapsed": time.Since(started).Round(time.Millisecond).String(),
				"stderr":  detail,
			}).Warn("claude-ja3 capture: claude exited before connecting")
			if detail != "" {
				return nil, fmt.Errorf("claude exited before connecting: %s", detail)
			}
			return nil, fmt.Errorf("claude exited before connecting without emitting a ClientHello")
		case <-time.After(timeout):
			connected := dialed.Load()
			// Reaching here means neither a ClientHello nor an early exit arrived
			// within the deadline, so the child is almost certainly still running.
			// Do a non-blocking check on exitCh to be certain (and to catch the
			// rare race where exit and timeout became ready together). This is
			// cross-platform, unlike a Signal(0) liveness probe (unsupported on
			// Windows for a running process).
			exited := false
			select {
			case <-exitCh:
				exited = true
			default:
			}
			detail := childErr(nil)
			log.WithFields(log.Fields{
				"pid":       pid,
				"elapsed":   time.Since(started).Round(time.Millisecond).String(),
				"connected": connected,
				"exited":    exited,
				"stderr":    detail,
			}).Warn("claude-ja3 capture: timed out waiting for ClientHello")

			// Name the most likely cause. The three cases we can distinguish are
			// meaningfully different to act on:
			//   - connected but no readable record: a TLS/read problem, not a hang;
			//   - never connected + still running: claude is stuck (interactive
			//     prompt, slow cold start, or blocked before it dials);
			//   - never connected + already gone: it died silently (see stderr).
			var cause string
			switch {
			case connected:
				cause = "claude connected but sent no readable ClientHello before the deadline"
			case exited:
				cause = "claude never connected and is no longer running — it exited without emitting a ClientHello"
			default:
				cause = "claude never connected and is still running — it is likely blocked on an interactive prompt or a slow first-run/onboarding step"
			}
			if detail != "" {
				return nil, fmt.Errorf("timeout after %s: %s (%s)", timeout, cause, detail)
			}
			return nil, fmt.Errorf("timeout after %s: %s (claude produced no stderr)", timeout, cause)
		}
	}
}

// DetectClaudeVersion returns the version-dir name of the newest locally
// installed Claude Code CLI (auto-detected; Windows only). It does not launch
// anything — it only inspects the install layout. Off Windows it returns the
// same "unsupported" error as auto-detected capture.
func DetectClaudeVersion() (string, error) {
	_, version, err := defaultClaudePath()
	if err != nil {
		return "", err
	}
	return version, nil
}

// RawHex returns the captured ClientHello as a lowercase hex string.
func (r *CaptureResult) RawHex() string {
	if r == nil {
		return ""
	}
	return hex.EncodeToString(r.Raw)
}

// readTLSRecord reads one full TLS record (5-byte header + payload).
func readTLSRecord(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 { // handshake
		return nil, fmt.Errorf("first record is not a handshake (type=0x%02x)", hdr[0])
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, recLen)
	if _, err := readFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// removeWithRetry deletes dir, retrying briefly to tolerate Windows still
// holding the cwd handle of a just-killed child process. A leftover empty temp
// dir is harmless, so failure is swallowed after the final attempt.
func removeWithRetry(dir string) {
	for i := 0; i < 10; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// removeCaptureTranscriptDir deletes the ~/.claude/projects/<encoded> transcript
// directory that claude creates for the given launch cwd, so captures don't leave
// session records behind. claude derives the directory name by replacing every
// character of the absolute cwd that is not an ASCII letter or digit with '-'
// (e.g. "C:\Users\me\...\claude-ja3-capture-42" -> "C--Users-me-...-claude-ja3-capture-42").
// cwd must be a capture temp dir (its name carries the unique "claude-ja3-capture-"
// marker); this never touches a real project's transcripts. Best-effort: any error
// (no HOME, dir absent, still-locked) is ignored, and a missing dir is not created.
func removeCaptureTranscriptDir(cwd string) {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return
	}
	// Guard: only ever remove our own capture dirs, never anything else.
	if !strings.Contains(filepath.Base(abs), "claude-ja3-capture-") {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return
	}
	encoded := encodeClaudeProjectDir(abs)
	target := filepath.Join(home, ".claude", "projects", encoded)
	if _, statErr := os.Stat(target); statErr != nil {
		return // nothing to clean
	}
	removeWithRetry(target)
}

// encodeClaudeProjectDir mirrors how claude names ~/.claude/projects entries:
// every rune that is not an ASCII letter or digit becomes '-'. Verified against
// live entries (drive colon, path separators, dots and underscores all map to '-').
func encodeClaudeProjectDir(absPath string) string {
	var b strings.Builder
	b.Grow(len(absPath))
	for _, r := range absPath {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// prepareClaudeJSON edits ~/.claude.json so `claude -p` runs non-interactively
// during a capture. It does two things in a single read/write (so the paired
// restore can undo both):
//
//   - approves the dummy API key (customApiKeyResponses.approved) so claude does
//     not block on the key-approval prompt;
//   - marks workDir as an already-trusted, already-onboarded project so claude
//     does not block on the "do you trust this folder?" dialog when it launches
//     with that directory as its cwd.
//
// It returns a restore func that puts the file back to its prior bytes (always
// call it, even on later failure). A missing ~/.claude.json is treated as an
// error because claude would recreate it interactively and hang.
func prepareClaudeJSON(key, workDir string) (restore func(), err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".claude.json")
	orig, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(orig, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	changed := false

	// 1. Approve the dummy API key.
	type approvals struct {
		Approved []string `json:"approved"`
		Rejected []string `json:"rejected"`
	}
	var resp approvals
	if raw, ok := doc["customApiKeyResponses"]; ok {
		_ = json.Unmarshal(raw, &resp)
	}
	id := key
	if len(id) > 20 {
		id = id[len(id)-20:]
	}
	// Drop from rejected, add to approved if absent.
	filtered := resp.Rejected[:0]
	for _, r := range resp.Rejected {
		if r != id {
			filtered = append(filtered, r)
		}
	}
	resp.Rejected = filtered
	approved := false
	for _, a := range resp.Approved {
		if a == id {
			approved = true
			break
		}
	}
	if !approved {
		resp.Approved = append(resp.Approved, id)
		newBlock, merr := json.Marshal(resp)
		if merr != nil {
			return nil, merr
		}
		doc["customApiKeyResponses"] = newBlock
		changed = true
	}

	// 2. Pre-trust workDir as a project so the trust/onboarding dialog is skipped
	//    when claude launches with it as cwd. We merge into any existing project
	//    entry rather than clobbering it, and only rewrite when something changed.
	if trustChanged, terr := ensureTrustedProject(doc, workDir); terr != nil {
		return nil, terr
	} else if trustChanged {
		changed = true
	}

	if !changed {
		// Nothing to change; no-op restore.
		return func() {}, nil
	}

	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(path, updated, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return func() { _ = os.WriteFile(path, orig, 0o600) }, nil
}

// ensureTrustedProject sets hasTrustDialogAccepted and the onboarding markers on
// doc.projects[workDir], preserving any other fields already present on that
// entry. It reports whether the document was modified. claude keys projects by
// the exact cwd string it launches with, so workDir must match proc.Dir.
func ensureTrustedProject(doc map[string]json.RawMessage, workDir string) (bool, error) {
	if strings.TrimSpace(workDir) == "" {
		return false, nil
	}
	projects := map[string]map[string]json.RawMessage{}
	if raw, ok := doc["projects"]; ok {
		if err := json.Unmarshal(raw, &projects); err != nil {
			return false, fmt.Errorf("parse projects: %w", err)
		}
	}
	entry := projects[workDir]
	if entry == nil {
		entry = map[string]json.RawMessage{}
	}

	// Desired values that suppress the interactive trust/onboarding prompts.
	trueRaw := json.RawMessage("true")
	want := map[string]json.RawMessage{
		"hasTrustDialogAccepted":                 trueRaw,
		"hasCompletedProjectOnboarding":          trueRaw,
		"hasClaudeMdExternalIncludesApproved":    trueRaw,
		"hasClaudeMdExternalIncludesWarningShown": trueRaw,
	}
	changed := false
	for k, v := range want {
		if cur, ok := entry[k]; !ok || string(cur) != string(v) {
			entry[k] = v
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	projects[workDir] = entry
	block, err := json.Marshal(projects)
	if err != nil {
		return false, err
	}
	doc["projects"] = block
	return true, nil
}

// errAutoDetectUnsupported is returned by defaultClaudePath on platforms without
// a known claude.exe install layout.
var errAutoDetectUnsupported = errors.New("auto-detecting the claude executable is only supported on Windows; supply an explicit path")
