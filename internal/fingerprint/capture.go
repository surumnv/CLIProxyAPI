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
	"time"
)

// dummyAPIKey is passed to claude.exe so it walks the request path even when the
// user is not logged in. The request itself fails (we drop the connection after
// the ClientHello), but the handshake bytes are emitted first. claude.exe
// interactively prompts before using an unknown custom API key; under `-p` with
// piped stdout that prompt cannot render and the process hangs, so we
// pre-approve this key in ~/.claude.json (see approveAPIKey).
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
	ApproveAPIKey bool
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

	if opts.ApproveAPIKey {
		restore, aerr := approveAPIKey(dummyAPIKey)
		if aerr != nil {
			return nil, fmt.Errorf("approve dummy api key: %w", aerr)
		}
		defer restore()
	}

	proc := exec.Command(exe, "-p", prompt)
	proc.Env = append(os.Environ(),
		"ANTHROPIC_BASE_URL="+baseURL,
		"ANTHROPIC_API_KEY="+dummyAPIKey,
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
	)
	// Discard child output; we only care about the ClientHello on the wire.
	proc.Stdout = nil
	proc.Stderr = nil
	if err = proc.Start(); err != nil {
		return nil, fmt.Errorf("start claude: %w", err)
	}
	defer func() {
		if proc.Process != nil {
			_ = proc.Process.Kill()
		}
	}()

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
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, rerr := readTLSRecord(conn)
		ch <- readOut{raw: raw, err: rerr}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("read ClientHello: %w", r.err)
		}
		if _, _, err = ComputeJA3(r.raw); err != nil {
			return nil, fmt.Errorf("parse ClientHello: %w", err)
		}
		if _, err = SpecFromRaw(r.raw); err != nil {
			return nil, fmt.Errorf("validate ClientHello: %w", err)
		}
		return &CaptureResult{Raw: r.raw, ClaudeVersion: version}, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout: no connection within %s", timeout)
	}
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

// approveAPIKey adds the last-20-chars id of key to customApiKeyResponses.approved
// in ~/.claude.json so `claude -p` does not block on the interactive approval
// prompt. It returns a restore func that puts the file back to its prior bytes
// (always call it, even on later failure). A missing ~/.claude.json is treated
// as an error because claude will recreate it interactively and hang.
func approveAPIKey(key string) (restore func(), err error) {
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
	already := false
	for _, a := range resp.Approved {
		if a == id {
			already = true
			break
		}
	}
	if already {
		// Nothing to change; no-op restore.
		return func() {}, nil
	}
	resp.Approved = append(resp.Approved, id)
	newBlock, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	doc["customApiKeyResponses"] = newBlock
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(path, updated, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return func() { _ = os.WriteFile(path, orig, 0o600) }, nil
}

// errAutoDetectUnsupported is returned by defaultClaudePath on platforms without
// a known claude.exe install layout.
var errAutoDetectUnsupported = errors.New("auto-detecting the claude executable is only supported on Windows; supply an explicit path")
