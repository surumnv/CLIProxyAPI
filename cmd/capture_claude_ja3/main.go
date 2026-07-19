// Command capture_claude_ja3 captures the real TLS ClientHello that the bundled
// Claude Code CLI (claude.exe) emits, then derives its JA3 fingerprint.
//
// It works without Wireshark and without decrypting anything: a ClientHello is
// the first plaintext TLS record on a fresh TCP connection, so we just start a
// local TCP listener, point claude.exe's API base URL at it, and read the first
// record off the wire. The handshake then fails (we present no certificate) but
// by that point we already have the ClientHello bytes.
//
// The capture engine lives in internal/fingerprint; this command is a thin CLI
// around it. The same package powers the runtime forwarding path and the
// POST /v0/management/claude-ja3/capture management endpoint, so the JA3 printed
// here is exactly what CPA reproduces on the wire.
//
// Usage (Windows, from the repo root):
//
//	go run ./cmd/capture_claude_ja3
//	go run ./cmd/capture_claude_ja3 -claude "C:\path\to\claude.exe"
//	go run ./cmd/capture_claude_ja3 -launch=false   # then trigger claude yourself
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
)

func main() {
	claudePath := flag.String("claude", "", "path to claude.exe (default: newest under %LOCALAPPDATA%\\Claude-3p\\claude-code)")
	port := flag.Int("port", 0, "local TCP port to listen on for -launch=false (0 = pick a free one)")
	launch := flag.Bool("launch", true, "auto-launch claude.exe pointed at the local port")
	prompt := flag.String("prompt", "hi", "prompt passed to claude -p to trigger a request")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to wait for the first connection")
	flag.Parse()

	var raw []byte
	if *launch {
		res, err := fingerprint.Capture(fingerprint.CaptureOptions{
			ClaudePath:    *claudePath,
			Prompt:        *prompt,
			Timeout:       *timeout,
			ApproveAPIKey: true,
		})
		if err != nil {
			fatal("capture:", err)
		}
		raw = res.Raw
		if res.ClaudeVersion != "" {
			fmt.Println("claude version:", res.ClaudeVersion)
		}
	} else {
		raw = captureManually(*port, *prompt, *timeout)
	}

	// Derive JA3 (ground truth) and validate the utls spec round-trips.
	ja3Str, ja3Hash, err := fingerprint.ComputeJA3(raw)
	if err != nil {
		fatal("parse ClientHello:", err)
	}
	spec, ferr := fingerprint.SpecFromRaw(raw)

	fmt.Println()
	fmt.Println("==== Claude Code ClientHello captured ====")
	fmt.Printf("record length : %d bytes\n", len(raw))
	fmt.Printf("JA3 string    : %s\n", ja3Str)
	fmt.Printf("JA3 hash      : %s\n", ja3Hash)
	if ferr != nil {
		fmt.Printf("utls spec     : FAILED to parse (%v)\n", ferr)
	} else {
		fmt.Printf("utls spec     : OK (%d cipher suites, %d extensions)\n", len(spec.CipherSuites), len(spec.Extensions))
	}
	fmt.Println()
	fmt.Println("raw ClientHello (hex):")
	fmt.Println(hex.EncodeToString(raw))
	fmt.Println()
	fmt.Println("Store it via: PUT /v0/management/claude-ja3  {\"raw_hex\":\"<hex above>\"}")
}

// captureManually runs the -launch=false path: it prints instructions and waits
// for the operator to point a claude command at the printed base URL.
func captureManually(port int, prompt string, timeout time.Duration) []byte {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fatal("listen:", err)
	}
	defer func() { _ = ln.Close() }()
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
	fmt.Printf("listening on %s (base url %s)\n", ln.Addr(), baseURL)
	fmt.Println()
	fmt.Println("Auto-launch disabled. In another terminal, run any claude command with:")
	fmt.Printf("  set ANTHROPIC_BASE_URL=%s\n", baseURL)
	fmt.Printf("  set ANTHROPIC_API_KEY=sk-ant-capture-dummy\n")
	fmt.Printf("  claude -p \"%s\"\n", prompt)
	fmt.Println()

	type result struct {
		raw []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- result{err: aerr}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, rerr := readTLSRecord(conn)
		ch <- result{raw: raw, err: rerr}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			fatal("read ClientHello:", r.err)
		}
		return r.raw
	case <-time.After(timeout):
		fatal("timeout:", errors.New("no connection within "+timeout.String()))
		return nil
	}
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

func fatal(prefix string, err error) {
	fmt.Fprintln(os.Stderr, prefix, err)
	os.Exit(1)
}
