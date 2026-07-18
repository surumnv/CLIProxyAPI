//go:build windows

// Command schannelprobe dials a TLS fingerprint echo service through the
// SChannel-backed net.Conn and prints the JA3/JA4 the server observed, plus the
// negotiated protocol/cipher. Use it to compare CLIProxyAPI's SChannel
// ClientHello against a real Codex CLI capture.
//
//	go run ./cmd/schannelprobe                 # default: tls.peet.ws
//	go run ./cmd/schannelprobe -host tls.peet.ws -path /api/all
//	go run ./cmd/schannelprobe -strong         # add SCH_USE_STRONG_CRYPTO
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/schannel"
)

func main() {
	host := flag.String("host", "tls.peet.ws", "TLS fingerprint echo host")
	path := flag.String("path", "/api/all", "request path")
	port := flag.String("port", "443", "port")
	strong := flag.Bool("strong", false, "add SCH_USE_STRONG_CRYPTO to cred flags")
	proto := flag.Uint("proto", 0, "grbitEnabledProtocols (0=system default)")
	alpn := flag.String("alpn", "h2,http/1.1", "comma-separated ALPN list (empty to disable)")
	flag.Parse()

	addr := net.JoinHostPort(*host, *port)
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}

	cfg := schannel.Config{
		ServerName:       *host,
		HandshakeTimeout: 15 * time.Second,
		EnabledProtocols: uint32(*proto),
	}
	if *alpn != "" {
		cfg.ALPNProtocols = strings.Split(*alpn, ",")
	}
	if *strong {
		cfg.ExtraCredFlags |= schannel.SchUseStrongCrypto
	}

	conn, err := schannel.Client(raw, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "handshake:", err)
		raw.Close()
		os.Exit(1)
	}
	defer conn.Close()

	// Minimal HTTP/1.1 GET. Header order here is illustrative; the real
	// integration reuses the ordered-h1 writer.
	req := "GET " + *path + " HTTP/1.1\r\n" +
		"Host: " + *host + "\r\n" +
		"User-Agent: schannelprobe\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read response:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("status:", resp.Status)
	fmt.Println(string(body))
}
