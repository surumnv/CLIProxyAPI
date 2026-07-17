package helps

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/proxy"
)

type orderedH1RoundTripper struct {
	fallback       http.RoundTripper
	proxyDialer    proxy.Dialer
	useProxyDialer bool
	disabled       bool
}

func newOrderedH1RoundTripper(proxyURL string, fallback http.RoundTripper) http.RoundTripper {
	if fallback == nil {
		fallback = http.DefaultTransport
	}
	rt := &orderedH1RoundTripper{fallback: fallback}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return rt
	}
	dialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
	if errBuild != nil {
		log.Errorf("ordered h1: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		rt.disabled = true
		return rt
	}
	if mode != proxyutil.ModeInherit && dialer != nil {
		rt.proxyDialer = dialer
		rt.useProxyDialer = true
	}
	return rt
}

func (t *orderedH1RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	if t.disabled || !canUseOrderedH1(req) {
		return t.fallback.RoundTrip(req)
	}

	lines := util.OriginalHeaderLinesFromContext(req.Context())
	body, errBody := readAndCloseRequestBody(req)
	if errBody != nil {
		return nil, errBody
	}
	raw, errBuild := buildOrderedH1Request(req, body, lines)
	if errBuild != nil {
		return nil, errBuild
	}

	conn, errDial := t.dial(req)
	if errDial != nil {
		return nil, errDial
	}
	if req.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: req.URL.Hostname()})
		if errHandshake := tlsConn.Handshake(); errHandshake != nil {
			if errClose := conn.Close(); errClose != nil {
				return nil, fmt.Errorf("ordered h1 TLS handshake failed: %w; close failed: %v", errHandshake, errClose)
			}
			return nil, fmt.Errorf("ordered h1 TLS handshake failed: %w", errHandshake)
		}
		conn = tlsConn
	}

	if errWrite := writeAll(conn, raw); errWrite != nil {
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("ordered h1 write failed: %w; close failed: %v", errWrite, errClose)
		}
		return nil, fmt.Errorf("ordered h1 write failed: %w", errWrite)
	}

	resp, errRead := http.ReadResponse(bufio.NewReader(conn), req)
	if errRead != nil {
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("ordered h1 read response failed: %w; close failed: %v", errRead, errClose)
		}
		return nil, fmt.Errorf("ordered h1 read response failed: %w", errRead)
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &closeConnReadCloser{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

func canUseOrderedH1(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return false
	}
	if req.URL.Host == "" {
		return false
	}
	return len(util.OriginalHeaderLinesFromContext(req.Context())) > 0
}

func (t *orderedH1RoundTripper) dial(req *http.Request) (net.Conn, error) {
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(req.URL.Hostname(), port)
	if t.useProxyDialer && t.proxyDialer != nil {
		return t.proxyDialer.Dial("tcp", addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(req.Context(), "tcp", addr)
}

func readAndCloseRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer func() {
		if errClose := req.Body.Close(); errClose != nil {
			log.Errorf("ordered h1: request body close error: %v", errClose)
		}
	}()
	return io.ReadAll(req.Body)
}

func buildOrderedH1Request(req *http.Request, body []byte, lines []util.OriginalHeaderLine) ([]byte, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("ordered h1 request is nil")
	}
	var raw bytes.Buffer
	raw.Grow(4096 + len(body))

	target := req.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	raw.WriteString(req.Method)
	raw.WriteByte(' ')
	raw.WriteString(target)
	raw.WriteString(" HTTP/1.1\r\n")

	emittedCounts := make(map[string]int, len(lines))
	emittedHost := false
	emittedContentLength := false
	for _, line := range lines {
		lowerName := strings.ToLower(strings.TrimSpace(line.LowerName))
		if lowerName == "" {
			continue
		}
		rawName := strings.TrimSpace(line.RawName)
		if rawName == "" {
			rawName = http.CanonicalHeaderKey(lowerName)
		}
		switch lowerName {
		case "host":
			if emittedHost {
				continue
			}
			host := outboundHost(req)
			if host == "" {
				continue
			}
			if err := writeHeaderLine(&raw, rawName, host); err != nil {
				return nil, err
			}
			emittedHost = true
			emittedCounts[lowerName]++
		case "content-length":
			if emittedContentLength {
				continue
			}
			if err := writeHeaderLine(&raw, rawName, fmt.Sprintf("%d", len(body))); err != nil {
				return nil, err
			}
			emittedContentLength = true
			emittedCounts[lowerName]++
		case "transfer-encoding":
			continue
		default:
			_, values := headerValues(req.Header, lowerName)
			cursor := emittedCounts[lowerName]
			if cursor >= len(values) {
				continue
			}
			if err := writeHeaderLine(&raw, rawName, values[cursor]); err != nil {
				return nil, err
			}
			emittedCounts[lowerName] = cursor + 1
		}
	}

	if !emittedHost {
		host := outboundHost(req)
		if host != "" {
			if err := writeHeaderLine(&raw, "Host", host); err != nil {
				return nil, err
			}
			emittedHost = true
		}
	}

	keys := sortedHeaderKeys(req.Header)
	for _, key := range keys {
		lowerName := strings.ToLower(key)
		if lowerName == "host" || lowerName == "content-length" || lowerName == "transfer-encoding" {
			continue
		}
		values := req.Header[key]
		cursor := emittedCounts[lowerName]
		for _, value := range values[cursor:] {
			if err := writeHeaderLine(&raw, key, value); err != nil {
				return nil, err
			}
		}
	}

	if !emittedContentLength && len(body) > 0 {
		if err := writeHeaderLine(&raw, "Content-Length", fmt.Sprintf("%d", len(body))); err != nil {
			return nil, err
		}
	}

	raw.WriteString("\r\n")
	raw.Write(body)
	return raw.Bytes(), nil
}

func outboundHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if host := strings.TrimSpace(req.Host); host != "" {
		return host
	}
	if req.Header != nil {
		if host := strings.TrimSpace(req.Header.Get("Host")); host != "" {
			return host
		}
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

func headerValues(headers http.Header, lowerName string) (string, []string) {
	if len(headers) == 0 {
		return "", nil
	}
	canonical := http.CanonicalHeaderKey(lowerName)
	if values, ok := headers[canonical]; ok {
		return canonical, values
	}
	for key, values := range headers {
		if strings.EqualFold(key, lowerName) {
			return key, values
		}
	}
	return "", nil
}

func sortedHeaderKeys(headers http.Header) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeHeaderLine(raw *bytes.Buffer, name, value string) error {
	if !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("ordered h1 invalid header name %q", name)
	}
	if !httpguts.ValidHeaderFieldValue(value) {
		return fmt.Errorf("ordered h1 invalid header value for %q", name)
	}
	raw.WriteString(name)
	raw.WriteString(": ")
	raw.WriteString(value)
	raw.WriteString("\r\n")
	return nil
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, errWrite := conn.Write(data)
		if errWrite != nil {
			return errWrite
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type closeConnReadCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (c *closeConnReadCloser) Close() error {
	errBody := c.ReadCloser.Close()
	errConn := c.conn.Close()
	if errBody != nil {
		return errBody
	}
	return errConn
}
