package helps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/proxy"
)

const (
	orderedH1MaxIdlePerKey = 2
	orderedH1IdleTimeout   = 90 * time.Second
	orderedH1ProbeTimeout  = time.Millisecond
)

type orderedH1RoundTripper struct {
	fallback       http.RoundTripper
	proxyDialer    proxy.Dialer
	useProxyDialer bool
	disabled       bool

	mu   sync.Mutex
	idle map[string][]*orderedH1PersistConn
}

func newOrderedH1RoundTripper(proxyURL string, fallback http.RoundTripper) http.RoundTripper {
	if fallback == nil {
		fallback = http.DefaultTransport
	}
	rt := &orderedH1RoundTripper{
		fallback: fallback,
		idle:     make(map[string][]*orderedH1PersistConn),
	}
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

var sharedOrderedH1RoundTrippers sync.Map

func sharedOrderedH1CacheKey(proxyURL string, fallback http.RoundTripper) string {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		proxyURL = "direct"
	}
	if fallback == nil || fallback == http.DefaultTransport {
		return proxyURL + "|default"
	}
	return fmt.Sprintf("%s|%T|%p", proxyURL, fallback, fallback)
}

func sharedOrderedH1RoundTripper(proxyURL string, fallback http.RoundTripper) http.RoundTripper {
	if fallback == nil {
		fallback = http.DefaultTransport
	}
	key := sharedOrderedH1CacheKey(proxyURL, fallback)
	if cached, ok := sharedOrderedH1RoundTrippers.Load(key); ok {
		return cached.(http.RoundTripper)
	}
	rt := newOrderedH1RoundTripper(proxyURL, fallback)
	actual, _ := sharedOrderedH1RoundTrippers.LoadOrStore(key, rt)
	return actual.(http.RoundTripper)
}

func (t *orderedH1RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	if t.disabled || !canUseOrderedH1(req) {
		return t.fallback.RoundTrip(req)
	}

	lines := util.OriginalHeaderLinesFromContext(req.Context())
	return t.roundTripAttempt(req, lines, true)
}

func (t *orderedH1RoundTripper) roundTripAttempt(req *http.Request, lines []util.OriginalHeaderLine, retryReused bool) (*http.Response, error) {
	body, contentLength, ownsBody, errBody := openOrderedH1RequestBody(req)
	if errBody != nil {
		return nil, errBody
	}
	// closeBody closes the body used by this attempt. When ownsBody is false we
	// are streaming req.Body directly; only close it after the attempt finishes
	// for good (success or non-retryable failure), never before a retry that can
	// still re-read via GetBody.
	closeBody := func(force bool) {
		if body == nil {
			return
		}
		if !ownsBody && !force {
			return
		}
		if errClose := body.Close(); errClose != nil {
			log.Errorf("ordered h1: request body close error: %v", errClose)
		}
		body = nil
		ownsBody = false
	}
	defer closeBody(true)

	head, errBuild := buildOrderedH1RequestHead(req, contentLength, lines)
	if errBuild != nil {
		return nil, errBuild
	}

	pc, reused, errConn := t.getConn(req)
	if errConn != nil {
		return nil, errConn
	}

	if errWrite := writeAll(pc.conn, head); errWrite != nil {
		pc.close()
		if reused && retryReused {
			// Head was not accepted; body has not been consumed yet. Keep a
			// non-owned req.Body open so the retry can stream it once.
			if ownsBody {
				closeBody(true)
			}
			return t.roundTripAttempt(req, lines, false)
		}
		if errClose := pc.closeErr(); errClose != nil {
			return nil, fmt.Errorf("ordered h1 write failed: %w; close failed: %v", errWrite, errClose)
		}
		return nil, fmt.Errorf("ordered h1 write failed: %w", errWrite)
	}

	if body != nil && contentLength != 0 {
		if errCopy := copyOrderedH1RequestBody(pc.conn, body, contentLength); errCopy != nil {
			pc.close()
			// Body bytes may already be partially written; only retry when the
			// request can recreate the body via GetBody.
			if reused && retryReused && req.GetBody != nil {
				closeBody(true)
				return t.roundTripAttempt(req, lines, false)
			}
			if errClose := pc.closeErr(); errClose != nil {
				return nil, fmt.Errorf("ordered h1 body write failed: %w; close failed: %v", errCopy, errClose)
			}
			return nil, fmt.Errorf("ordered h1 body write failed: %w", errCopy)
		}
	}
	closeBody(true)

	resp, errRead := http.ReadResponse(pc.reader, req)
	if errRead != nil {
		pc.close()
		// Request body was fully written; retry only when GetBody can rebuild it
		// or there was no body.
		if reused && retryReused && (req.GetBody != nil || contentLength == 0) {
			return t.roundTripAttempt(req, lines, false)
		}
		if errClose := pc.closeErr(); errClose != nil {
			return nil, fmt.Errorf("ordered h1 read response failed: %w; close failed: %v", errRead, errClose)
		}
		return nil, fmt.Errorf("ordered h1 read response failed: %w", errRead)
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &orderedH1ResponseBody{
		ReadCloser:      resp.Body,
		pc:              pc,
		req:             req,
		resp:            resp,
		reusableOnClose: responseHasNoBody(req, resp),
	}
	return resp, nil
}

// openOrderedH1RequestBody returns the outbound body reader and the Content-Length
// that should be advertised. Known-length bodies are streamed; only unknown-length
// bodies are buffered so the request can still carry a Content-Length.
// ownsBody is true when the caller must Close the returned reader.
func openOrderedH1RequestBody(req *http.Request) (body io.ReadCloser, contentLength int64, ownsBody bool, err error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, 0, false, nil
	}
	if req.ContentLength == 0 {
		return nil, 0, false, nil
	}
	if req.ContentLength > 0 {
		if req.GetBody != nil {
			opened, errBody := req.GetBody()
			if errBody != nil {
				return nil, 0, false, errBody
			}
			return opened, req.ContentLength, true, nil
		}
		// Stream the original body once. Retries after body writes require GetBody.
		return req.Body, req.ContentLength, false, nil
	}

	// Unknown length: buffer once so we can emit Content-Length and optionally retry.
	defer func() {
		if errClose := req.Body.Close(); errClose != nil {
			log.Errorf("ordered h1: request body close error: %v", errClose)
		}
	}()
	data, errRead := io.ReadAll(req.Body)
	if errRead != nil {
		return nil, 0, false, errRead
	}
	req.Body = http.NoBody
	req.ContentLength = int64(len(data))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), true, nil
}

func copyOrderedH1RequestBody(conn net.Conn, body io.Reader, contentLength int64) error {
	if body == nil || contentLength == 0 {
		return nil
	}
	if contentLength > 0 {
		written, errCopy := io.Copy(conn, io.LimitReader(body, contentLength))
		if errCopy != nil {
			return errCopy
		}
		if written != contentLength {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	_, errCopy := io.Copy(conn, body)
	return errCopy
}

func (t *orderedH1RoundTripper) getConn(req *http.Request) (*orderedH1PersistConn, bool, error) {
	key := orderedH1ConnKey(req)
	for {
		t.mu.Lock()
		idle := t.idle[key]
		if n := len(idle); n > 0 {
			pc := idle[n-1]
			t.idle[key] = idle[:n-1]
			if len(t.idle[key]) == 0 {
				delete(t.idle, key)
			}
			t.mu.Unlock()
			if pc.alive() {
				return pc, true, nil
			}
			pc.close()
			continue
		}
		t.mu.Unlock()
		break
	}

	conn, errDial := t.dial(req)
	if errDial != nil {
		return nil, false, errDial
	}
	if req.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: req.URL.Hostname()})
		if errHandshake := tlsConn.HandshakeContext(req.Context()); errHandshake != nil {
			if errClose := conn.Close(); errClose != nil {
				return nil, false, fmt.Errorf("ordered h1 TLS handshake failed: %w; close failed: %v", errHandshake, errClose)
			}
			return nil, false, fmt.Errorf("ordered h1 TLS handshake failed: %w", errHandshake)
		}
		conn = tlsConn
	}
	return &orderedH1PersistConn{
		conn:   conn,
		reader: bufio.NewReader(conn),
		key:    key,
		rt:     t,
	}, false, nil
}

func (t *orderedH1RoundTripper) putIdle(pc *orderedH1PersistConn) {
	if t == nil || pc == nil || pc.conn == nil {
		return
	}
	pc.idleAt = time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.idle[pc.key]) >= orderedH1MaxIdlePerKey {
		pc.close()
		return
	}
	t.idle[pc.key] = append(t.idle[pc.key], pc)
}

func (t *orderedH1RoundTripper) CloseIdleConnections() {
	if t == nil {
		return
	}
	t.mu.Lock()
	idle := t.idle
	t.idle = make(map[string][]*orderedH1PersistConn)
	t.mu.Unlock()
	for _, conns := range idle {
		for _, pc := range conns {
			pc.close()
		}
	}
	if closer, ok := t.fallback.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
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
	ctx := context.Background()
	if req != nil && req.Context() != nil {
		ctx = req.Context()
	}
	if t.useProxyDialer && t.proxyDialer != nil {
		return dialProxyContext(ctx, t.proxyDialer, "tcp", addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr)
}

func dialProxyContext(ctx context.Context, dialer proxy.Dialer, network, addr string) (net.Conn, error) {
	if dialer == nil {
		return nil, fmt.Errorf("ordered h1 proxy dialer is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, network, addr)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, errDial := dialer.Dial(network, addr)
		ch <- dialResult{conn: conn, err: errDial}
	}()

	select {
	case <-ctx.Done():
		go func() {
			res := <-ch
			if res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

func orderedH1ConnKey(req *http.Request) string {
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(strings.ToLower(req.URL.Hostname()), port)
	return req.URL.Scheme + "://" + addr
}

func buildOrderedH1RequestHead(req *http.Request, contentLength int64, lines []util.OriginalHeaderLine) ([]byte, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("ordered h1 request is nil")
	}
	var raw bytes.Buffer
	raw.Grow(4096)

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
			if contentLength < 0 {
				continue
			}
			if err := writeHeaderLine(&raw, rawName, fmt.Sprintf("%d", contentLength)); err != nil {
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

	if !emittedContentLength && contentLength > 0 {
		if err := writeHeaderLine(&raw, "Content-Length", fmt.Sprintf("%d", contentLength)); err != nil {
			return nil, err
		}
	}

	raw.WriteString("\r\n")
	return raw.Bytes(), nil
}

// buildOrderedH1Request remains for tests that assert the full wire image of small bodies.
func buildOrderedH1Request(req *http.Request, body []byte, lines []util.OriginalHeaderLine) ([]byte, error) {
	head, err := buildOrderedH1RequestHead(req, int64(len(body)), lines)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return head, nil
	}
	out := make([]byte, 0, len(head)+len(body))
	out = append(out, head...)
	out = append(out, body...)
	return out, nil
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

type orderedH1PersistConn struct {
	conn   net.Conn
	reader *bufio.Reader
	key    string
	rt     *orderedH1RoundTripper
	err    error
	idleAt time.Time
}

func (c *orderedH1PersistConn) close() {
	if c == nil || c.conn == nil {
		return
	}
	c.err = c.conn.Close()
	c.conn = nil
}

func (c *orderedH1PersistConn) closeErr() error {
	if c == nil {
		return nil
	}
	return c.err
}

func (c *orderedH1PersistConn) alive() bool {
	if c == nil || c.conn == nil || c.reader == nil {
		return false
	}
	if !c.idleAt.IsZero() && time.Since(c.idleAt) > orderedH1IdleTimeout {
		return false
	}
	if c.reader.Buffered() != 0 {
		return false
	}
	if errDeadline := c.conn.SetReadDeadline(time.Now().Add(orderedH1ProbeTimeout)); errDeadline != nil {
		return false
	}
	defer func() {
		_ = c.conn.SetReadDeadline(time.Time{})
	}()

	_, errPeek := c.reader.Peek(1)
	if errPeek == nil {
		// Unexpected buffered data means the connection is no longer idle/clean.
		return false
	}
	if netErr, ok := errPeek.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

type orderedH1ResponseBody struct {
	io.ReadCloser
	pc              *orderedH1PersistConn
	req             *http.Request
	resp            *http.Response
	reusableOnClose bool

	mu     sync.Mutex
	sawEOF bool
	closed bool
}

func (b *orderedH1ResponseBody) Read(p []byte) (int, error) {
	n, errRead := b.ReadCloser.Read(p)
	if errRead == io.EOF {
		b.mu.Lock()
		b.sawEOF = true
		b.mu.Unlock()
	}
	return n, errRead
}

func (b *orderedH1ResponseBody) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	reusable := b.reusableOnClose || b.sawEOF
	b.mu.Unlock()

	errBody := b.ReadCloser.Close()
	if errBody != nil {
		b.pc.close()
		return errBody
	}
	if reusable && canReuseOrderedH1Conn(b.req, b.resp, b.pc) {
		b.pc.rt.putIdle(b.pc)
		return nil
	}
	b.pc.close()
	return b.pc.closeErr()
}

func canReuseOrderedH1Conn(req *http.Request, resp *http.Response, pc *orderedH1PersistConn) bool {
	if req == nil || resp == nil || pc == nil || pc.conn == nil || pc.reader == nil {
		return false
	}
	if req.Close || resp.Close {
		return false
	}
	if hasConnectionClose(req.Header) || hasConnectionClose(resp.Header) {
		return false
	}
	if pc.reader.Buffered() != 0 {
		return false
	}
	return responseHasKnownEnd(req, resp)
}

func responseHasKnownEnd(req *http.Request, resp *http.Response) bool {
	if responseHasNoBody(req, resp) {
		return true
	}
	if resp.ContentLength >= 0 {
		return true
	}
	for _, encoding := range resp.TransferEncoding {
		if strings.EqualFold(encoding, "chunked") {
			return true
		}
	}
	return false
}

func responseHasNoBody(req *http.Request, resp *http.Response) bool {
	if req != nil && req.Method == http.MethodHead {
		return true
	}
	if resp == nil {
		return false
	}
	return (resp.StatusCode >= 100 && resp.StatusCode <= 199) ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified
}

func hasConnectionClose(headers http.Header) bool {
	for _, rawValue := range headers.Values("Connection") {
		for _, token := range strings.Split(rawValue, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				return true
			}
		}
	}
	return false
}

