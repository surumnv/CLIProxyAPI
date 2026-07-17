package util

import (
	"net/http"
	"strings"
)

// ApplyCustomHeadersFromAttrs applies user-defined headers stored in the provided attributes map.
// Custom headers override built-in defaults when conflicts occur.
func ApplyCustomHeadersFromAttrs(r *http.Request, attrs map[string]string) {
	if r == nil {
		return
	}
	applyCustomHeaders(r, extractCustomHeaders(attrs))
}

// passthroughHeaderDenylist lists headers that must NOT be copied verbatim from
// an inbound client request onto an outgoing upstream request. The proxy rewrites
// the request body and target, and net/http manages these itself; forwarding the
// inbound values would produce a wrong Content-Length, a wrong Host, break hop-by-hop
// semantics, or defeat transparent gzip handling.
//
// NOTE on the last four entries (Content-Encoding, Expect, Cookie,
// Proxy-Authorization): none of these appeared in the real captured request
// headers from Claude Desktop or Codex that this passthrough is built to
// preserve. They are denylisted defensively — if a future client (or a
// misbehaving intermediary) ever adds one, forwarding it verbatim onto a
// re-serialized request would corrupt the body framing (Content-Encoding),
// stall the exchange (Expect), or leak inbound-hop credentials to a third-party
// upstream (Cookie / Proxy-Authorization). Denylisting them now costs nothing
// for the observed clients and closes those holes ahead of time.
var passthroughHeaderDenylist = map[string]struct{}{
	"Content-Length":    {},
	"Host":              {},
	"Connection":        {},
	"Proxy-Connection":  {},
	"Keep-Alive":        {},
	"Transfer-Encoding": {},
	"Te":                {},
	"Trailer":           {},
	"Upgrade":           {},
	"Accept-Encoding":   {},
	// Content-Encoding describes the framing of the *inbound* body. Every executor
	// re-serializes the request body to plain (uncompressed) JSON or rebuilds the
	// multipart form before sending, so forwarding the inbound encoding would tell
	// the upstream the body is e.g. gzip when it is not, corrupting the request.
	// Not present in any observed Claude Desktop / Codex capture; denylisted
	// defensively.
	"Content-Encoding": {},
	// Expect: 100-continue is meaningless for our re-serialized, known-length
	// bodies (we write the head and body without waiting for a 100 response) and
	// can stall or confuse upstreams; drop it rather than forward it verbatim.
	// Not present in any observed Claude Desktop / Codex capture; denylisted
	// defensively.
	"Expect": {},
	// Cookie / Proxy-Authorization are session/credential material scoped to the
	// inbound hop. Forwarding them to a third-party upstream both leaks the
	// client's session and is a fingerprint anomaly (real Codex/Claude clients do
	// not send them upstream). They are never part of the headers we want to
	// faithfully pass through. Not present in any observed Claude Desktop / Codex
	// capture; denylisted defensively.
	"Cookie":              {},
	"Proxy-Authorization": {},
}

// CopyInboundHeaders copies headers from the inbound client request (src) onto the
// outgoing upstream request r, so that as much of the original request as possible
// is preserved. Headers the proxy must manage itself are skipped (see
// passthroughHeaderDenylist), and any header names passed in skip are ignored so the
// caller can keep authoritative control over them (e.g. a User-Agent governed by
// config precedence). Values already present on r are preserved and never clobbered,
// which lets the caller set authoritative headers (Authorization, Content-Type, ...)
// either before or after this call.
func CopyInboundHeaders(r *http.Request, src http.Header, skip ...string) {
	if r == nil || len(src) == 0 {
		return
	}
	skipSet := make(map[string]struct{}, len(skip))
	for _, s := range skip {
		if s == "" {
			continue
		}
		skipSet[http.CanonicalHeaderKey(s)] = struct{}{}
	}
	for key, values := range src {
		canonical := http.CanonicalHeaderKey(key)
		if _, blocked := passthroughHeaderDenylist[canonical]; blocked {
			continue
		}
		if _, skipped := skipSet[canonical]; skipped {
			continue
		}
		if strings.TrimSpace(r.Header.Get(key)) != "" {
			// Preserve whatever the proxy already set on this key.
			continue
		}
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				continue
			}
			r.Header.Add(key, v)
		}
	}
}

func extractCustomHeaders(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	headers := make(map[string]string)
	for k, v := range attrs {
		if !strings.HasPrefix(k, "header:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(k, "header:"))
		if name == "" {
			continue
		}
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		headers[name] = val
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func applyCustomHeaders(r *http.Request, headers map[string]string) {
	if r == nil || len(headers) == 0 {
		return
	}
	for k, v := range headers {
		if k == "" || v == "" {
			continue
		}
		// net/http reads Host from req.Host (not req.Header) when writing
		// a real request, so we must mirror it there. Some callers pass
		// synthetic requests (e.g. &http.Request{Header: ...}) and only
		// consume r.Header afterwards, so keep the value in the header
		// map too.
		if http.CanonicalHeaderKey(k) == "Host" {
			r.Host = v
		}
		r.Header.Set(k, v)
	}
}
