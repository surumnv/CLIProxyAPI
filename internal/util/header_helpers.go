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
