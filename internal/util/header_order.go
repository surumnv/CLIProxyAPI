package util

import (
	"bytes"
	"context"
	"strings"
	"sync"
)

// OriginalHeaderLine records one inbound header line as it appeared on the wire.
type OriginalHeaderLine struct {
	LowerName string
	RawName   string
}

// OriginalHeaderOrder stores the first HTTP/1.1 request header order observed on
// a downstream connection.
type OriginalHeaderOrder struct {
	mu    sync.RWMutex
	lines []OriginalHeaderLine
}

// Set replaces the stored order with a defensive copy of lines.
func (o *OriginalHeaderOrder) Set(lines []OriginalHeaderLine) {
	if o == nil {
		return
	}
	cp := make([]OriginalHeaderLine, len(lines))
	copy(cp, lines)
	o.mu.Lock()
	o.lines = cp
	o.mu.Unlock()
}

// Lines returns a defensive copy of the stored order.
func (o *OriginalHeaderOrder) Lines() []OriginalHeaderLine {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if len(o.lines) == 0 {
		return nil
	}
	cp := make([]OriginalHeaderLine, len(o.lines))
	copy(cp, o.lines)
	return cp
}

type originalHeaderOrderContextKey struct{}

// WithOriginalHeaderOrder attaches the captured inbound header order to ctx.
func WithOriginalHeaderOrder(ctx context.Context, order *OriginalHeaderOrder) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if order == nil {
		return ctx
	}
	return context.WithValue(ctx, originalHeaderOrderContextKey{}, order)
}

// OriginalHeaderOrderFromContext returns the captured inbound header order, if any.
func OriginalHeaderOrderFromContext(ctx context.Context) *OriginalHeaderOrder {
	if ctx == nil {
		return nil
	}
	order, _ := ctx.Value(originalHeaderOrderContextKey{}).(*OriginalHeaderOrder)
	return order
}

// OriginalHeaderLinesFromContext returns a snapshot of the captured inbound header order.
func OriginalHeaderLinesFromContext(ctx context.Context) []OriginalHeaderLine {
	return OriginalHeaderOrderFromContext(ctx).Lines()
}

// ParseOriginalHeaderOrder extracts header names from a raw HTTP/1.x request head.
func ParseOriginalHeaderOrder(raw []byte) []OriginalHeaderLine {
	headEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	lineSep := []byte("\r\n")
	if headEnd < 0 {
		headEnd = bytes.Index(raw, []byte("\n\n"))
		lineSep = []byte("\n")
	}
	if headEnd < 0 {
		return nil
	}

	lines := bytes.Split(raw[:headEnd], lineSep)
	if len(lines) <= 1 {
		return nil
	}

	out := make([]OriginalHeaderLine, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		rawName := strings.TrimSpace(string(line[:colon]))
		if rawName == "" {
			continue
		}
		out = append(out, OriginalHeaderLine{
			LowerName: strings.ToLower(rawName),
			RawName:   rawName,
		})
	}
	return out
}
