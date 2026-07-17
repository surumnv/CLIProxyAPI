package util

import "testing"

func TestParseOriginalHeaderOrderPreservesWireOrderAndCase(t *testing.T) {
	t.Parallel()

	raw := []byte("POST /v1/messages HTTP/1.1\r\nhost: local\r\nUser-Agent: codex\r\nX-Custom: one\r\nx-custom: two\r\nContent-Length: 2\r\n\r\n{}")
	lines := ParseOriginalHeaderOrder(raw)

	want := []OriginalHeaderLine{
		{LowerName: "host", RawName: "host"},
		{LowerName: "user-agent", RawName: "User-Agent"},
		{LowerName: "x-custom", RawName: "X-Custom"},
		{LowerName: "x-custom", RawName: "x-custom"},
		{LowerName: "content-length", RawName: "Content-Length"},
	}
	if len(lines) != len(want) {
		t.Fatalf("line count = %d, want %d: %#v", len(lines), len(want), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line[%d] = %#v, want %#v", i, lines[i], want[i])
		}
	}
}
