package helps

import (
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

func TestBuildOrderedH1RequestUsesOriginalPositionsWithFinalValues(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "https://upstream.example/v1/messages?beta=true", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "target.example"
	req.Header.Set("User-Agent", "claude-cli/2.1.63")
	req.Header.Set("Authorization", "Bearer regenerated")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Client", "kept")
	req.Header.Set("X-New", "appended")

	lines := []util.OriginalHeaderLine{
		{LowerName: "host", RawName: "host"},
		{LowerName: "user-agent", RawName: "user-agent"},
		{LowerName: "authorization", RawName: "authorization"},
		{LowerName: "content-type", RawName: "content-type"},
		{LowerName: "accept-encoding", RawName: "accept-encoding"},
		{LowerName: "content-length", RawName: "content-length"},
		{LowerName: "x-client", RawName: "x-client"},
	}

	raw, err := buildOrderedH1Request(req, []byte(`{"ok":true}`), lines)
	if err != nil {
		t.Fatalf("buildOrderedH1Request: %v", err)
	}
	head := string(raw[:strings.Index(string(raw), "\r\n\r\n")])
	gotLines := strings.Split(head, "\r\n")
	wantLines := []string{
		"POST /v1/messages?beta=true HTTP/1.1",
		"host: target.example",
		"user-agent: claude-cli/2.1.63",
		"authorization: Bearer regenerated",
		"content-type: application/json",
		"accept-encoding: identity",
		"content-length: 11",
		"x-client: kept",
		"X-New: appended",
	}
	if len(gotLines) != len(wantLines) {
		t.Fatalf("header lines = %#v, want %#v", gotLines, wantLines)
	}
	for i := range wantLines {
		if gotLines[i] != wantLines[i] {
			t.Fatalf("line[%d] = %q, want %q\nall lines: %#v", i, gotLines[i], wantLines[i], gotLines)
		}
	}
}
