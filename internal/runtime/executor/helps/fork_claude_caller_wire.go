package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/tidwall/sjson"
)

// This file holds the fork-only parts of the Claude caller-owned wire so the
// upstream request builder keeps a single call site per behavior. Upstream
// rewrites applyClaudeHeadersWithNativeProfile often; keeping the logic here
// reduces the merge surface to those call lines.

// nonClaudeInboundHeaderPrefixes are header name prefixes that only a non-Claude
// client emits. They are transport hints for the Codex/OpenAI upstream and carry
// no meaning for a Claude upstream, so forwarding them just contradicts the
// Claude Code identity the rest of the request presents.
var nonClaudeInboundHeaderPrefixes = []string{"x-codex-", "x-openai-", "openai-"}

// nonClaudeInboundHeaderNames are exact client-identity headers dropped for the
// same reason. chatgpt-account-id is the most sensitive of them: it names the
// caller's ChatGPT account and must never reach an unrelated Claude relay.
var nonClaudeInboundHeaderNames = map[string]struct{}{
	"originator":               {},
	"session-id":               {},
	"thread-id":                {},
	"x-client-request-id":      {},
	"x-claude-code-session-id": {},
	"chatgpt-account-id":       {},
}

// filterNonClaudeInboundHeaders returns a copy of headers without the identity
// and transport headers listed above. The input is never mutated: the caller
// keeps the original inbound header set for its own bookkeeping.
func filterNonClaudeInboundHeaders(headers http.Header) http.Header {
	if len(headers) == 0 {
		return headers
	}
	filtered := headers.Clone()
	for key := range filtered {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if _, drop := nonClaudeInboundHeaderNames[lowerKey]; drop {
			delete(filtered, key)
			continue
		}
		for _, prefix := range nonClaudeInboundHeaderPrefixes {
			if strings.HasPrefix(lowerKey, prefix) {
				delete(filtered, key)
				break
			}
		}
	}
	return filtered
}

// ForkFilterNonClaudeCallerHeaders implements fork commit de020b03 for the
// caller-owned Claude path: a Claude upstream must never be handed the identity
// of a client that is not Claude Code. A native claude-cli caller keeps its own
// wire untouched; every other caller has its client-identity headers dropped
// before any of them can be copied onto the upstream request.
//
// It returns the header set to use from here on, plus whether the caller was a
// native Claude client, which the identity step below also needs.
func ForkFilterNonClaudeCallerHeaders(incomingHeaders http.Header) (http.Header, bool) {
	inboundClaudeClient := IsClaudeCodeClient(incomingHeaders.Get("User-Agent"))
	if inboundClaudeClient {
		return incomingHeaders, true
	}
	return filterNonClaudeInboundHeaders(incomingHeaders), false
}

// ForkApplyNonClaudeCallerIdentity implements the rest of fork commit de020b03
// for the caller-owned Claude path. It must run after the caller-owned defaults
// (Anthropic-Version, Accept, Accept-Encoding, the CPA User-Agent fallback) are
// already on r, and incomingHeaders must be the value returned by
// ForkFilterNonClaudeCallerHeaders.
//
// Two things happen here:
//
// A caller that announced a foreign client (Codex, lobe-chat, ...) is presented
// upstream as the locally installed Claude Code CLI instead of leaking that
// name. A caller that sent no User-Agent at all leaks no identity, so it keeps
// the CPA value already set by the caller-owned defaults.
//
// Then the remaining inbound headers are passed through best-effort, so a native
// Claude Desktop / Claude Code caller keeps everything the fingerprint whitelist
// does not name (Originator, X-Trace-Id, and any header a future release adds).
// util.CopyInboundHeaders never clobbers a value already on r, and its own
// denylist drops hop-by-hop, length, host and Accept-Encoding. The skip list
// keeps CPA in control of what it must own:
//   - Authorization / X-Api-Key: carry the proxy credential, never the inbound
//     token (Anthropic+API-key mode deliberately drops Authorization).
//   - Anthropic-Beta: resolved by the caller before and after this call.
//   - Accept: negotiated per stream / upstream by the caller.
//   - Anthropic-Dangerous-Direct-Browser-Access: OAuth mode intentionally omits
//     it, so it must not be resurrected from the inbound request.
func ForkApplyNonClaudeCallerIdentity(r *http.Request, incomingHeaders http.Header, inboundClaudeClient bool, apiKey string) error {
	if r == nil {
		return nil
	}
	if !inboundClaudeClient && strings.TrimSpace(incomingHeaders.Get("User-Agent")) != "" {
		r.Header.Set("User-Agent", misc.LocalClaudeCodeUserAgent())
		// The inbound X-Claude-Code-Session-Id was dropped with the rest of the
		// foreign identity, and a request presenting the Claude Code CLI UA without
		// one is itself an anomaly. Use the per-credential cached session ID.
		sessionID, errCallerSessionID := CachedSessionIDRequired(r.Context(), apiKey)
		if errCallerSessionID != nil {
			return errCallerSessionID
		}
		misc.EnsureHeader(r.Header, incomingHeaders, "X-Claude-Code-Session-Id", sessionID)
	}
	util.CopyInboundHeaders(r, incomingHeaders,
		"Authorization",
		"X-Api-Key",
		"Anthropic-Beta",
		"Accept",
		"Anthropic-Dangerous-Direct-Browser-Access",
	)
	return nil
}

// ForkNormalizeNonNativeClaudeSampling implements fork commit dc0f7f9b: the
// caller's temperature is forwarded instead of stripped. Third-party
// Anthropic-compatible relays honour it and clients that set it expect it to
// take effect, so dropping it silently changed sampling. top_p and top_k are
// still removed while thinking is active because Anthropic rejects them in that
// combination.
func ForkNormalizeNonNativeClaudeSampling(body []byte, thinkingActive bool) []byte {
	if !thinkingActive {
		return body
	}
	body, _ = sjson.DeleteBytes(body, "top_p")
	body, _ = sjson.DeleteBytes(body, "top_k")
	return body
}
