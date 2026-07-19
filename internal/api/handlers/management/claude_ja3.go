package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/fingerprint"
)

// claudeJA3Response is the JSON shape returned by the claude-ja3 endpoints.
type claudeJA3Response struct {
	Configured    bool   `json:"configured"`
	JA3           string `json:"ja3,omitempty"`
	JA3Hash       string `json:"ja3_hash,omitempty"`
	Source        string `json:"source,omitempty"`
	CapturedAt    string `json:"captured_at,omitempty"`
	ClaudeVersion string `json:"claude_version,omitempty"`
	RawHex        string `json:"raw_hex,omitempty"`
}

func (h *Handler) claudeJA3Store() *fingerprint.Store {
	authDir := ""
	if h.cfg != nil {
		authDir = h.cfg.AuthDir
	}
	return fingerprint.NewStore(authDir)
}

func recordToResponse(rec fingerprint.Record, configured bool) claudeJA3Response {
	return claudeJA3Response{
		Configured:    configured,
		JA3:           rec.JA3,
		JA3Hash:       rec.JA3Hash,
		Source:        rec.Source,
		CapturedAt:    rec.CapturedAt,
		ClaudeVersion: rec.ClaudeVersion,
		RawHex:        rec.RawHex,
	}
}

// GetClaudeJA3 returns the currently active Claude TLS fingerprint metadata, or
// {"configured": false} when none is set.
//
//	GET /v0/management/claude-ja3
func (h *Handler) GetClaudeJA3(c *gin.Context) {
	rec, ok := h.claudeJA3StoreCurrent()
	c.JSON(http.StatusOK, recordToResponse(rec, ok))
}

// claudeJA3StoreCurrent reads the current fingerprint from a store bound to the
// live auth dir. It reloads from disk so it reflects the persisted state even if
// this handler instance predates a capture.
func (h *Handler) claudeJA3StoreCurrent() (fingerprint.Record, bool) {
	s := h.claudeJA3Store()
	if err := s.Load(); err != nil {
		return fingerprint.Record{}, false
	}
	return s.Current()
}

// claudeJA3Request is the body for PUT (manual set).
type claudeJA3Request struct {
	RawHex string `json:"raw_hex"`
}

// PutClaudeJA3 sets the Claude fingerprint from a raw ClientHello hex string
// supplied in the body. Useful for restoring a value captured elsewhere.
//
//	PUT /v0/management/claude-ja3   {"raw_hex":"1603..."}
func (h *Handler) PutClaudeJA3(c *gin.Context) {
	var req claudeJA3Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.RawHex) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "raw_hex is required"})
		return
	}
	s := h.claudeJA3Store()
	rec, err := s.Set(req.RawHex, "manual", "")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Reinstall as the process-wide active fingerprint.
	if _, err = fingerprint.Init(h.authDir()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "saved but failed to activate: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, recordToResponse(rec, true))
}

// DeleteClaudeJA3 clears the stored fingerprint; outbound requests then fall
// back to the default (Chrome) fingerprint.
//
//	DELETE /v0/management/claude-ja3
func (h *Handler) DeleteClaudeJA3(c *gin.Context) {
	s := h.claudeJA3Store()
	if err := s.Clear(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if _, err := fingerprint.Init(h.authDir()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cleared but failed to refresh: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"configured": false})
}

// GetClaudeCLIVersion reports the version-dir name of the newest locally
// installed Claude Code CLI (auto-detected; Windows only). The frontend uses
// this to detect bundled-CLI upgrades and refresh the JA3 fingerprint. It only
// inspects the install layout and never launches the executable.
//
//	GET /v0/management/claude-ja3/cli-version
func (h *Handler) GetClaudeCLIVersion(c *gin.Context) {
	version, err := fingerprint.DetectClaudeVersion()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"detected": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"detected": true, "version": version})
}

// captureClaudeJA3Request is the optional body for POST (live capture).
type captureClaudeJA3Request struct {
	ClaudePath string `json:"claude_path,omitempty"`
	Prompt     string `json:"prompt,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

// CaptureClaudeJA3 launches the local Claude Code CLI, captures its real
// ClientHello, stores it, and activates it. Windows only (auto-detects
// claude.exe); on other platforms a claude_path must be supplied.
//
//	POST /v0/management/claude-ja3/capture   {"prompt":"hi"}
func (h *Handler) CaptureClaudeJA3(c *gin.Context) {
	var req captureClaudeJA3Request
	// Body is optional; ignore bind errors on an empty body.
	if c.Request != nil && c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
			return
		}
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	res, err := fingerprint.Capture(fingerprint.CaptureOptions{
		ClaudePath:    strings.TrimSpace(req.ClaudePath),
		Prompt:        req.Prompt,
		Timeout:       timeout,
		ApproveAPIKey: true,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "capture failed: " + err.Error()})
		return
	}
	s := h.claudeJA3Store()
	rec, err := s.Set(res.RawHex(), "capture", res.ClaudeVersion)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "captured but failed to store: " + err.Error()})
		return
	}
	if _, err = fingerprint.Init(h.authDir()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stored but failed to activate: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, recordToResponse(rec, true))
}

func (h *Handler) authDir() string {
	if h.cfg != nil {
		return h.cfg.AuthDir
	}
	return ""
}
