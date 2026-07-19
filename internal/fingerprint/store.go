package fingerprint

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
)

// storeFileName is the on-disk file (under the auth directory) that persists the
// captured Claude ClientHello. It is decoupled from config.yaml so reloading the
// main config never disturbs the fingerprint, and vice versa.
const storeFileName = "claude_ja3.json"

// Record is the persisted form of a captured Claude fingerprint.
type Record struct {
	// RawHex is the full ClientHello record (record header + handshake) in hex.
	RawHex string `json:"raw_hex"`
	// JA3 is the derived JA3 string, stored for display/inspection only.
	JA3 string `json:"ja3,omitempty"`
	// JA3Hash is the MD5 of JA3, stored for display/inspection only.
	JA3Hash string `json:"ja3_hash,omitempty"`
	// Source records where the value came from ("capture", "manual", ...).
	Source string `json:"source,omitempty"`
	// CapturedAt is an RFC3339 timestamp of when the value was saved.
	CapturedAt string `json:"captured_at,omitempty"`
	// ClaudeVersion is the claude.exe version dir the capture launched, if known.
	ClaudeVersion string `json:"claude_version,omitempty"`
}

// Store holds the active Claude fingerprint and persists it. The zero value is
// not usable; construct one with NewStore. All methods are safe for concurrent
// use. Forwarding code reads the active spec via ClaudeSpec; only Set/Clear
// (driven by explicit management calls) mutate it.
type Store struct {
	path string

	mu   sync.RWMutex
	rec  Record
	spec *tls.ClientHelloSpec // parsed once on Set/Load; nil means "no fingerprint"
}

// pkgStore is the process-wide store, wired at startup via Init. Transport code
// reads it through the package-level accessors so it does not need a handle.
var (
	pkgStore   *Store
	pkgStoreMu sync.RWMutex
)

// NewStore creates a store backed by <authDir>/claude_ja3.json. It does not read
// the file; call Load for that.
func NewStore(authDir string) *Store {
	return &Store{path: filepath.Join(strings.TrimSpace(authDir), storeFileName)}
}

// Init constructs the store, loads any persisted fingerprint, and installs it as
// the process-wide store used by the transport layer. A missing file is not an
// error (the fingerprint is simply unset and callers fall back to Chrome). Any
// parse error is returned but the store is still installed (empty).
func Init(authDir string) (*Store, error) {
	s := NewStore(authDir)
	err := s.Load()
	pkgStoreMu.Lock()
	pkgStore = s
	pkgStoreMu.Unlock()
	return s, err
}

// active returns the installed process-wide store, or nil if Init was never
// called.
func active() *Store {
	pkgStoreMu.RLock()
	defer pkgStoreMu.RUnlock()
	return pkgStore
}

// Load reads and parses the persisted fingerprint. A missing file leaves the
// store empty and returns nil.
func (s *Store) Load() error {
	if s == nil {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var rec Record
	if err = json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if strings.TrimSpace(rec.RawHex) == "" {
		return nil
	}
	raw, err := decodeHex(rec.RawHex)
	if err != nil {
		return err
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.rec = rec
	s.spec = spec
	s.mu.Unlock()
	return nil
}

// Set validates the raw ClientHello hex, derives its JA3, persists it, and makes
// it the active fingerprint. source labels the origin ("capture"/"manual").
// claudeVersion is optional metadata. It returns the stored Record.
func (s *Store) Set(rawHex, source, claudeVersion string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("fingerprint store not initialized")
	}
	raw, err := decodeHex(rawHex)
	if err != nil {
		return Record{}, err
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		return Record{}, err
	}
	ja3, ja3Hash, err := ComputeJA3(raw)
	if err != nil {
		return Record{}, err
	}
	rec := Record{
		RawHex:        strings.ToLower(strings.TrimSpace(rawHex)),
		JA3:           ja3,
		JA3Hash:       ja3Hash,
		Source:        source,
		CapturedAt:    time.Now().UTC().Format(time.RFC3339),
		ClaudeVersion: claudeVersion,
	}
	if err = s.persist(rec); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	s.rec = rec
	s.spec = spec
	s.mu.Unlock()
	return rec, nil
}

// Clear removes the persisted fingerprint and unsets the active spec, so callers
// fall back to the default (Chrome) fingerprint.
func (s *Store) Clear() error {
	if s == nil {
		return errors.New("fingerprint store not initialized")
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.mu.Lock()
	s.rec = Record{}
	s.spec = nil
	s.mu.Unlock()
	return nil
}

// Current returns the stored Record (metadata) and whether a fingerprint is set.
func (s *Store) Current() (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rec, s.spec != nil
}

// SpecWithALPN returns a copy of the active ClientHelloSpec with its ALPN
// extension set to protocols, or nil if no fingerprint is set. Each call returns
// a fresh spec because utls mutates spec/extension state during ApplyPreset, so
// specs must not be shared across handshakes.
func (s *Store) SpecWithALPN(protocols ...string) *tls.ClientHelloSpec {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	rawHex := s.rec.RawHex
	has := s.spec != nil
	s.mu.RUnlock()
	if !has || rawHex == "" {
		return nil
	}
	// Re-parse from the stored bytes to get an independent spec instance.
	raw, err := decodeHex(rawHex)
	if err != nil {
		return nil
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		return nil
	}
	overrideALPN(spec, protocols)
	return spec
}

func (s *Store) persist(rec Record) error {
	if s.path == "" {
		return errors.New("fingerprint store path is empty")
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---- package-level accessors used by the transport layer ------------------

// ClaudeSpecH2 returns the active Claude ClientHelloSpec with ALPN set to
// [h2, http/1.1] for the official api.anthropic.com HTTP/2 path, or nil when no
// fingerprint is configured (callers then keep their default behaviour).
func ClaudeSpecH2() *tls.ClientHelloSpec {
	return active().SpecWithALPN("h2", "http/1.1")
}

// ClaudeSpecH1 returns the active Claude ClientHelloSpec with ALPN set to
// [http/1.1] for the third-party ordered-HTTP/1.1 path, or nil when no
// fingerprint is configured.
func ClaudeSpecH1() *tls.ClientHelloSpec {
	return active().SpecWithALPN("http/1.1")
}

// HasClaudeSpec reports whether a Claude fingerprint is currently configured.
func HasClaudeSpec() bool {
	_, ok := active().Current()
	return ok
}
