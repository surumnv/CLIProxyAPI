package fingerprint

import (
	"bytes"
	"io"
	"net"
	"testing"

	tls "github.com/refraction-networking/utls"
)

// The constants below are the measured fingerprint of the real Linux Codex CLI
// (Codex CLI 0.151.0 on Debian 13, WSL2, x86_64). They are the reference the
// declared spec in codex_linux_hello.go is checked against: if anyone edits the
// cipher order, extension order, groups or signature algorithms, these tests
// fail.
//
// Re-measuring is only needed when Codex changes its TLS stack, which shows up
// in codex-rs/Cargo.lock as a new openssl-src / native-tls / reqwest version,
// not merely as a new Codex release.
const (
	codexLinuxJA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-0-11-10-35-22-23-13-43-45-51,4588-29-23-30-24-25-256-257,0"

	codexLinuxJA3Hash = "0b85eb0d4981e69064e40753e4f0ac5f"
)

// codexLinuxMeasuredExtensionOrder is the extension order the real client emits.
// OpenSSL puts renegotiation_info first and key_share last; JA3 covers the order,
// so this is pinned explicitly to make a reordering failure readable.
var codexLinuxMeasuredExtensionOrder = []uint16{65281, 0, 11, 10, 35, 22, 23, 13, 43, 45, 51}

// codexLinuxMeasuredGroups is the supported_groups list of the real client,
// leading with the X25519MLKEM768 hybrid.
var codexLinuxMeasuredGroups = []uint16{4588, 29, 23, 30, 24, 25, 256, 257}

// TestCodexLinuxJA3MatchesMeasurement is the primary guard: it serialises the
// declared spec and checks the resulting JA3 against the value measured from the
// real client.
func TestCodexLinuxJA3MatchesMeasurement(t *testing.T) {
	t.Parallel()

	ja3, ja3Hash, err := CodexLinuxJA3()
	if err != nil {
		t.Fatalf("CodexLinuxJA3() error = %v", err)
	}
	if ja3 != codexLinuxJA3 {
		t.Errorf("JA3 string mismatch\n got: %s\nwant: %s", ja3, codexLinuxJA3)
	}
	if ja3Hash != codexLinuxJA3Hash {
		t.Errorf("JA3 hash = %s, want %s", ja3Hash, codexLinuxJA3Hash)
	}
}

// TestCodexLinuxSpecH1Shape asserts the declared spec keeps the measured shape:
// 30 cipher suites and 11 extensions in the measured order, including extension
// 22 (encrypt_then_mac), which OpenSSL sends and utls has no typed struct for.
func TestCodexLinuxSpecH1Shape(t *testing.T) {
	t.Parallel()

	spec := CodexLinuxSpecH1()
	if spec == nil {
		t.Fatal("CodexLinuxSpecH1() = nil, want a spec")
	}
	if got, want := len(spec.CipherSuites), 30; got != want {
		t.Errorf("cipher suite count = %d, want %d", got, want)
	}
	if got, want := len(spec.CompressionMethods), 1; got != want {
		t.Errorf("compression method count = %d, want %d", got, want)
	}
	if got, want := len(spec.Extensions), len(codexLinuxMeasuredExtensionOrder); got != want {
		t.Fatalf("extension count = %d, want %d", got, want)
	}

	var sawGeneric22 bool
	for _, ext := range spec.Extensions {
		if generic, ok := ext.(*tls.GenericExtension); ok && generic.Id == 22 {
			sawGeneric22 = true
			if len(generic.Data) != 0 {
				t.Errorf("extension 22 carries %d body bytes, want an empty body", len(generic.Data))
			}
		}
	}
	if !sawGeneric22 {
		t.Error("extension 22 (encrypt_then_mac) is missing from the spec")
	}
}

// TestCodexLinuxExtensionOrderOnTheWire checks the serialised record, not just
// the spec: extension order is part of JA3 and utls is free to reorder or drop
// extensions while applying a preset.
func TestCodexLinuxExtensionOrderOnTheWire(t *testing.T) {
	t.Parallel()

	record, err := CodexLinuxClientHelloRecord("chatgpt.com")
	if err != nil {
		t.Fatalf("CodexLinuxClientHelloRecord() error = %v", err)
	}
	order, groups, err := parseExtensionOrderAndGroups(record)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	if !equalUint16(order, codexLinuxMeasuredExtensionOrder) {
		t.Errorf("extension order on the wire = %v, want %v", order, codexLinuxMeasuredExtensionOrder)
	}
	if !equalUint16(groups, codexLinuxMeasuredGroups) {
		t.Errorf("supported_groups on the wire = %v, want %v", groups, codexLinuxMeasuredGroups)
	}
}

// TestCodexLinuxSpecH1CarriesNoStaticSecrets is the privacy guard. The spec
// declares protocol constants only: no client_random, no session ID and no
// key_share public key may be baked in, because utls must generate all of them
// per connection. SNI must likewise be left empty so ApplyPreset fills in the
// host actually being dialled.
func TestCodexLinuxSpecH1CarriesNoStaticSecrets(t *testing.T) {
	t.Parallel()

	spec := CodexLinuxSpecH1()
	if spec == nil {
		t.Fatal("CodexLinuxSpecH1() = nil, want a spec")
	}
	if spec.GetSessionID != nil {
		t.Error("spec pins a session ID generator; utls must generate it per connection")
	}

	var sawSNI, sawKeyShare bool
	for _, ext := range spec.Extensions {
		switch typed := ext.(type) {
		case *tls.SNIExtension:
			sawSNI = true
			if typed.ServerName != "" {
				t.Errorf("SNI ServerName = %q, want empty so ApplyPreset fills the dialled host", typed.ServerName)
			}
		case *tls.KeyShareExtension:
			sawKeyShare = true
			for i, keyShare := range typed.KeyShares {
				if len(keyShare.Data) != 0 {
					t.Errorf("key share %d (group %d) carries %d static bytes, want none", i, keyShare.Group, len(keyShare.Data))
				}
			}
		}
	}
	if !sawSNI {
		t.Error("spec has no SNI extension; upstreams behind SNI-routed edges would fail")
	}
	if !sawKeyShare {
		t.Error("spec has no key_share extension")
	}
}

// TestCodexLinuxRandomnessIsPerConnection backs the privacy claim end to end: two
// serialisations of the same spec must share the fingerprint but differ in
// client_random, session ID and key_share bytes.
func TestCodexLinuxRandomnessIsPerConnection(t *testing.T) {
	t.Parallel()

	first, err := CodexLinuxClientHelloRecord("chatgpt.com")
	if err != nil {
		t.Fatalf("CodexLinuxClientHelloRecord() error = %v", err)
	}
	second, err := CodexLinuxClientHelloRecord("chatgpt.com")
	if err != nil {
		t.Fatalf("CodexLinuxClientHelloRecord() second call error = %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("record lengths differ: %d vs %d", len(first), len(second))
	}
	if bytes.Equal(first, second) {
		t.Fatal("two ClientHellos are byte-identical; per-connection randomness is not being generated")
	}

	// client_random sits at a fixed offset: 5 record header + 4 handshake header
	// + 2 legacy version.
	const randomOffset = 5 + 4 + 2
	if bytes.Equal(first[randomOffset:randomOffset+32], second[randomOffset:randomOffset+32]) {
		t.Error("client_random is identical across connections")
	}
	// session ID follows client_random, prefixed by its length.
	sidOffset := randomOffset + 32
	sidLen := int(first[sidOffset])
	if sidLen != 32 {
		t.Fatalf("session ID length = %d, want 32", sidLen)
	}
	if bytes.Equal(first[sidOffset+1:sidOffset+1+sidLen], second[sidOffset+1:sidOffset+1+sidLen]) {
		t.Error("session ID is identical across connections")
	}
}

// TestCodexLinuxSpecH1CarriesNoALPN pins the measured absence of ALPN. The real
// Linux Codex client advertises none and speaks HTTP/1.1, which is what the
// ordered-h1 transport writes onto the connection. Adding ALPN here would both
// change the JA3 and risk negotiating h2 under an HTTP/1.1 writer.
func TestCodexLinuxSpecH1CarriesNoALPN(t *testing.T) {
	t.Parallel()

	spec := CodexLinuxSpecH1()
	if spec == nil {
		t.Fatal("CodexLinuxSpecH1() = nil, want a spec")
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.ALPNExtension); ok {
			t.Fatal("spec advertises ALPN, want none to match the real client")
		}
	}
}

// TestCodexLinuxSpecH1ReturnsFreshInstances guards the per-connection contract:
// utls mutates the spec and its extensions during ApplyPreset (it fills in
// ServerName and generates key shares), so two callers must never share state.
//
// Freshness is asserted semantically rather than by pointer identity: several
// extensions in this spec are zero-sized structs, and Go is free to give distinct
// zero-sized allocations the same address.
func TestCodexLinuxSpecH1ReturnsFreshInstances(t *testing.T) {
	t.Parallel()

	first := CodexLinuxSpecH1()
	if first == nil {
		t.Fatal("CodexLinuxSpecH1() = nil, want a spec")
	}
	var mutated bool
	for _, ext := range first.Extensions {
		if sni, ok := ext.(*tls.SNIExtension); ok {
			sni.ServerName = "mutated.example"
			mutated = true
		}
	}
	if !mutated {
		t.Fatal("spec carries no SNI extension to mutate")
	}
	first.CipherSuites[0] = 0x1301

	second := CodexLinuxSpecH1()
	if second == nil {
		t.Fatal("CodexLinuxSpecH1() = nil on second call, want a spec")
	}
	if first == second {
		t.Fatal("CodexLinuxSpecH1() returned the same spec pointer twice")
	}
	for _, ext := range second.Extensions {
		if sni, ok := ext.(*tls.SNIExtension); ok && sni.ServerName != "" {
			t.Fatalf("second spec observed mutation from the first: ServerName = %q", sni.ServerName)
		}
	}
	if second.CipherSuites[0] != codexLinuxCipherSuites[0] {
		t.Fatal("second spec shares the cipher suite slice with the first")
	}
	if codexLinuxCipherSuites[0] == 0x1301 {
		t.Fatal("mutating a returned spec corrupted the package-level cipher list")
	}
}

// TestCodexLinuxSpecH1WireImage is the end-to-end guard for the handshake path:
// it runs a real utls handshake attempt against a local listener, captures the
// ClientHello that actually reaches the wire, and checks it against the measured
// fingerprint. This covers the whole chain (ApplyPreset, key share generation,
// record serialisation) rather than the offline serialiser alone.
func TestCodexLinuxSpecH1WireImage(t *testing.T) {
	t.Parallel()

	const serverName = "chatgpt.com"

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Skipf("cannot listen on loopback: %v", errListen)
	}
	defer func() {
		if errClose := listener.Close(); errClose != nil {
			t.Logf("close listener: %v", errClose)
		}
	}()

	type captured struct {
		raw []byte
		err error
	}
	results := make(chan captured, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			results <- captured{err: errAccept}
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		raw, errRead := readOneTLSRecord(conn)
		results <- captured{raw: raw, err: errRead}
	}()

	conn, errDial := net.Dial("tcp", listener.Addr().String())
	if errDial != nil {
		t.Fatalf("dial loopback listener: %v", errDial)
	}
	defer func() {
		_ = conn.Close()
	}()

	spec := CodexLinuxSpecH1()
	if spec == nil {
		t.Fatal("CodexLinuxSpecH1() = nil, want a spec")
	}
	uconn := tls.UClient(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}, tls.HelloCustom)
	if errPreset := uconn.ApplyPreset(spec); errPreset != nil {
		t.Fatalf("ApplyPreset() error = %v", errPreset)
	}
	// The listener never answers, so the handshake cannot complete; the
	// ClientHello is flushed before the failure, which is all this test needs.
	_ = uconn.Handshake()

	result := <-results
	if result.err != nil {
		t.Fatalf("read ClientHello from wire: %v", result.err)
	}

	_, ja3Hash, errJA3 := ComputeJA3(result.raw)
	if errJA3 != nil {
		t.Fatalf("ComputeJA3(wire bytes) error = %v", errJA3)
	}
	if ja3Hash != codexLinuxJA3Hash {
		t.Fatalf("on-the-wire JA3 = %s, want %s", ja3Hash, codexLinuxJA3Hash)
	}
	if !bytes.Contains(result.raw, []byte(serverName)) {
		t.Fatalf("ClientHello does not carry SNI %q", serverName)
	}
}

// readOneTLSRecord reads a single TLS record (5-byte header plus payload) from
// conn and returns the complete record bytes.
func readOneTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[3])<<8 | int(header[4])
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return append(header, payload...), nil
}

// parseExtensionOrderAndGroups walks a raw ClientHello record and returns the
// extension types in wire order plus the supported_groups codepoints.
func parseExtensionOrderAndGroups(rec []byte) (order []uint16, groups []uint16, err error) {
	p := 5 + 4 + 2 + 32
	if p >= len(rec) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	p += 1 + int(rec[p]) // session ID
	if p+2 > len(rec) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	p += 2 + int(rec[p])<<8 + int(rec[p+1]) // cipher suites
	if p >= len(rec) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	p += 1 + int(rec[p]) // compression methods
	if p+2 > len(rec) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	end := p + 2 + int(rec[p])<<8 + int(rec[p+1])
	p += 2
	if end > len(rec) {
		end = len(rec)
	}
	for p+4 <= end {
		extType := uint16(rec[p])<<8 | uint16(rec[p+1])
		extLen := int(rec[p+2])<<8 | int(rec[p+3])
		p += 4
		if p+extLen > end {
			return nil, nil, io.ErrUnexpectedEOF
		}
		order = append(order, extType)
		if extType == 10 && extLen >= 2 {
			body := rec[p : p+extLen]
			listLen := int(body[0])<<8 | int(body[1])
			for i := 0; i+1 < listLen && 2+i+1 < len(body); i += 2 {
				groups = append(groups, uint16(body[2+i])<<8|uint16(body[2+i+1]))
			}
		}
		p += extLen
	}
	return order, groups, nil
}

func equalUint16(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
