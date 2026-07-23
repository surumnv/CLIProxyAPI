package fingerprint

import (
	"testing"

	tls "github.com/refraction-networking/utls"
)

// capturedNoSNIHex is a real Claude Code ClientHello captured against a
// 127.0.0.1 listener; per RFC 6066 it carries no server_name extension.
const capturedNoSNIHex = "16030100fb010000f70303e41a8bee1d3f6dac08d8a2d91934843713e9a3c86863948124b6e16e6cfba897202d34a7fddd98b0aae29843b0651f67fb10363fb0bc337be2fa56fde97d66991a0022130113021303c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f00350100008c00170000ff01000100000a00080006001d00170018000b00020100002300000010000b000908687474702f312e31000500050100000000000d0014001204030804040105030805050108060601020100120000003300260024001d00207549371d4fc007491dea9dc6e8816324ddb6a4e26c615efc5e437742c806be07002d00020101002b00050403040303"

func specHasSNI(spec *tls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.SNIExtension); ok {
			return true
		}
	}
	return false
}

// TestEnsureSNIExtensionAddsMissingSNI verifies that a captured ClientHello with
// no server_name extension gains one, so utls emits SNI on the wire (otherwise
// SNI-routed edges serve a fallback certificate that fails verification).
func TestEnsureSNIExtensionAddsMissingSNI(t *testing.T) {
	raw, err := decodeHex(capturedNoSNIHex)
	if err != nil {
		t.Fatalf("decodeHex: %v", err)
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	if specHasSNI(spec) {
		t.Fatal("precondition failed: captured spec unexpectedly already has SNI")
	}

	ensureSNIExtension(spec)

	if !specHasSNI(spec) {
		t.Fatal("ensureSNIExtension did not add an SNI extension")
	}
	// OpenSSL/BoringSSL clients place server_name first.
	if _, ok := spec.Extensions[0].(*tls.SNIExtension); !ok {
		t.Fatalf("SNI extension not prepended; first ext is %T", spec.Extensions[0])
	}
	// The added extension must have an empty ServerName so utls seeds it per
	// connection from Config.ServerName.
	if sni := spec.Extensions[0].(*tls.SNIExtension); sni.ServerName != "" {
		t.Fatalf("prepended SNI must have empty ServerName, got %q", sni.ServerName)
	}
}

// TestEnsureSNIExtensionIdempotent verifies a spec that already carries SNI is
// left unchanged (no duplicate extension).
func TestEnsureSNIExtensionIdempotent(t *testing.T) {
	spec := &tls.ClientHelloSpec{
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2"}},
		},
	}
	ensureSNIExtension(spec)
	count := 0
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.SNIExtension); ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 SNI extension, got %d", count)
	}
}

// TestSpecWithALPNEmitsSNI is an end-to-end check on the production accessor:
// the spec handed to the handshake must carry SNI and the requested ALPN.
func TestSpecWithALPNEmitsSNI(t *testing.T) {
	s := &Store{}
	rec := Record{RawHex: capturedNoSNIHex}
	raw, err := decodeHex(capturedNoSNIHex)
	if err != nil {
		t.Fatalf("decodeHex: %v", err)
	}
	parsed, err := SpecFromRaw(raw)
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	s.rec = rec
	s.spec = parsed

	spec := s.SpecWithALPN("http/1.1")
	if spec == nil {
		t.Fatal("SpecWithALPN returned nil")
	}
	if !specHasSNI(spec) {
		t.Fatal("SpecWithALPN result missing SNI extension")
	}
}
