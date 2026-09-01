package fingerprint

import (
	"encoding/binary"
	"errors"
	"fmt"

	tls "github.com/refraction-networking/utls"
)

// This file declares the ClientHello fingerprint of the Linux Codex CLI.
//
// Why a second fingerprint exists: the Codex CLI builds its HTTP client with
// reqwest's default TLS backend (codex-rs/http-client/client_builder.rs keeps
// TlsBackend::TransportDefault unless a caller opts into rustls), which resolves
// to native-tls. native-tls maps to SChannel on Windows and to OpenSSL
// everywhere else, and the Linux Codex binary statically links OpenSSL 3.6.3
// (Cargo.lock: openssl-src 300.6.1+3.6.3). A Codex request coming from
// WSL2/Debian therefore has a completely different ClientHello than the
// SChannel one the Windows path reproduces.
//
// Why this is declared rather than replayed: the Windows path can call the very
// same library Codex uses, because SChannel is an OS component both processes
// share (see internal/schannel). On Linux that is impossible - Codex's OpenSSL
// is statically linked into its own binary, and CPA runs on Windows where that
// library does not exist at all. What is reproducible is the wire shape, so the
// handshake parameters below are declared field by field from a measurement of
// the real client:
//
//	Codex CLI 0.151.0, Debian 13 (WSL2, x86_64, x86_64-unknown-linux-musl)
//	JA3      771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-0-11-10-35-22-23-13-43-45-51,4588-29-23-30-24-25-256-257,0
//	JA3 hash 0b85eb0d4981e69064e40753e4f0ac5f
//	JA4      t13d301000_1d37bd780c83_8e6e362c5eac
//
// Nothing from the measurement run is embedded: client_random, session_id and
// the key_share public keys are all generated per connection by utls
// (ApplyPreset overwrites Random and SessionId unconditionally and derives key
// shares from Config.rand()), and SNI is filled from the dialled host. Only
// protocol constants - cipher order, extension order, groups, signature
// algorithms - are stated here, and codex_linux_hello_test.go pins every one of
// them against the measured values.
//
// Shape notes worth keeping in mind when re-measuring:
//   - 30 cipher suites, 11 extensions, no GREASE, no ALPN.
//   - supported_groups leads with X25519MLKEM768 (4588), so the post-quantum
//     hybrid must be reproducible; utls v1.8.2 supports it natively.
//   - extension 22 (encrypt_then_mac) is present. OpenSSL sends it, SChannel and
//     BoringSSL do not, and utls has no typed struct for it, so it is declared as
//     an empty GenericExtension.
//   - renegotiation_info (65281) comes first, before server_name.

// codexLinuxCipherSuites is the cipher list of the Linux Codex CLI, in the order
// it offers them.
var codexLinuxCipherSuites = []uint16{
	tls.TLS_AES_256_GCM_SHA384,                  // 0x1302
	tls.TLS_CHACHA20_POLY1305_SHA256,            // 0x1303
	tls.TLS_AES_128_GCM_SHA256,                  // 0x1301
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 0xc02c
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // 0xc030
	0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,  // 0xcca9
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,    // 0xcca8
	0xccaa,                                      // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xc02b
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 0xc02f
	0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	0x006b, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, // 0xc027
	0x0067,                                   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // 0xc00a
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,   // 0xc014
	0x0039,                                   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // 0xc009
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,   // 0xc013
	0x0033,                                   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	0x009d,                                   // TLS_RSA_WITH_AES_256_GCM_SHA384
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,      // 0x009c
	0x003d,                                   // TLS_RSA_WITH_AES_256_CBC_SHA256
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,      // 0x003c
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,         // 0x0035
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,         // 0x002f
}

// codexLinuxSupportedGroups is the supported_groups list of the Linux Codex CLI.
// utls has no constants for X448 or the FFDHE groups, so they are given by
// codepoint.
var codexLinuxSupportedGroups = []tls.CurveID{
	tls.X25519MLKEM768,             // 4588
	tls.X25519,                     // 29
	tls.CurveP256,                  // 23
	tls.CurveID(30),                // X448
	tls.CurveP384,                  // 24
	tls.CurveP521,                  // 25
	tls.CurveID(tls.FakeFFDHE2048), // 256
	tls.CurveID(tls.FakeFFDHE3072), // 257
}

// codexLinuxSignatureAlgorithms is the signature_algorithms list of the Linux
// Codex CLI. OpenSSL 3.6 offers ML-DSA and brainpool schemes that crypto/tls has
// no constants for, so those are given by codepoint.
var codexLinuxSignatureAlgorithms = []tls.SignatureScheme{
	0x0905,                     // mldsa65
	0x0906,                     // mldsa87
	0x0904,                     // mldsa44
	tls.ECDSAWithP256AndSHA256, // 0x0403
	tls.ECDSAWithP384AndSHA384, // 0x0503
	tls.ECDSAWithP521AndSHA512, // 0x0603
	tls.Ed25519,                // 0x0807
	0x0808,                     // ed448
	0x081a,                     // ecdsa_brainpoolP256r1tls13_sha256
	0x081b,                     // ecdsa_brainpoolP384r1tls13_sha384
	0x081c,                     // ecdsa_brainpoolP512r1tls13_sha512
	0x0809,                     // rsa_pss_pss_sha256
	0x080a,                     // rsa_pss_pss_sha384
	0x080b,                     // rsa_pss_pss_sha512
	tls.PSSWithSHA256,          // 0x0804 rsa_pss_rsae_sha256
	tls.PSSWithSHA384,          // 0x0805 rsa_pss_rsae_sha384
	tls.PSSWithSHA512,          // 0x0806 rsa_pss_rsae_sha512
	tls.PKCS1WithSHA256,        // 0x0401
	tls.PKCS1WithSHA384,        // 0x0501
	tls.PKCS1WithSHA512,        // 0x0601
	0x0303,                     // ecdsa_sha224
	0x0301,                     // rsa_pkcs1_sha224
	0x0302,                     // dsa_sha224
	0x0402,                     // dsa_sha256
	0x0502,                     // dsa_sha384
	0x0602,                     // dsa_sha512
}

// CodexLinuxSpecH1 returns the Linux Codex ClientHelloSpec for the HTTP/1.1
// path. A fresh spec is built on every call because utls mutates the spec and
// its extensions during ApplyPreset (it fills in ServerName and generates key
// shares), so callers must never share one.
//
// No ALPN extension is declared: the real client advertises none and speaks
// HTTP/1.1, which is what the ordered-h1 transport writes onto the connection.
func CodexLinuxSpecH1() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
		CipherSuites:       append([]uint16(nil), codexLinuxCipherSuites...),
		CompressionMethods: []uint8{0x00},
		Extensions: []tls.TLSExtension{
			// 65281 renegotiation_info, empty body.
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			// 0 server_name; ApplyPreset fills ServerName from the dialled host.
			&tls.SNIExtension{},
			// 11 ec_point_formats: uncompressed only.
			&tls.SupportedPointsExtension{SupportedPoints: []uint8{0x00}},
			// 10 supported_groups.
			&tls.SupportedCurvesExtension{Curves: append([]tls.CurveID(nil), codexLinuxSupportedGroups...)},
			// 35 session_ticket, empty.
			&tls.SessionTicketExtension{},
			// 22 encrypt_then_mac; OpenSSL-only, no typed utls struct.
			&tls.GenericExtension{Id: 22},
			// 23 extended_master_secret.
			&tls.ExtendedMasterSecretExtension{},
			// 13 signature_algorithms.
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: append([]tls.SignatureScheme(nil), codexLinuxSignatureAlgorithms...),
			},
			// 43 supported_versions: TLS 1.3 then TLS 1.2.
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			// 45 psk_key_exchange_modes: psk_dhe_ke.
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			// 51 key_share; public keys are generated per connection because the
			// Data fields are left empty.
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
		},
	}
}

// CodexLinuxClientHelloRecord serialises the spec into a complete ClientHello
// record for the given server name, without opening a connection. It exists so
// the fingerprint can be inspected and asserted offline; the handshake path uses
// CodexLinuxSpecH1 directly.
func CodexLinuxClientHelloRecord(serverName string) ([]byte, error) {
	spec := CodexLinuxSpecH1()
	if spec == nil {
		return nil, errors.New("nil Codex Linux spec")
	}
	uconn := tls.UClient(nil, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}, tls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("apply Codex Linux preset: %w", err)
	}
	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("marshal Codex Linux ClientHello: %w", err)
	}
	body := uconn.HandshakeState.Hello.Raw
	if len(body) == 0 {
		return nil, errors.New("empty Codex Linux ClientHello")
	}
	// ComputeJA3 and the JA3/JA4 tooling expect a full TLS record, so prepend the
	// handshake record header (type 0x16, legacy version 0x0301).
	record := make([]byte, 0, 5+len(body))
	record = append(record, 0x16, 0x03, 0x01, 0, 0)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
	return append(record, body...), nil
}

// CodexLinuxJA3 returns the JA3 string and hash produced by the declared spec.
// It backs the unit test that pins the fingerprint to the measured client and is
// useful for diagnostics.
func CodexLinuxJA3() (ja3 string, ja3Hash string, err error) {
	record, err := CodexLinuxClientHelloRecord("chatgpt.com")
	if err != nil {
		return "", "", err
	}
	return ComputeJA3(record)
}
