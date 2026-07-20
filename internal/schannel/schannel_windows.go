//go:build windows

// Package schannel provides a net.Conn backed by Windows SChannel (SSPI), so
// CLIProxyAPI's outbound TLS produces the same ClientHello / JA3 fingerprint as
// a native-tls (schannel-rs) client such as the Codex CLI.
//
// SChannel is used purely as an encrypted transport: the HTTP/1.1 request bytes
// (method, header order, body) are still constructed by Go above this layer
// (the ordered-h1 round tripper), so header-order preservation is unaffected.
// Only the TLS handshake and record encryption happen here.
//
// The legacy SCHANNEL_CRED credential structure is used deliberately. Per
// Microsoft's docs it cannot negotiate TLS 1.3 (that needs the newer
// SCH_CREDENTIALS struct); schannel-rs / native-tls use the same legacy struct,
// which is why a real Codex client tops out at TLS 1.2. Matching the structure
// is what makes the ClientHello — and therefore the JA3/JA4 — line up.
package schannel

import "time"

// ---- SSPI constants -------------------------------------------------------

const (
	schannelCredVersion = 4 // SCHANNEL_CRED_VERSION

	unispName = "Microsoft Unified Security Protocol Provider" // UNISP_NAME_W

	secpkgCredOutbound = 2 // SECPKG_CRED_OUTBOUND

	// grbitEnabledProtocols (client side). 0 means "use the system default".
	spProtTLS1_0Client = 0x00000080
	spProtTLS1_1Client = 0x00000200
	spProtTLS1_2Client = 0x00000800
	spProtTLS1_3Client = 0x00002000

	// SCHANNEL_CRED.dwFlags
	schCredManualCredValidation = 0x00000008
	schCredNoDefaultCreds       = 0x00000010
	schUseStrongCrypto          = 0x00400000

	// fContextReq flags for InitializeSecurityContext
	iscReqConfidentiality      = 0x00000010
	iscReqAllocateMemory       = 0x00000100
	iscReqStream               = 0x00008000
	iscReqExtendedError        = 0x00004000
	iscReqManualCredValidation = 0x00080000

	// SecBuffer types
	secbufferEmpty                = 0
	secbufferData                 = 1
	secbufferToken                = 2
	secbufferExtra                = 5
	secbufferStreamTrailer        = 6
	secbufferStreamHeader         = 7
	secbufferAlert                = 17
	secbufferApplicationProtocols = 18

	// SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT
	secApplicationProtocolNegotiationExtALPN = 2

	// SECPKG_ATTR for reading the negotiated ALPN protocol
	secpkgAttrApplicationProtocol = 35

	secbufferVersion = 0

	secpkgAttrStreamSizes = 4

	// SECURITY_STATUS return codes
	secEOK                = 0x00000000
	secIContinueNeeded    = 0x00090312
	secIContextExpired    = 0x00090317
	secIRenegotiate       = 0x00090321
	secEIncompleteMessage = 0x80090318
)

// ---- SSPI structures (amd64 layout) --------------------------------------

// schannelCred mirrors SCHANNEL_CRED. Explicit padding fields keep the Go
// layout identical to the C struct on amd64 (pointers align to 8 bytes).
type schannelCred struct {
	dwVersion               uint32
	cCreds                  uint32
	paCred                  uintptr
	hRootStore              uintptr
	cMappers                uint32
	_                       uint32 // pad -> align aphMappers to 8
	aphMappers              uintptr
	cSupportedAlgs          uint32
	_                       uint32 // pad -> align palgSupportedAlgs to 8
	palgSupportedAlgs       uintptr
	grbitEnabledProtocols   uint32
	dwMinimumCipherStrength uint32
	dwMaximumCipherStrength uint32
	dwSessionLifespan       uint32
	dwFlags                 uint32
	dwCredFormat            uint32
}

type secHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type secBuffer struct {
	cbBuffer   uint32
	bufferType uint32
	pvBuffer   uintptr
}

type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr
}

type secPkgContextStreamSizes struct {
	cbHeader         uint32
	cbTrailer        uint32
	cbMaximumMessage uint32
	cBuffers         uint32
	cbBlockSize      uint32
}

// ---- public configuration -------------------------------------------------

// Config controls the SChannel credential used for the handshake. The zero
// value (except ServerName) approximates schannel-rs / native-tls behaviour.
type Config struct {
	// ServerName is the SNI host name; required.
	ServerName string

	// EnabledProtocols is grbitEnabledProtocols. 0 lets SChannel pick the
	// system default (the legacy struct tops out at TLS 1.2). Override to pin
	// a specific set while tuning the fingerprint.
	EnabledProtocols uint32

	// ExtraCredFlags is OR'd into SCHANNEL_CRED.dwFlags on top of the base
	// flags (SCH_CRED_NO_DEFAULT_CREDS, and SCH_CRED_MANUAL_CRED_VALIDATION only
	// when InsecureSkipVerify is true). Use it to experiment with e.g.
	// SCH_USE_STRONG_CRYPTO while matching a captured Codex ClientHello.
	ExtraCredFlags uint32

	// InsecureSkipVerify, when true, opts out of SChannel server-certificate
	// validation (SCH_CRED_MANUAL_CRED_VALIDATION + ISC_REQ_MANUAL_CRED_VALIDATION).
	// The default false keeps system chain validation enabled. Certificate
	// validation happens after ClientHello, so this flag does not affect JA3.
	InsecureSkipVerify bool

	// HandshakeTimeout bounds the whole handshake. 0 means no deadline change.
	HandshakeTimeout time.Duration

	// ALPNProtocols is the ordered ALPN list advertised in the ClientHello
	// (e.g. {"h2", "http/1.1"}). Empty means no ALPN extension is sent. Codex's
	// native-tls client advertises ALPN, so set this to match its ClientHello.
	ALPNProtocols []string
}

// Exposed flag/protocol values so callers can tune via Config without
// redeclaring the raw constants.
const (
	SchUseStrongCrypto = schUseStrongCrypto
	ProtTLS10          = spProtTLS1_0Client
	ProtTLS11          = spProtTLS1_1Client
	ProtTLS12          = spProtTLS1_2Client
	ProtTLS13          = spProtTLS1_3Client
)
