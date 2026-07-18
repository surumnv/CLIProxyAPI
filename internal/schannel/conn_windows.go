//go:build windows

package schannel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// buildALPNBuffer builds a SEC_APPLICATION_PROTOCOLS structure:
//
//	DWORD ProtocolListsSize
//	SEC_APPLICATION_PROTOCOL_LIST {
//	    SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt // DWORD
//	    SHORT  ProtocolListSize
//	    BYTE   ProtocolList[]   // each: len-prefixed protocol name
//	}
//
// Returns nil when no protocols are requested.
func buildALPNBuffer(protocols []string) []byte {
	if len(protocols) == 0 {
		return nil
	}
	// Wire-format protocol list: for each proto, 1-byte length + bytes.
	var protoList []byte
	for _, p := range protocols {
		if len(p) == 0 || len(p) > 255 {
			continue
		}
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, p...)
	}
	if len(protoList) == 0 {
		return nil
	}

	// ProtocolListsSize (4) covers everything after it:
	//   ProtoNegoExt(4) + ProtocolListSize(2) + protoList
	extAndList := 4 + 2 + len(protoList)
	buf := make([]byte, 4+extAndList)
	binary.LittleEndian.PutUint32(buf[0:], uint32(extAndList))
	binary.LittleEndian.PutUint32(buf[4:], uint32(secApplicationProtocolNegotiationExtALPN))
	binary.LittleEndian.PutUint16(buf[8:], uint16(len(protoList)))
	copy(buf[10:], protoList)
	return buf
}

var (
	modSecur32                     = windows.NewLazySystemDLL("secur32.dll")
	procAcquireCredentialsHandleW  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procFreeCredentialsHandle      = modSecur32.NewProc("FreeCredentialsHandle")
	procInitializeSecurityContextW = modSecur32.NewProc("InitializeSecurityContextW")
	procDeleteSecurityContext      = modSecur32.NewProc("DeleteSecurityContext")
	procFreeContextBuffer          = modSecur32.NewProc("FreeContextBuffer")
	procQueryContextAttributesW    = modSecur32.NewProc("QueryContextAttributesW")
	procEncryptMessage             = modSecur32.NewProc("EncryptMessage")
	procDecryptMessage             = modSecur32.NewProc("DecryptMessage")
)

// secStatus formats a SECURITY_STATUS for error messages.
func secStatus(code uintptr) string {
	return fmt.Sprintf("0x%08X", uint32(code))
}

// Conn is a net.Conn whose TLS layer is provided by Windows SChannel.
type Conn struct {
	raw    net.Conn
	cfg    Config
	cred   secHandle
	ctx    secHandle
	haveCtx bool

	sizes secPkgContextStreamSizes

	// incoming ciphertext not yet consumed by the TLS layer
	recvRaw []byte
	// decrypted plaintext ready for Read
	plain []byte

	hsDone bool

	mu       sync.Mutex // serializes writes (EncryptMessage)
	readMu   sync.Mutex // serializes reads (DecryptMessage)
}

// Client performs a TLS client handshake over raw using SChannel and returns a
// net.Conn. The caller keeps ownership of raw only through the returned Conn;
// closing the Conn closes raw.
func Client(raw net.Conn, cfg Config) (*Conn, error) {
	if cfg.ServerName == "" {
		return nil, errors.New("schannel: Config.ServerName is required")
	}
	c := &Conn{raw: raw, cfg: cfg}
	if err := c.acquireCredentials(); err != nil {
		return nil, err
	}
	if err := c.handshake(); err != nil {
		c.freeCredentials()
		return nil, err
	}
	return c, nil
}

func (c *Conn) acquireCredentials() error {
	flags := uint32(schCredNoDefaultCreds | schCredManualCredValidation)
	flags |= c.cfg.ExtraCredFlags

	cred := schannelCred{
		dwVersion:             schannelCredVersion,
		grbitEnabledProtocols: c.cfg.EnabledProtocols,
		dwFlags:               flags,
	}

	pkg, err := windows.UTF16PtrFromString(unispName)
	if err != nil {
		return fmt.Errorf("schannel: package name: %w", err)
	}

	var expiry windows.Filetime
	ret, _, _ := procAcquireCredentialsHandleW.Call(
		0, // pszPrincipal
		uintptr(unsafe.Pointer(pkg)),
		secpkgCredOutbound,
		0, // pvLogonID
		uintptr(unsafe.Pointer(&cred)),
		0, // pGetKeyFn
		0, // pvGetKeyArgument
		uintptr(unsafe.Pointer(&c.cred)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	if ret != secEOK {
		return fmt.Errorf("schannel: AcquireCredentialsHandle failed: %s", secStatus(ret))
	}
	return nil
}

func (c *Conn) freeCredentials() {
	if c.cred.dwLower != 0 || c.cred.dwUpper != 0 {
		procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&c.cred)))
		c.cred = secHandle{}
	}
}

const initContextReq = iscReqConfidentiality | iscReqAllocateMemory |
	iscReqStream | iscReqExtendedError | iscReqManualCredValidation

func (c *Conn) handshake() error {
	if c.cfg.HandshakeTimeout > 0 {
		_ = c.raw.SetDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
		defer c.raw.SetDeadline(time.Time{})
	}

	target, err := windows.UTF16PtrFromString(c.cfg.ServerName)
	if err != nil {
		return fmt.Errorf("schannel: server name: %w", err)
	}

	// First call: optionally feed an ALPN buffer, produce the ClientHello token.
	var ctx secHandle
	var ctxAttr uint32
	var expiry windows.Filetime

	outBuf := secBuffer{bufferType: secbufferToken}
	outDesc := secBufferDesc{
		ulVersion: secbufferVersion,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&outBuf)),
	}

	// Build the ALPN input buffer if requested. It must stay alive across the
	// call, so keep alpnBytes referenced until InitializeSecurityContext returns.
	var inDescPtr uintptr
	alpnBytes := buildALPNBuffer(c.cfg.ALPNProtocols)
	var inBuf secBuffer
	var inDesc secBufferDesc
	if len(alpnBytes) > 0 {
		inBuf = secBuffer{
			bufferType: secbufferApplicationProtocols,
			cbBuffer:   uint32(len(alpnBytes)),
			pvBuffer:   bytesPtr(alpnBytes),
		}
		inDesc = secBufferDesc{
			ulVersion: secbufferVersion,
			cBuffers:  1,
			pBuffers:  uintptr(unsafe.Pointer(&inBuf)),
		}
		inDescPtr = uintptr(unsafe.Pointer(&inDesc))
	}

	ret, _, _ := procInitializeSecurityContextW.Call(
		uintptr(unsafe.Pointer(&c.cred)),
		0, // no existing context
		uintptr(unsafe.Pointer(target)),
		uintptr(initContextReq),
		0,
		0, // TargetDataRep unused for SChannel
		inDescPtr, // ALPN input (or 0)
		0,
		uintptr(unsafe.Pointer(&ctx)),
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&ctxAttr)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	runtime.KeepAlive(alpnBytes)
	if ret != secIContinueNeeded {
		return fmt.Errorf("schannel: initial InitializeSecurityContext: %s", secStatus(ret))
	}
	c.ctx = ctx
	c.haveCtx = true

	// Send the ClientHello.
	if outBuf.cbBuffer > 0 && outBuf.pvBuffer != 0 {
		token := goBytes(outBuf.pvBuffer, outBuf.cbBuffer)
		_, werr := c.raw.Write(token)
		procFreeContextBuffer.Call(outBuf.pvBuffer)
		if werr != nil {
			return fmt.Errorf("schannel: write ClientHello: %w", werr)
		}
	}

	return c.handshakeLoop(target)
}

func (c *Conn) handshakeLoop(target *uint16) error {
	buf := make([]byte, 0, 16384)
	tmp := make([]byte, 16384)

	for {
		n, err := c.raw.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return fmt.Errorf("schannel: handshake read: %w", err)
		}

		inBufs := [2]secBuffer{
			{bufferType: secbufferToken, cbBuffer: uint32(len(buf)), pvBuffer: bytesPtr(buf)},
			{bufferType: secbufferEmpty},
		}
		inDesc := secBufferDesc{
			ulVersion: secbufferVersion,
			cBuffers:  2,
			pBuffers:  uintptr(unsafe.Pointer(&inBufs[0])),
		}

		outBuf := secBuffer{bufferType: secbufferToken}
		outDesc := secBufferDesc{
			ulVersion: secbufferVersion,
			cBuffers:  1,
			pBuffers:  uintptr(unsafe.Pointer(&outBuf)),
		}

		var ctxAttr uint32
		var expiry windows.Filetime

		ret, _, _ := procInitializeSecurityContextW.Call(
			uintptr(unsafe.Pointer(&c.cred)),
			uintptr(unsafe.Pointer(&c.ctx)),
			uintptr(unsafe.Pointer(target)),
			uintptr(initContextReq),
			0,
			0,
			uintptr(unsafe.Pointer(&inDesc)),
			0,
			uintptr(unsafe.Pointer(&c.ctx)),
			uintptr(unsafe.Pointer(&outDesc)),
			uintptr(unsafe.Pointer(&ctxAttr)),
			uintptr(unsafe.Pointer(&expiry)),
		)

		// Emit any output token regardless of status (may carry client Finished).
		if outBuf.cbBuffer > 0 && outBuf.pvBuffer != 0 {
			token := goBytes(outBuf.pvBuffer, outBuf.cbBuffer)
			_, werr := c.raw.Write(token)
			procFreeContextBuffer.Call(outBuf.pvBuffer)
			if werr != nil {
				return fmt.Errorf("schannel: handshake write: %w", werr)
			}
		}

		switch ret {
		case secEOK:
			// Handshake complete. Preserve any extra (leftover) bytes.
			if extra := findExtra(&inBufs); extra > 0 {
				c.recvRaw = append(c.recvRaw, buf[len(buf)-extra:]...)
			}
			return c.finishHandshake()

		case secIContinueNeeded:
			if extra := findExtra(&inBufs); extra > 0 {
				buf = append(buf[:0], buf[len(buf)-extra:]...)
			} else {
				buf = buf[:0]
			}
			continue

		case secEIncompleteMessage:
			// Need more bytes; keep accumulating into buf.
			continue

		default:
			return fmt.Errorf("schannel: handshake InitializeSecurityContext: %s", secStatus(ret))
		}
	}
}

// findExtra returns the number of trailing bytes SChannel reported as SECBUFFER_EXTRA.
func findExtra(bufs *[2]secBuffer) int {
	for i := range bufs {
		if bufs[i].bufferType == secbufferExtra && bufs[i].cbBuffer > 0 {
			return int(bufs[i].cbBuffer)
		}
	}
	return 0
}

func (c *Conn) finishHandshake() error {
	ret, _, _ := procQueryContextAttributesW.Call(
		uintptr(unsafe.Pointer(&c.ctx)),
		secpkgAttrStreamSizes,
		uintptr(unsafe.Pointer(&c.sizes)),
	)
	if ret != secEOK {
		return fmt.Errorf("schannel: QueryContextAttributes(StreamSizes): %s", secStatus(ret))
	}
	c.hsDone = true
	return nil
}

// ---- net.Conn: Write ------------------------------------------------------

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hsDone {
		return 0, errors.New("schannel: write before handshake complete")
	}

	total := 0
	max := int(c.sizes.cbMaximumMessage)
	if max <= 0 {
		max = 16384
	}
	for len(b) > 0 {
		chunk := b
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		if err := c.writeChunk(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *Conn) writeChunk(chunk []byte) error {
	header := int(c.sizes.cbHeader)
	trailer := int(c.sizes.cbTrailer)

	// Layout: [header][plaintext][trailer] in one contiguous buffer.
	msg := make([]byte, header+len(chunk)+trailer)
	copy(msg[header:], chunk)

	bufs := [3]secBuffer{
		{bufferType: secbufferStreamHeader, cbBuffer: uint32(header), pvBuffer: bytesPtr(msg)},
		{bufferType: secbufferData, cbBuffer: uint32(len(chunk)), pvBuffer: bytesPtrAt(msg, header)},
		{bufferType: secbufferStreamTrailer, cbBuffer: uint32(trailer), pvBuffer: bytesPtrAt(msg, header+len(chunk))},
	}
	desc := secBufferDesc{
		ulVersion: secbufferVersion,
		cBuffers:  3,
		pBuffers:  uintptr(unsafe.Pointer(&bufs[0])),
	}

	ret, _, _ := procEncryptMessage.Call(
		uintptr(unsafe.Pointer(&c.ctx)),
		0,
		uintptr(unsafe.Pointer(&desc)),
		0,
	)
	if ret != secEOK {
		return fmt.Errorf("schannel: EncryptMessage: %s", secStatus(ret))
	}

	// After encryption, cbBuffer of each SecBuffer holds the real size.
	out := make([]byte, 0, bufs[0].cbBuffer+bufs[1].cbBuffer+bufs[2].cbBuffer)
	out = append(out, msg[:bufs[0].cbBuffer]...)
	out = append(out, msg[header:header+int(bufs[1].cbBuffer)]...)
	out = append(out, msg[header+len(chunk):header+len(chunk)+int(bufs[2].cbBuffer)]...)

	if _, err := c.raw.Write(out); err != nil {
		return fmt.Errorf("schannel: raw write: %w", err)
	}
	return nil
}

// ---- net.Conn: Read -------------------------------------------------------

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.plain) > 0 {
		n := copy(b, c.plain)
		c.plain = c.plain[n:]
		return n, nil
	}
	if !c.hsDone {
		return 0, errors.New("schannel: read before handshake complete")
	}

	tmp := make([]byte, 16384)
	for {
		// Try to decrypt whatever ciphertext we already have.
		if len(c.recvRaw) > 0 {
			n, done, err := c.decrypt()
			if err != nil {
				return 0, err
			}
			if done {
				return 0, io.EOF
			}
			if n {
				out := copy(b, c.plain)
				c.plain = c.plain[out:]
				return out, nil
			}
			// need more bytes
		}

		rn, rerr := c.raw.Read(tmp)
		if rn > 0 {
			c.recvRaw = append(c.recvRaw, tmp[:rn]...)
			continue
		}
		if rerr != nil {
			if len(c.recvRaw) == 0 {
				return 0, rerr
			}
			return 0, rerr
		}
	}
}

// decrypt attempts to decrypt one TLS record from c.recvRaw. Returns
// (producedPlaintext, contextExpired, error).
func (c *Conn) decrypt() (bool, bool, error) {
	bufs := [4]secBuffer{
		{bufferType: secbufferData, cbBuffer: uint32(len(c.recvRaw)), pvBuffer: bytesPtr(c.recvRaw)},
		{bufferType: secbufferEmpty},
		{bufferType: secbufferEmpty},
		{bufferType: secbufferEmpty},
	}
	desc := secBufferDesc{
		ulVersion: secbufferVersion,
		cBuffers:  4,
		pBuffers:  uintptr(unsafe.Pointer(&bufs[0])),
	}

	ret, _, _ := procDecryptMessage.Call(
		uintptr(unsafe.Pointer(&c.ctx)),
		uintptr(unsafe.Pointer(&desc)),
		0,
		0,
	)

	switch ret {
	case secEOK:
		var extra []byte
		produced := false
		for i := range bufs {
			switch bufs[i].bufferType {
			case secbufferData:
				if bufs[i].cbBuffer > 0 {
					c.plain = append(c.plain, goBytes(bufs[i].pvBuffer, bufs[i].cbBuffer)...)
					produced = true
				}
			case secbufferExtra:
				if bufs[i].cbBuffer > 0 {
					extra = append(extra, goBytes(bufs[i].pvBuffer, bufs[i].cbBuffer)...)
				}
			}
		}
		c.recvRaw = append(c.recvRaw[:0], extra...)
		return produced, false, nil

	case secEIncompleteMessage:
		// keep buffering
		return false, false, nil

	case secIContextExpired:
		c.recvRaw = c.recvRaw[:0]
		return false, true, nil

	case secIRenegotiate:
		// A server-initiated renegotiation. For our client use (Codex-style
		// short-lived requests) we treat it as unsupported rather than risk a
		// broken state machine.
		return false, false, errors.New("schannel: server requested renegotiation (unsupported)")

	default:
		return false, false, fmt.Errorf("schannel: DecryptMessage: %s", secStatus(ret))
	}
}

// ---- net.Conn: lifecycle & passthrough ------------------------------------

func (c *Conn) Close() error {
	if c.haveCtx {
		procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&c.ctx)))
		c.haveCtx = false
	}
	c.freeCredentials()
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// ---- helpers --------------------------------------------------------------

// goBytes copies cnt bytes from a native buffer into a Go slice.
func goBytes(ptr uintptr, cnt uint32) []byte {
	if ptr == 0 || cnt == 0 {
		return nil
	}
	out := make([]byte, cnt)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), cnt))
	return out
}

// bytesPtr returns a pointer to the first byte of b (0 if empty).
func bytesPtr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

// bytesPtrAt returns a pointer to b[off].
func bytesPtrAt(b []byte, off int) uintptr {
	if off >= len(b) {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[off]))
}

var _ net.Conn = (*Conn)(nil)
