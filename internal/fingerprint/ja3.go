// Package fingerprint holds the outbound TLS ClientHello fingerprint that
// CLIProxyAPI uses when talking to Anthropic. The active fingerprint is the raw
// ClientHello captured from the real Claude Code CLI (claude.exe); forwarding
// requests reuse the saved value, and only an explicit management call updates
// it.
//
// This file contains the platform-independent pieces: JA3 derivation from a raw
// ClientHello record, turning a raw ClientHello into a utls ClientHelloSpec
// (what the transport layer applies via HelloCustom + ApplyPreset), and the ALPN
// override used to distinguish the official HTTP/2 path from the third-party
// HTTP/1.1 path.
package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// isGREASE reports whether a 16-bit value is a GREASE placeholder
// (0x0a0a, 0x1a1a, ... 0xfafa): high byte == low byte and low nibble == 0xa.
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// ComputeJA3 parses a raw ClientHello record (starting with the 0x16 handshake
// record header) and returns the JA3 string and its MD5 hash, per the JA3 spec:
// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats.
func ComputeJA3(rec []byte) (ja3 string, ja3Hash string, err error) {
	// Skip record header (5) + handshake type (1) + handshake length (3).
	p := 5 + 4
	need := func(n int) error {
		if p+n > len(rec) {
			return errors.New("ClientHello truncated")
		}
		return nil
	}

	if err = need(2); err != nil {
		return "", "", err
	}
	version := int(rec[p])<<8 | int(rec[p+1]) // legacy_version
	p += 2

	p += 32 // random
	if err = need(1); err != nil {
		return "", "", err
	}
	sidLen := int(rec[p])
	p += 1 + sidLen

	// Cipher suites.
	if err = need(2); err != nil {
		return "", "", err
	}
	csLen := int(rec[p])<<8 | int(rec[p+1])
	p += 2
	if err = need(csLen); err != nil {
		return "", "", err
	}
	var ciphers []string
	for i := 0; i+1 < csLen; i += 2 {
		v := uint16(rec[p+i])<<8 | uint16(rec[p+i+1])
		if !isGREASE(v) {
			ciphers = append(ciphers, strconv.Itoa(int(v)))
		}
	}
	p += csLen

	// Compression methods.
	if err = need(1); err != nil {
		return "", "", err
	}
	compLen := int(rec[p])
	p += 1 + compLen

	// Extensions.
	var extTypes, curves, pointFmts []string
	if p+2 <= len(rec) {
		extTotal := int(rec[p])<<8 | int(rec[p+1])
		p += 2
		end := p + extTotal
		if end > len(rec) {
			end = len(rec)
		}
		for p+4 <= end {
			etype := uint16(rec[p])<<8 | uint16(rec[p+1])
			elen := int(rec[p+2])<<8 | int(rec[p+3])
			p += 4
			if p+elen > end {
				break
			}
			data := rec[p : p+elen]
			p += elen
			if isGREASE(etype) {
				continue
			}
			extTypes = append(extTypes, strconv.Itoa(int(etype)))
			switch etype {
			case 0x000a: // supported_groups
				if len(data) >= 2 {
					n := int(data[0])<<8 | int(data[1])
					for i := 0; i+1 < n && 2+i+1 < len(data); i += 2 {
						v := uint16(data[2+i])<<8 | uint16(data[2+i+1])
						if !isGREASE(v) {
							curves = append(curves, strconv.Itoa(int(v)))
						}
					}
				}
			case 0x000b: // ec_point_formats
				if len(data) >= 1 {
					n := int(data[0])
					for i := 0; i < n && 1+i < len(data); i++ {
						pointFmts = append(pointFmts, strconv.Itoa(int(data[1+i])))
					}
				}
			}
		}
	}

	ja3 = strings.Join([]string{
		strconv.Itoa(version),
		strings.Join(ciphers, "-"),
		strings.Join(extTypes, "-"),
		strings.Join(curves, "-"),
		strings.Join(pointFmts, "-"),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:]), nil
}

// SpecFromRaw turns a raw ClientHello record into a utls ClientHelloSpec, which
// the transport layer applies to a UConn via HelloCustom + ApplyPreset. It
// validates that the bytes parse into a spec (the same check the capture tool
// prints as "utls spec OK").
func SpecFromRaw(rec []byte) (*tls.ClientHelloSpec, error) {
	if len(rec) == 0 {
		return nil, errors.New("empty ClientHello")
	}
	spec, err := (&tls.Fingerprinter{}).FingerprintClientHello(rec)
	if err != nil {
		return nil, fmt.Errorf("fingerprint ClientHello: %w", err)
	}
	return spec, nil
}

// ensureSNIExtension guarantees the spec carries a server_name (SNI) extension so
// utls emits SNI on the wire. The Claude ClientHello is captured by pointing
// claude.exe at a local listener addressed by IP (https://127.0.0.1:<port>); per
// RFC 6066 a TLS client sends no server_name for an IP literal, so the captured
// record — and every spec reconstructed from it — has no SNI extension at all.
//
// utls only fills in ServerName for an SNIExtension that already exists in the
// spec (ApplyPreset seeds ext.ServerName from config.ServerName when it is
// empty); it never adds a missing one. Without this, the reconstructed
// ClientHello reaches the upstream with no SNI, and SNI-routed edges (e.g. Aliyun
// ESA in front of some third-party relays) cannot select the right certificate
// and serve a fallback cert, which then fails hostname verification.
//
// A real claude.exe talking to a hostname (api.anthropic.com) does send SNI, so
// adding an empty SNIExtension — whose ServerName utls fills per-connection with
// the actual target host — restores the authentic wire image rather than
// diverging from it. OpenSSL/BoringSSL clients place server_name first, so it is
// prepended. No-op when an SNI extension is already present.
func ensureSNIExtension(spec *tls.ClientHelloSpec) {
	if spec == nil {
		return
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.SNIExtension); ok {
			return
		}
	}
	spec.Extensions = append([]tls.TLSExtension{&tls.SNIExtension{}}, spec.Extensions...)
}

// overrideALPN sets the ALPN protocol list on any ALPN extension present in the
// spec. JA3 keys on extension types, not their contents, so swapping the ALPN
// value keeps the JA3 hash identical while letting the official path advertise
// h2 and the third-party path advertise http/1.1. If the captured ClientHello
// carries no ALPN extension, nothing is added (absence is itself part of the
// fingerprint).
func overrideALPN(spec *tls.ClientHelloSpec, protocols []string) {
	if spec == nil || len(protocols) == 0 {
		return
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			alpn.AlpnProtocols = append([]string(nil), protocols...)
		}
	}
}

// decodeHex parses a raw ClientHello hex string (as printed by the capture tool
// and stored on disk), tolerating surrounding whitespace.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	if s == "" {
		return nil, errors.New("empty hex")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode ClientHello hex: %w", err)
	}
	if len(raw) < 5 || raw[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record (expected leading 0x16)")
	}
	return raw, nil
}
