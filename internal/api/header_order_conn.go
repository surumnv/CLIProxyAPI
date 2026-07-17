package api

import (
	"bytes"
	"crypto/tls"
	"net"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

const maxCapturedHeaderOrderBytes = 64 << 10

type headerOrderConn struct {
	net.Conn
	order *util.OriginalHeaderOrder

	mu   sync.Mutex
	buf  []byte
	done bool
}

func newHeaderOrderConn(conn net.Conn) *headerOrderConn {
	return &headerOrderConn{
		Conn:  conn,
		order: &util.OriginalHeaderOrder{},
	}
}

func (c *headerOrderConn) OriginalHeaderOrder() *util.OriginalHeaderOrder {
	if c == nil {
		return nil
	}
	return c.order
}

func (c *headerOrderConn) ConnectionState() tls.ConnectionState {
	if c == nil || c.Conn == nil {
		return tls.ConnectionState{}
	}
	if stater, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return stater.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *headerOrderConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.capture(p[:n])
	}
	return n, err
}

func (c *headerOrderConn) capture(chunk []byte) {
	if c == nil || len(chunk) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	remaining := maxCapturedHeaderOrderBytes - len(c.buf)
	if remaining <= 0 {
		c.done = true
		c.buf = nil
		return
	}
	if len(chunk) > remaining {
		chunk = chunk[:remaining]
	}
	c.buf = append(c.buf, chunk...)
	if bytes.Contains(c.buf, []byte("\r\n\r\n")) || bytes.Contains(c.buf, []byte("\n\n")) {
		c.order.Set(util.ParseOriginalHeaderOrder(c.buf))
		c.done = true
		c.buf = nil
		return
	}
	if len(c.buf) >= maxCapturedHeaderOrderBytes {
		c.done = true
		c.buf = nil
	}
}
