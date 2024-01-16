package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

type BufioConn struct {
	net.Conn
	br *bufio.Reader
}

func NewBufioConn(conn net.Conn) *BufioConn {
	return &BufioConn{
		Conn: conn,
		br:   newBufioReader(conn),
	}
}

func (c *BufioConn) Reader() *bufio.Reader {
	return c.br
}

func (c *BufioConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

func (c *BufioConn) WriteTo(w io.Writer) (int64, error) {
	return c.br.WriteTo(w)
}

func (c *BufioConn) Close() error {
	if c.br != nil {
		putBufioReader(c.br)
		c.br = nil
	}
	return c.Conn.Close()
}

type CachedConn struct {
	net.Conn
	used   bool
	buffer *bytes.Buffer
}

func NewCachedConn(conn net.Conn) *CachedConn {
	return &CachedConn{
		Conn:   conn,
		used:   false,
		buffer: newBuffer(),
	}
}

func (c *CachedConn) Rewind() int {
	c.used = true
	return c.buffer.Len()
}

func (c *CachedConn) Prefetch(n int) (buf []byte, err error) {
	if c.used {
		return nil, errors.New("proxy: prefetch on used connection")
	}

	pos := c.buffer.Len()
	_, err = c.buffer.ReadFrom(io.LimitReader(c.Conn, int64(n)))
	return c.buffer.Bytes()[pos:], err
}

func (c *CachedConn) Read(b []byte) (n int, err error) {
	if c.used {
		if c.buffer.Len() > 0 {
			n, _ = c.buffer.Read(b)
			return n, nil
		}
		return c.Conn.Read(b)
	} else {
		n, err = c.Conn.Read(b)
		c.buffer.Write(b[:n])
		return n, err
	}
}

func (c *CachedConn) Close() error {
	if c.buffer != nil {
		putBuffer(c.buffer)
		c.buffer = nil
	}
	return c.Conn.Close()
}
