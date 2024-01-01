package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"
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
	used   int
	buffer *[]byte
}

func NewCachedConn(conn net.Conn) *CachedConn {
	return &CachedConn{
		Conn:   conn,
		used:   -1,
		buffer: newBuffer(),
	}
}

func (c *CachedConn) Rewind() {
	if c.used == -1 {
		c.used = 0
	}
}

func (c *CachedConn) Read(b []byte) (n int, err error) {
	if c.used == -1 {
		n, err = c.Conn.Read(b)
		*c.buffer = append(*c.buffer, b[:n]...)
		return n, err
	} else {
		if len(*c.buffer) > c.used {
			n = copy(b, (*c.buffer)[c.used:])
			c.used += n
			return n, nil
		}
		return c.Conn.Read(b)
	}
}

func (c *CachedConn) Close() error {
	if c.buffer != nil {
		putBuffer(c.buffer)
		c.buffer = nil
	}
	return c.Conn.Close()
}

var errWriteOnReadOnly = errors.New("proxy: write on read-only connection")

type ReadOnlyConn struct{ Conn net.Conn }

func (c *ReadOnlyConn) Read(b []byte) (int, error)       { return c.Conn.Read(b) }
func (c *ReadOnlyConn) Write([]byte) (int, error)        { return 0, errWriteOnReadOnly }
func (c *ReadOnlyConn) Close() error                     { return nil }
func (c *ReadOnlyConn) LocalAddr() net.Addr              { return nil }
func (c *ReadOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c *ReadOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *ReadOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ReadOnlyConn) SetWriteDeadline(time.Time) error { return nil }
