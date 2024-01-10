package proxy

import (
	"bufio"
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

func (c *CachedConn) Rewind() int {
	if c.used == -1 {
		c.used = 0
	}
	return len(*c.buffer)
}

func (c *CachedConn) Prefetch(n int) (buf []byte, err error) {
	if c.used >= 0 {
		return nil, errors.New("proxy: prefetch on used connection")
	} else if len(*c.buffer)+n > cap(*c.buffer) {
		return nil, errors.New("proxy: cache buffer already full")
	}

	sum, cur := 0, 0
	buf = (*c.buffer)[len(*c.buffer) : len(*c.buffer)+n]
	for sum < n && err == nil {
		cur, err = c.Conn.Read(buf[sum:])
		sum += cur
	}
	*c.buffer = (*c.buffer)[:len(*c.buffer)+sum]
	if sum >= n {
		err = nil
	}
	return buf[:sum], err
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
