package proxy

import (
	"bufio"
	"io"
	"sync"
)

var (
	bufferPool      sync.Pool
	bufioReaderPool sync.Pool
)

func newBuffer() *[]byte {
	if v := bufferPool.Get(); v != nil {
		return v.(*[]byte)
	}
	buf := make([]byte, 0, 4096)
	return &buf
}

func putBuffer(buf *[]byte) {
	*buf = (*buf)[:0]
	bufferPool.Put(buf)
}

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	return bufio.NewReader(r)
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}
