package proxy

import (
	"bufio"
	"bytes"
	"io"
	"sync"
)

const defaultBufSize = 4096

var (
	bufferPool      sync.Pool
	bufioReaderPool sync.Pool
)

func newBuffer() *bytes.Buffer {
	if v := bufferPool.Get(); v != nil {
		return v.(*bytes.Buffer)
	}
	return bytes.NewBuffer(make([]byte, 0, defaultBufSize))
}

func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	return bufio.NewReaderSize(r, 4096)
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}
