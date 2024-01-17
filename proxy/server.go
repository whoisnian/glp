package proxy

import (
	"net"
	"net/http"
	"runtime/debug"
	"strconv"

	"github.com/whoisnian/glp/ca"
	"github.com/whoisnian/glp/global"
	"golang.org/x/net/proxy"
)

type Server struct {
	addr  string
	proxy string
	ca    *ca.Store

	dialer    proxy.Dialer
	transport *http.Transport
}

func NewServer(addr string, proxy string, ca *ca.Store) (s *Server, err error) {
	s = &Server{addr: addr, proxy: proxy, ca: ca}
	s.dialer, s.transport, err = parseProxy(proxy)
	return s, err
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			global.LOG.Errorf("proxy: panic serving %v: %v\n%s", conn.RemoteAddr(), err, debug.Stack())
		}
	}()

	bufioConn := NewBufioConn(conn)
	defer bufioConn.Close()

	req, err := http.ReadRequest(bufioConn.Reader())
	if err != nil {
		global.LOG.Errorf("proxy: serve.ReadRequest: %s", err.Error())
		return
	}

	if req.URL.Host == "" {
		s.handleRequest(bufioConn, req)
	} else if req.Method == http.MethodConnect {
		bufioConn.Write([]byte("HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n"))

		if data, err := bufioConn.Reader().Peek(8); err != nil {
			global.LOG.Warnf("proxy: fallback to tcp error %s", err.Error())
			s.handleTCP(bufioConn, req)
		} else if sniffTLSHandshakePrefix(data) {
			s.handleTLS(bufioConn, req)
		} else if sniffHTTPMethodPrefix(data) {
			s.handleHTTP(bufioConn, req)
		} else {
			global.LOG.Warnf("proxy: fallback to tcp unknown %s", strconv.QuoteToGraphic(string(data)))
			s.handleTCP(bufioConn, req)
		}
	} else {
		s.handleHTTP(bufioConn, req)
	}
}
