package proxy

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/whoisnian/glp/cert"
	"github.com/whoisnian/glp/global"
)

type Server struct {
	caCer   *x509.Certificate
	caKey   crypto.Signer
	caCache *cert.SyncCache

	dialer    *net.Dialer
	transport *http.Transport
}

func NewServer(cer *x509.Certificate, key crypto.Signer) *Server {
	// https://pkg.go.dev/net/http#RoundTripper
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &Server{
		caCer:   cer,
		caKey:   key,
		caCache: cert.NewSyncCache(128),

		dialer: dialer,
		transport: &http.Transport{
			Proxy:                 nil, // http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
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
		global.LOG.Errorf("proxy: serve.ReadRequest: %v", err)
		return
	}

	if req.Method == "CONNECT" {
		s.handleConnect(bufioConn, req)
	} else {
		s.handleRawHTTP(bufioConn, req)
	}
}

func (s *Server) handleRawHTTP(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Infof("proxy: handleRawHTTP %s %s", req.Method, req.RequestURI)
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		global.LOG.Errorf("proxy: handleRawHTTP %s %s %v", req.Method, req.RequestURI, err)
		return
	}
	res.Write(conn)
	global.LOG.Infof("proxy: handleRawHTTP %s %s %dms", req.Method, req.RequestURI, time.Since(start).Milliseconds())
}

func (s *Server) handleRawTCP(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Infof("proxy: handleRawTCP  %s %s", req.Method, req.RequestURI)
	upstream, err := s.dialer.Dial("tcp", req.RequestURI)
	if err != nil {
		global.LOG.Errorf("proxy: handleRawTCP  %s %s %v", req.Method, req.RequestURI, err)
		return
	}
	defer upstream.Close()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		io.Copy(conn, upstream)
		wg.Done()
	}()
	io.Copy(upstream, conn)
	wg.Wait()
	global.LOG.Infof("proxy: handleRawTCP  %s %s %dms", req.Method, req.RequestURI, time.Since(start).Milliseconds())
}

func (s *Server) handleConnect(conn net.Conn, req *http.Request) {
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	cachedConn := NewCachedConn(conn)
	defer cachedConn.Close()

	var (
		clientHello  *tls.ClientHelloInfo
		errHandshake = errors.New("proxy: expected interrupt handshake")
	)
	err := tls.Server(&ReadOnlyConn{cachedConn}, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = info
			return nil, errHandshake
		},
	}).Handshake()
	cachedConn.Rewind()
	if err != errHandshake || clientHello == nil {
		global.LOG.Errorf("proxy: handleConnect.Handshake %s %s %v", req.Method, req.RequestURI, err)
		s.handleRawTCP(cachedConn, req)
		return
	}

	cer, ok := s.caCache.Load(clientHello.ServerName)
	if !ok {
		cer, _, err = cert.GenerateLeaf(s.caCer, s.caKey, []string{clientHello.ServerName})
		if err != nil {
			global.LOG.Errorf("proxy: handleConnect.GenerateLeaf %s %s %v", req.Method, req.RequestURI, err)
			s.handleRawTCP(cachedConn, req)
			return
		}
		s.caCache.LoadOrStore(clientHello.ServerName, cer)
	}

	tlsConn := tls.Server(cachedConn, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cer.Raw, s.caCer.Raw},
			PrivateKey:  s.caKey,
			Leaf:        cer,
		}},
	})
	defer tlsConn.Close()

	bufioConn := NewBufioConn(tlsConn)
	defer bufioConn.Close()
	tlsReq, err := http.ReadRequest(bufioConn.Reader())
	if err != nil {
		global.LOG.Errorf("proxy: handleConnect.ReadRequest %s %s %v", req.Method, req.RequestURI, err)
		return
	}

	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host
	s.handleRawHTTP(bufioConn, tlsReq)
}
