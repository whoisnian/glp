package proxy

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"net"
	"net/http"
	"runtime"
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
	defer conn.Close()
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			global.LOG.Errorf("proxy: panic serving %v: %v\n%s", conn.RemoteAddr(), err, buf)
		}
	}()

	bw := newBufioWriter(conn)
	defer putBufioWriter(bw)
	br := newBufioReader(conn)
	defer putBufioReader(br)
	req, err := http.ReadRequest(br)
	if err != nil {
		global.LOG.Errorf("proxy: serve.ReadRequest: %v", err)
		return
	}

	if req.Method == "CONNECT" {
		s.handleConnect(bw, br, req)
	} else {
		s.handleRawHTTP(bw, br, req)
	}
}

func (s *Server) handleRawHTTP(bw *bufio.Writer, br *bufio.Reader, req *http.Request) {
	global.LOG.Infof("proxy: handleRawHTTP %s %s", req.Method, req.RequestURI)
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		global.LOG.Errorf("proxy: handleRawHTTP %s %s %v", req.Method, req.RequestURI, err)
		return
	}
	res.Write(bw)
}

func (s *Server) handleRawTCP(bw *bufio.Writer, br *bufio.Reader, req *http.Request) {
	global.LOG.Infof("proxy: handleRawTCP %s %s", req.Method, req.RequestURI)
	upstream, err := s.dialer.Dial("tcp", req.RequestURI)
	if err != nil {
		global.LOG.Errorf("proxy: handleRawTCP %s %s %v", req.Method, req.RequestURI, err)
		return
	}
	defer upstream.Close()

	go bw.ReadFrom(upstream)
	br.WriteTo(upstream)
}

func (s *Server) handleConnect(bw *bufio.Writer, br *bufio.Reader, req *http.Request) {
	bw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	bw.Flush()

	s.handleRawTCP(bw, br, req)
	// usedConn, sni, err := checkSNI(conn)
	// if err != nil {
	// 	s.handleRawTCP(bw, br, req)
	// 	return
	// }

	// h := sni
	// if h == "" {
	// 	h, _, _ = net.SplitHostPort(req.RequestURI)
	// }
	// host := hostPromote(h)

	// pack, ok := s.caCache.Load(host[0])
	// if !ok {
	// 	cer, key, err := cert.GenerateChild(p.caCer, p.caKey, host)
	// 	if err != nil {
	// 		logger.Error("GenerateChild", err)
	// 		return
	// 	}
	// 	pack, _ = p.cerCache.LoadOrStore(host[0], &certPack{cer, key})
	// }

	// ck := pack.(*certPack)
	// config := &tls.Config{
	// 	Certificates: []tls.Certificate{{
	// 		Certificate: [][]byte{ck.cer.Raw, p.caCer.Raw},
	// 		PrivateKey:  ck.key,
	// 	}},
	// }

	// tlsConn := tls.Server(usedConn, config)
	// defer tlsConn.Close()
	// reader := bufio.NewReader(tlsConn)
	// r2, err := http.ReadRequest(reader)
	// if err != nil {
	// 	logger.Error("ReadRequest ", err)
	// 	return
	// }

	// r2.URL.Scheme = "https"
	// r2.URL.Host = r2.Host
	// s.handleRawHTTP(tlsConn, r2)
}
