package proxy

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/whoisnian/glb/util/netutil"
	"github.com/whoisnian/glp/cert"
	"github.com/whoisnian/glp/global"
	"golang.org/x/net/proxy"
)

type Server struct {
	addr  string
	proxy string
	caCer *x509.Certificate
	caKey crypto.Signer

	cache     *cert.SyncCache
	dialer    proxy.Dialer
	transport *http.Transport
}

func NewServer(addr string, proxy string, cer *x509.Certificate, key crypto.Signer) (s *Server, err error) {
	s = &Server{
		addr:  addr,
		proxy: proxy,
		caCer: cer,
		caKey: key,
		cache: cert.NewSyncCache(128),
	}
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

	if req.Method == http.MethodConnect {
		bufioConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

		if data, err := bufioConn.Reader().Peek(8); err != nil {
			global.LOG.Warnf("proxy: fallback to tcp %s", err.Error())
			s.handleTCP(bufioConn, req)
		} else if sniffTLSHandshakePrefix(data) {
			s.handleTLS(bufioConn, req)
		} else if sniffHTTPMethodPrefix(data) {
			s.handleHTTP(bufioConn, req)
		} else {
			global.LOG.Warnf("proxy: fallback to tcp %x", data)
			s.handleTCP(bufioConn, req)
		}
	} else {
		s.handleHTTP(bufioConn, req)
	}
}

func (s *Server) handleTCP(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Infof("TCP   %-7s %s", req.Method, req.URL)
	upstream, err := s.dialer.Dial("tcp", req.URL.Host)
	if err != nil {
		global.LOG.Errorf("proxy: handleTCP %s %s %s", req.Method, req.URL, err.Error())
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
	global.LOG.Infof("TCP   %-7s %s %dms", req.Method, req.URL, time.Since(start).Milliseconds())
}

func (s *Server) handleHTTP(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Infof("HTTP  %-7s %s", req.Method, req.URL)
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		global.LOG.Errorf("proxy: handleHTTP %s %s %s", req.Method, req.URL, err.Error())
		return
	}
	defer res.Body.Close()

	if w, ok := res.Body.(io.Writer); ok {
		wg := new(sync.WaitGroup)
		wg.Add(1)
		go func() {
			res.Write(conn)
			wg.Done()
		}()
		io.Copy(w, conn)
		wg.Wait()
	} else {
		res.Write(conn)
	}
	global.LOG.Infof("HTTP  %-7s %s %dms", req.Method, req.URL, time.Since(start).Milliseconds())
}

func (s *Server) handleTLS(conn net.Conn, req *http.Request) {
	cachedConn := NewCachedConn(conn)
	defer cachedConn.Close()

	serverName, err := readServerNameIndication(cachedConn)
	cachedConn.Rewind()
	if err != nil {
		global.LOG.Errorf("proxy: readServerNameIndication %s %s %s", req.Method, req.URL, err.Error())
		s.handleTCP(cachedConn, req)
		return
	}

	cer, err := s.getCertFromCache(serverName, req)
	if err != nil {
		global.LOG.Errorf("proxy: getCertFromCache %s %s %s", req.Method, req.URL, err.Error())
		s.handleTCP(cachedConn, req)
		return
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
	if data, err := bufioConn.Reader().Peek(8); err != nil {
		s.handleTCP(bufioConn, req)
	} else if sniffHTTPMethodPrefix(data) {
		tlsReq, err := http.ReadRequest(bufioConn.Reader())
		if err != nil {
			global.LOG.Errorf("proxy: handleTLS.ReadRequest %s %s %s", req.Method, req.URL, err.Error())
			return
		}
		tlsReq.URL.Scheme = "https"
		tlsReq.URL.Host = tlsReq.Host
		s.handleHTTP(bufioConn, tlsReq)
	} else {
		global.LOG.Warnf("proxy: %x(%s) fallback to tcp in tls", data, strconv.QuoteToGraphic(string(data)))
		s.handleTCP(bufioConn, req)
	}
}

func (s *Server) getCertFromCache(serverName string, req *http.Request) (cer *x509.Certificate, err error) {
	if len(serverName) == 0 {
		serverName, _ = netutil.SplitHostPort(req.Host)
	}

	var dns []string
	var ips []net.IP
	key := serverName
	ip := net.ParseIP(serverName)
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		dns = cert.WildcardDomain(serverName)
		key = dns[0]
	}

	if cer, ok := s.cache.Load(key); ok {
		global.LOG.Debugf("CERT  LOAD    %s for %s (%d/%d)", key, serverName, s.cache.Len(), s.cache.Cap())
		return cer, nil
	}
	if cer, _, err = cert.GenerateLeaf(s.caCer, s.caKey, dns, ips); err == nil {
		s.cache.LoadOrStore(key, cer)
		global.LOG.Debugf("CERT  SAVE    %s for %s (%d/%d)", key, serverName, s.cache.Len(), s.cache.Cap())
	}
	return cer, err
}

func sniffHTTPMethodPrefix(data []byte) bool {
	pos := bytes.IndexByte(data, ' ')
	if pos == -1 {
		return false
	}

	method := string(data[:pos])
	if pos == 3 && (method == http.MethodGet || method == http.MethodPut) {
		return true
	} else if pos == 4 && (method == http.MethodPost || method == http.MethodHead) {
		return true
	} else if pos == 5 && method == http.MethodTrace {
		return true
	} else if pos == 6 && method == http.MethodDelete {
		return true
	} else if pos == 7 && (method == http.MethodOptions || method == http.MethodConnect) {
		return true
	} else {
		return false
	}
}

func sniffTLSHandshakePrefix(data []byte) bool {
	// tls.recordTypeHandshake = 0x16
	// tls.VersionTLS10 = 0x0301
	// tls.VersionTLS11 = 0x0302
	// tls.VersionTLS12 = 0x0303
	// tls.VersionTLS13 = 0x0304
	return data[0] == 0x16 && data[1] == 0x03 && data[2] < 0x05
}
