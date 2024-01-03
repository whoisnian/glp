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
	"strings"
	"sync"
	"time"

	"github.com/whoisnian/glb/util/netutil"
	"github.com/whoisnian/glp/cert"
	"github.com/whoisnian/glp/global"
	"golang.org/x/net/publicsuffix"
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

	cer, err := s.getCertFromCache(clientHello, req)
	if err != nil {
		global.LOG.Errorf("proxy: getCertFromCache %s %s %v", req.Method, req.RequestURI, err)
		s.handleRawTCP(cachedConn, req)
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
	tlsReq, err := http.ReadRequest(bufioConn.Reader())
	if err != nil {
		global.LOG.Errorf("proxy: handleConnect.ReadRequest %s %s %v", req.Method, req.RequestURI, err)
		return
	}

	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host
	s.handleRawHTTP(bufioConn, tlsReq)
}

func (s *Server) getCertFromCache(clientHello *tls.ClientHelloInfo, req *http.Request) (cer *x509.Certificate, err error) {
	san := clientHello.ServerName
	if len(san) == 0 {
		san, _ = netutil.SplitHostPort(req.Host)
	}

	var dns []string
	var ips []net.IP
	key := san
	ip := net.ParseIP(san)
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		dns = asteriskFor(san)
		key = dns[0]
	}

	if cer, ok := s.caCache.Load(key); ok {
		return cer, nil
	}
	if cer, _, err = cert.GenerateLeaf(s.caCer, s.caKey, dns, ips); err == nil {
		s.caCache.LoadOrStore(key, cer)
	}
	return cer, err
}

// https://source.chromium.org/chromium/chromium/src/+/main:net/cert/x509_certificate.cc;l=499;drc=facce19fd074e20a40e90d7c7afeee1c47b8dabb
// https://pki.goog/repo/cp/4.2/GTS-CP.html#3-2-2-6-wildcard-domain-validation
func asteriskFor(host string) []string {
	dotSum := strings.Count(host, ".")
	if dotSum == 0 {
		// localhost => localhost
		return []string{host}
	}

	if suffix, icann := publicsuffix.PublicSuffix(host); icann {
		if dotSuffix := strings.Count(suffix, "."); dotSum == dotSuffix {
			// aisai.aichi.jp => aisai.aichi.jp
			return []string{host}
		} else if dotSum-dotSuffix == 1 {
			// example.com => *.example.com + example.com
			return []string{"*." + host, host}
		} else if dotSum-dotSuffix == 2 {
			// a.example.com => *.example.com + example.com
			pos := strings.IndexByte(host, '.')
			return []string{"*" + host[pos:], host[pos+1:]}
		} else {
			// b.a.example.com => *.a.example.com
			return []string{"*" + host[strings.IndexByte(host, '.'):]}
		}
	} else {
		if dotSuffix := strings.Count(suffix, "."); dotSum == dotSuffix {
			// appspot.com => *.appspot.com + appspot.com
			return []string{"*." + host, host}
		} else if dotSum-dotSuffix == 1 {
			// a.appspot.com => *.appspot.com + appspot.com
			pos := strings.IndexByte(host, '.')
			return []string{"*" + host[pos:], host[pos+1:]}
		} else {
			// b.a.appspot.com => *.a.appspot.com
			return []string{"*" + host[strings.IndexByte(host, '.'):]}
		}
	}
}
