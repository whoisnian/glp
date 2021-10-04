package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"

	"github.com/whoisnian/glb/logger"
	"github.com/whoisnian/glb/util/netutil"
	"github.com/whoisnian/glp/cache"
	"github.com/whoisnian/glp/cert"
)

type Proxy struct {
	caCer    *x509.Certificate
	caKey    *ecdsa.PrivateKey
	cerCache *cache.SyncCache
}

type certPack struct {
	cer *x509.Certificate
	key *ecdsa.PrivateKey
}

func New(caCer *x509.Certificate, caKey *ecdsa.PrivateKey) *Proxy {
	return &Proxy{
		caCer, caKey,
		cache.New(128),
	}
}

func (p *Proxy) ListenAndServe(host, port string) {
	listenAddr := net.JoinHostPort(host, port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Panic(err)
	}

	predictAddr := listenAddr
	if ip := net.ParseIP(host); ip.IsUnspecified() {
		if ip, err := netutil.GetOutBoundIP(); err == nil {
			predictAddr = net.JoinHostPort(ip.String(), port)
		}
	}

	logger.Info("Service started: <http://", listenAddr, ">")
	logger.Info("ENV: export http_proxy=\"http://", predictAddr, "\" https_proxy=\"http://", predictAddr, "\";")
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Panic(err)
		}
		go p.Handle(conn)
	}
}

func (p *Proxy) Handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Error(err)
		return
	}

	if req.Method == "CONNECT" {
		p.handleConnectMethod(conn, req)
	} else {
		p.handleOtherMethod(conn, req)
	}
}

func (p *Proxy) handleConnectMethod(conn net.Conn, req *http.Request) {
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	usedConn, sni, err := checkSNI(conn)
	if err != nil {
		p.handleTCP(usedConn, req)
		return
	}

	if logger.IsDebug() {
		logger.Debug("checkSNI ok: ", sni)
	}

	h := sni
	if h == "" {
		h, _, _ = net.SplitHostPort(req.RequestURI)
	}
	host := hostPromote(h)

	pack, ok := p.cerCache.Load(host[0])
	if !ok {
		cer, key, err := cert.GenerateChild(p.caCer, p.caKey, host)
		if err != nil {
			logger.Error("GenerateChild", err)
			return
		}
		pack, _ = p.cerCache.LoadOrStore(host[0], &certPack{cer, key})
	}

	ck := pack.(*certPack)
	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{ck.cer.Raw, p.caCer.Raw},
			PrivateKey:  ck.key,
		}},
	}

	tlsConn := tls.Server(usedConn, config)
	defer tlsConn.Close()
	reader := bufio.NewReader(tlsConn)
	r2, err := http.ReadRequest(reader)
	if err != nil {
		logger.Error("ReadRequest ", err)
		return
	}

	r2.URL.Scheme = "https"
	r2.URL.Host = r2.Host
	p.handleHTTP(tlsConn, r2)
}

func (p *Proxy) handleOtherMethod(conn net.Conn, req *http.Request) {
	p.handleHTTP(conn, req)
}

func (p *Proxy) handleHTTP(conn net.Conn, req *http.Request) {
	if len(req.RequestURI) < 4 || req.RequestURI[:4] != "http" {
		logger.Info("handleHTTP ", req.Method, " ", req.URL.Scheme, "://", req.URL.Host, req.RequestURI)
	} else {
		logger.Info("handleHTTP ", req.Method, " ", req.RequestURI)
	}
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		logger.Error("handleHTTP ", err)
		return
	}
	res.Write(conn)
}

func (p *Proxy) handleTCP(conn net.Conn, req *http.Request) {
	logger.Info("handleTCP ", req.Method, " ", req.RequestURI)
	outConn, err := net.Dial("tcp", req.RequestURI)
	if err != nil {
		logger.Error("handleTCP ", err)
		return
	}
	defer outConn.Close()

	go func() {
		io.Copy(conn, outConn)
	}()
	io.Copy(outConn, conn)
}
