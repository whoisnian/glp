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
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		logger.Debug("return 200 to proxy req")

		tc, sni, err := checkSNI(conn, reader)
		if err != nil {
			logger.Error("checkSNI", err)
			outConn, err := net.Dial("tcp", req.RequestURI)
			if err != nil {
				logger.Error("Dial ", err)
				return
			}
			go func() {
				io.Copy(tc, outConn)
			}()
			io.Copy(outConn, tc)
			return
		}
		logger.Info(sni)
		logger.Debug("parse sni ok")

		h, _, _ := net.SplitHostPort(req.RequestURI)
		cer, key, err := cert.GenerateChild(p.caCer, p.caKey, []string{h})
		if err != nil {
			logger.Error("GenerateChild", err)
			return
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cer.Raw, p.caCer.Raw},
				PrivateKey:  key,
			}},
		}

		tlsConn := tls.Server(tc, config)
		defer tlsConn.Close()
		logger.Debug("upgrade to ssl")
		reader2 := bufio.NewReader(tlsConn)
		r2, err := http.ReadRequest(reader2)
		if err != nil {
			logger.Error("ReadRequest ", err)
			return
		}

		r2.URL.Scheme = "https"
		r2.URL.Host = r2.Host
		logger.Info(r2.Method, " ", r2.URL)
		p.handleHTTP(tlsConn, r2)
	} else {
		logger.Info(req.Method, " ", req.RequestURI)
		p.handleHTTP(conn, req)
	}
	logger.Debug("req end")
}

func (p *Proxy) handleHTTP(conn net.Conn, req *http.Request) {
	logger.Debug("handle HTTP")
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		logger.Error("HandleHTTP ", err)
		return
	}
	res.Write(conn)
}
