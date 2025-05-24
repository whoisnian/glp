package proxy

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/whoisnian/glb/util/netutil"
	"github.com/whoisnian/glp/ca"
	"github.com/whoisnian/glp/global"
)

type ServerStatus struct {
	Goroutines int
	CacheCap   int
	CacheLen   int
}

func (s *Server) handleRequest(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Debug(req.Context(), "",
		global.LogAttrTag("HTTP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
	)

	if req.Method == http.MethodGet && req.URL.Path == "/status" {
		buf := newBuffer()
		defer putBuffer(buf)

		length, capacity := ca.CacheStatus()
		json.NewEncoder(buf).Encode(ServerStatus{
			Goroutines: runtime.NumGoroutine(),
			CacheCap:   capacity,
			CacheLen:   length,
		})

		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: "))
		conn.Write([]byte(strconv.Itoa(buf.Len())))
		conn.Write([]byte("\r\n\r\n"))
		buf.WriteTo(conn)
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	}
	global.LOG.Info(req.Context(), "",
		global.LogAttrTag("HTTP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
		global.LogAttrDuration(time.Since(start)),
	)
}

func (s *Server) handleTCP(conn net.Conn, req *http.Request, secure bool) {
	start := time.Now()
	global.LOG.Debug(req.Context(), "",
		global.LogAttrTag("TCP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
	)
	upstream, err := s.dialer.Dial("tcp", req.URL.Host)
	if err != nil {
		global.LOG.Errorf(req.Context(), "proxy: handleTCP %s %s %s", req.Method, req.URL, err.Error())
		return
	}
	if secure {
		hostname, _ := netutil.SplitHostPort(req.URL.Host)
		upstream = tls.Client(upstream, &tls.Config{ServerName: hostname})
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
	global.LOG.Info(req.Context(), "",
		global.LogAttrTag("TCP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
		global.LogAttrDuration(time.Since(start)),
	)
}

func (s *Server) handleHTTP(conn net.Conn, req *http.Request) {
	start := time.Now()
	global.LOG.Debug(req.Context(), "",
		global.LogAttrTag("HTTP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
	)
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		global.LOG.Errorf(req.Context(), "proxy: handleHTTP %s %s %s", req.Method, req.URL, err.Error())
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
	global.LOG.Info(req.Context(), "",
		global.LogAttrTag("HTTP"),
		global.LogAttrMethod(req.Method),
		global.LogAttrURL(req.URL),
		global.LogAttrDuration(time.Since(start)),
	)
}

func (s *Server) handleTLS(conn net.Conn, req *http.Request) {
	cachedConn := NewCachedConn(conn)
	defer cachedConn.Close()

	serverName, err := sniffTLSHandshakeServerName(cachedConn)
	cachedConn.Rewind()
	if err != nil {
		global.LOG.Errorf(req.Context(), "proxy: sniffTLSHandshakeServerName %s %s %s", req.Method, req.URL, err.Error())
		s.handleTCP(cachedConn, req, false)
		return
	}

	if len(serverName) == 0 {
		serverName, _ = netutil.SplitHostPort(req.Host)
	}
	cer, err := ca.GetCertificate(req.Context(), serverName)
	if err != nil {
		global.LOG.Errorf(req.Context(), "proxy: ca.GetCertificate %s %s %s", req.Method, req.URL, err.Error())
		s.handleTCP(cachedConn, req, false)
		return
	}
	tlsConn := tls.Server(cachedConn, &tls.Config{
		Certificates: []tls.Certificate{*cer},
		KeyLogWriter: s.klogw,
	})
	defer tlsConn.Close()

	bufioConn := NewBufioConn(tlsConn)
	defer bufioConn.Close()
	if data, err := bufioConn.Reader().Peek(8); err != nil {
		global.LOG.Warnf(req.Context(), "proxy: fallback to tcp in tls error %s for %s %s", err.Error(), req.Method, req.URL)
		s.handleTCP(bufioConn, req, true)
	} else if sniffHTTPMethodPrefix(data) {
		tlsReq, err := http.ReadRequest(bufioConn.Reader())
		if err != nil {
			global.LOG.Errorf(req.Context(), "proxy: handleTLS.ReadRequest %s %s %s", req.Method, req.URL, err.Error())
			return
		}
		tlsReq.URL.Scheme = "https"
		tlsReq.URL.Host = tlsReq.Host
		s.handleHTTP(bufioConn, tlsReq)
	} else if sniffGcmLoginPrefix(data) {
		s.handleTCP(bufioConn, req, true)
	} else {
		global.LOG.Warnf(req.Context(), "proxy: fallback to tcp in tls unknown %s for %s %s", strconv.QuoteToGraphic(string(data)), req.Method, req.URL)
		s.handleTCP(bufioConn, req, true)
	}
}
