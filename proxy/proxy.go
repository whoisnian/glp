package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

var directDialer = &net.Dialer{}

type httpProxy struct {
	addr string
	tls  bool
	hdr  http.Header
}

func newHttpProxy(url *url.URL) *httpProxy {
	hdr := http.Header{}
	if url.User != nil {
		pass, _ := url.User.Password()
		auth := url.User.Username() + ":" + pass
		hdr = http.Header{"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(auth))}}
	}
	return &httpProxy{
		addr: net.JoinHostPort(url.Hostname(), url.Port()),
		tls:  url.Scheme == "https",
		hdr:  hdr,
	}
}

func (p *httpProxy) Dial(network, addr string) (conn net.Conn, err error) {
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  "HTTP/1.1",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: p.hdr,
	}
	if p.tls {
		conn, err = tls.DialWithDialer(directDialer, "tcp", p.addr, nil)
	} else {
		conn, err = directDialer.Dial("tcp", p.addr)
	}
	if err != nil {
		return nil, err
	}

	bufioConn := NewBufioConn(conn)
	req.Write(bufioConn)

	res, err := http.ReadResponse(bufioConn.Reader(), req)
	if err != nil {
		return nil, err
	} else if res.StatusCode != http.StatusOK {
		return nil, errors.New("proxy: unexpected CONNECT status: " + res.Status)
	}
	return bufioConn, nil
}

func parseProxy(rawURL string) (proxy.Dialer, *http.Transport, error) {
	if rawURL == "" {
		return directDialer, &http.Transport{
			Proxy: nil, // http.DefaultTransport but without proxy
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}

	var dialer proxy.Dialer
	if u.Scheme == "socks5" {
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pass}
		}
		if dialer, err = proxy.SOCKS5("tcp", net.JoinHostPort(u.Hostname(), u.Port()), auth, directDialer); err != nil {
			return nil, nil, err
		}
	} else if u.Scheme == "http" || u.Scheme == "https" {
		dialer = newHttpProxy(u)
	} else {
		return nil, nil, errors.New("proxy: unknown scheme: " + u.Scheme)
	}
	return dialer, &http.Transport{
		Proxy: http.ProxyURL(u), // http.DefaultTransport but fixed proxy
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}, nil
}
