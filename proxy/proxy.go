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
	url *url.URL
	tls bool
}

func (p *httpProxy) Dial(network, addr string) (conn net.Conn, err error) {
	targetAddr := net.JoinHostPort(p.url.Hostname(), p.url.Port())
	hdr := make(http.Header)
	if p.url.User != nil {
		password, _ := p.url.User.Password()
		info := p.url.User.Username() + ":" + password
		hdr.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(info)))
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  "HTTP/1.1",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: hdr,
	}

	if p.tls {
		conn, err = tls.DialWithDialer(directDialer, "tcp", targetAddr, nil)
	} else {
		conn, err = directDialer.Dial("tcp", targetAddr)
	}
	if err != nil {
		return nil, err
	}

	bufioConn := NewBufioConn(conn)
	req.Write(bufioConn)

	res, err := http.ReadResponse(bufioConn.Reader(), req)
	if err != nil {
		return nil, err
	} else if res.StatusCode != 200 {
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
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		if dialer, err = proxy.SOCKS5("tcp", net.JoinHostPort(u.Hostname(), u.Port()), auth, directDialer); err != nil {
			return nil, nil, err
		}
	} else if u.Scheme == "http" {
		dialer = &httpProxy{url: u, tls: false}
	} else if u.Scheme == "https" {
		dialer = &httpProxy{url: u, tls: true}
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
