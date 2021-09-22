package main

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

var certBlock string = `
-----BEGIN CERTIFICATE-----
MIIB4zCCAYigAwIBAgIHBcyXl0f15jAKBggqhkjOPQQDAjAqMRowGAYDVQQKExFM
b2NhbGhvc3QgUm9vdCBDQTEMMAoGA1UEAxMDTENBMCAXDTIxMDkyMjE1NTg1M1oY
DzIxMjEwOTIyMTU1ODUzWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASAsLu50I8X1KFGXeeEWcGU8s8dYGvHRk4+RoNNwipG
e4QzhKcM/DMKVeMH+Yt0TYx/AB6yPp+938TMqhYenM2Vo4GsMIGpMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUkwTVH+rrNlfJ
QVZ2Px5eRHjIs0owYwYDVR0RBFwwWoIJbG9jYWxob3N0ghVsb2NhbGhvc3QubG9j
YWxkb21haW6CDXdob2lzbmlhbi5jb22CDyoud2hvaXNuaWFuLmNvbYcEfwAAAYcQ
AAAAAAAAAAAAAAAAAAAAATAKBggqhkjOPQQDAgNJADBGAiEApaiJf/Cyoi5bv6H/
+GbHt/s4kmwHlwDHstBR9GFUo58CIQC7Dp5VDcJq0ETjqOs6Xy+7oRHweXClQNq/
aJOm2iCNdg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIHBcxueZznRDAKBggqhkjOPQQDAjAqMRowGAYDVQQKExFM
b2NhbGhvc3QgUm9vdCBDQTEMMAoGA1UEAxMDTENBMCAXDTIxMDkyMDE0NTU0MloY
DzIxMjEwOTIwMTQ1NTQyWjAqMRowGAYDVQQKExFMb2NhbGhvc3QgUm9vdCBDQTEM
MAoGA1UEAxMDTENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgLC7udCPF9Sh
Rl3nhFnBlPLPHWBrx0ZOPkaDTcIqRnuEM4SnDPwzClXjB/mLdE2MfwAesj6fvd/E
zKoWHpzNlaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFJME1R/q6zZXyUFWdj8eXkR4yLNKMAoGCCqGSM49BAMCA0gAMEUCIQDY
5XXK1lMxMAfM4gjo3Z4Y1i4jDaGsrzqzDAH16a8JUwIgemjzQz38X9e7qufxkpBk
OUpFCAZpvxKvDCa+GaZpZ6k=
-----END CERTIFICATE-----
`
var keyBlock string = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEV7nnfb1Xk8VK00I/8vcAioYyij3At2d/bEYqSEcxDuoAoGCCqGSM49
AwEHoUQDQgAEgLC7udCPF9ShRl3nhFnBlPLPHWBrx0ZOPkaDTcIqRnuEM4SnDPwz
ClXjB/mLdE2MfwAesj6fvd/EzKoWHpzNlQ==
-----END EC PRIVATE KEY-----
`

func main() {
	log.Println("start at :8889")

	l, err := net.Listen("tcp", ":8889")
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func(c net.Conn) {
			reader := bufio.NewReader(conn)
			r, err := http.ReadRequest(reader)
			if err != nil {
				log.Fatal(err)
			}
			log.Println(r.Method, r.RequestURI)

			if r.Method == "CONNECT" {
				// for https
				conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

				config := &tls.Config{}
				config.Certificates = make([]tls.Certificate, 1)
				config.Certificates[0], err = tls.X509KeyPair([]byte(certBlock), []byte(keyBlock))
				if err != nil {
					log.Panicln(err)
				}

				tlsConn := tls.Server(conn, config)
				defer tlsConn.Close()
				reader2 := bufio.NewReader(tlsConn)
				r2, err := http.ReadRequest(reader2)
				if err != nil {
					log.Panicln(err)
				}
				r2.URL.Scheme = "https"
				r2.URL.Host = r2.Host
				log.Println("HTTPS:", r2.Method, r2.URL)

				res, err := http.DefaultTransport.RoundTrip(r2)
				if err != nil {
					log.Fatal(err)
				}

				res.Write(tlsConn)
			} else {
				defer conn.Close()
				// for http
				res, err := http.DefaultTransport.RoundTrip(r)
				if err != nil {
					log.Fatal(err)
				}

				res.Write(conn)
			}
		}(conn)
	}
}
