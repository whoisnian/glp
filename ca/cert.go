package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/tls.go;l=355
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("ca: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("ca: failed to parse private key")
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/tls.go;l=320
func verify(cer *x509.Certificate, key crypto.Signer) error {
	if time.Now().After(cer.NotAfter) {
		return errors.New("ca: certificate has expired")
	}

	switch pub := cer.PublicKey.(type) {
	case *rsa.PublicKey:
		if priv, ok := key.(*rsa.PrivateKey); !ok {
			return errors.New("ca: private key type does not match certificate")
		} else if pub.N.Cmp(priv.N) != 0 {
			return errors.New("ca: private key does not match certificate")
		}
	case *ecdsa.PublicKey:
		if priv, ok := key.(*ecdsa.PrivateKey); !ok {
			return errors.New("ca: private key type does not match certificate")
		} else if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return errors.New("ca: private key does not match certificate")
		}
	case ed25519.PublicKey:
		if priv, ok := key.(ed25519.PrivateKey); !ok {
			return errors.New("ca: private key type does not match certificate")
		} else if !pub.Equal(priv.Public()) {
			return errors.New("ca: private key does not match certificate")
		}
	default:
		return errors.New("ca: unknown public key algorithm")
	}
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/generate_cert.go;l=106
func generateSerialNumber() (n *big.Int, err error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func pickCommonName(dns []string, ips []net.IP) string {
	if len(dns) == 0 {
		// len("255.255.255.255") == 15
		// len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == 39
		return ips[0].String()
	}
	result := dns[0]
	if len(result) <= 64 {
		return result
	}

	// xxx.yyy.zzz.s3-accesspoint-fips.dualstack.us-gov-west-1.amazonaws.com => zzz.s3-accesspoint-fips.dualstack.us-gov-west-1.amazonaws.com
	result = result[len(result)-64:]
	return result[strings.IndexByte(result, '.')+1:]
}

func generateCert(template *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

// https://source.chromium.org/chromium/chromium/src/+/main:net/cert/x509_certificate.cc;l=499;drc=facce19fd074e20a40e90d7c7afeee1c47b8dabb
// https://pki.goog/repo/cp/4.2/GTS-CP.html#3-2-2-6-wildcard-domain-validation
func asteriskFor(domain string) []string {
	dotSum := strings.Count(domain, ".")
	if dotSum == 0 {
		// localhost => localhost
		return []string{domain}
	}

	if suffix, icann := publicsuffix.PublicSuffix(domain); icann {
		if dotSuffix := strings.Count(suffix, "."); dotSum == dotSuffix {
			// aisai.aichi.jp => aisai.aichi.jp
			return []string{domain}
		} else if dotSum-dotSuffix == 1 {
			// example.com => *.example.com + example.com
			return []string{"*." + domain, domain}
		} else if dotSum-dotSuffix == 2 {
			// a.example.com => *.example.com + example.com
			pos := strings.IndexByte(domain, '.')
			return []string{"*" + domain[pos:], domain[pos+1:]}
		} else {
			// b.a.example.com => *.a.example.com
			return []string{"*" + domain[strings.IndexByte(domain, '.'):]}
		}
	} else {
		if dotSuffix := strings.Count(suffix, "."); dotSum == 1 || dotSum == dotSuffix {
			// appspot.com => *.appspot.com + appspot.com
			return []string{"*." + domain, domain}
		} else if dotSum-dotSuffix == 1 {
			// a.appspot.com => *.appspot.com + appspot.com
			pos := strings.IndexByte(domain, '.')
			return []string{"*" + domain[pos:], domain[pos+1:]}
		} else {
			// b.a.appspot.com => *.a.appspot.com
			return []string{"*" + domain[strings.IndexByte(domain, '.'):]}
		}
	}
}
