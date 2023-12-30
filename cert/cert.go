package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
)

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/tls.go;l=339
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
			return nil, errors.New("cert: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("cert: failed to parse private key")
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/tls.go;l=304
func verify(cer *x509.Certificate, key crypto.Signer) error {
	switch pub := cer.PublicKey.(type) {
	case *rsa.PublicKey:
		if priv, ok := key.(*rsa.PrivateKey); !ok {
			return errors.New("cert: private key type does not match certificate")
		} else if pub.N.Cmp(priv.N) != 0 {
			return errors.New("cert: private key does not match certificate")
		}
	case *ecdsa.PublicKey:
		if priv, ok := key.(*ecdsa.PrivateKey); !ok {
			return errors.New("cert: private key type does not match certificate")
		} else if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return errors.New("cert: private key does not match certificate")
		}
	case ed25519.PublicKey:
		if priv, ok := key.(ed25519.PrivateKey); !ok {
			return errors.New("cert: private key type does not match certificate")
		} else if !pub.Equal(priv.Public()) {
			return errors.New("cert: private key does not match certificate")
		}
	default:
		return errors.New("cert: unknown public key algorithm")
	}
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/generate_cert.go;l=106
func generateSerialNumber() (n *big.Int, err error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// TODO: https://pkg.go.dev/golang.org/x/net/publicsuffix
func validateCommonName(cn string) string {
	// len("255.255.255.255") == 15
	// len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == 39
	if len(cn) <= 64 {
		return cn
	}

	// xxx.yyy.zzz.s3-accesspoint-fips.dualstack.us-gov-west-1.amazonaws.com => .zzz.s3-accesspoint-fips.dualstack.us-gov-west-1.amazonaws.com
	for i := len(cn) - 64; i < len(cn); i++ {
		if cn[i] == '.' {
			return cn[i:]
		}
	}
	return cn[len(cn)-64:]
}

func generateCert(template *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
