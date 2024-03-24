// https://docs.mitmproxy.org/stable/concepts-certificates/
// https://github.com/mitmproxy/mitmproxy/blob/d4200a7c0d2f4efd77c44651645b59662a29a54a/mitmproxy/certs.py
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whoisnian/glb/util/fsutil"
	"github.com/whoisnian/glb/util/osutil"
	"github.com/whoisnian/glp/global"
)

type Store struct {
	caCer *x509.Certificate
	caKey crypto.Signer
	Cache *Cache
}

func NewStore(certPath string) (*Store, error) {
	fullPath, err := fsutil.ExpandHomeDir(certPath)
	if err != nil {
		return nil, err
	}

	s := Store{Cache: NewCache(128)}
	global.LOG.Infof("loading ca certificate from %s", fullPath)
	if err = s.loadFrom(fullPath); err != nil && errors.Is(err, fs.ErrNotExist) {
		global.LOG.Warnf("%s, generating new certificate", err.Error())
		if err = s.generateCA(); err != nil {
			return nil, err
		}
		err = s.saveAs(fullPath)
	}
	return &s, err
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.22.1:src/crypto/tls/tls.go;l=245
func (s *Store) loadFrom(certPath string) error {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	var block *pem.Block
	for len(data) > 0 {
		if block, data = pem.Decode(data); block == nil {
			return errors.New("ca: failed to parse pem block")
		}

		if s.caCer == nil && block.Type == "CERTIFICATE" {
			if s.caCer, err = x509.ParseCertificate(block.Bytes); err != nil {
				return err
			}
		} else if s.caKey == nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
			if s.caKey, err = parsePrivateKey(block.Bytes); err != nil {
				return err
			}
		}
	}

	if s.caCer == nil {
		return errors.New("ca: missing ca certificate in pem blocks")
	} else if s.caKey == nil {
		return errors.New("ca: missing private key in pem blocks")
	}
	return verify(s.caCer, s.caKey)
}

func (s *Store) saveAs(certPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), osutil.DefaultDirMode); err != nil {
		return err
	}

	fi, err := os.OpenFile(certPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer fi.Close()

	data, err := x509.MarshalPKCS8PrivateKey(s.caKey)
	if err != nil {
		return err
	}

	if err = pem.Encode(fi, &pem.Block{Type: "PRIVATE KEY", Bytes: data}); err != nil {
		return err
	}
	return pem.Encode(fi, &pem.Block{Type: "CERTIFICATE", Bytes: s.caCer.Raw})
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.22.1:src/crypto/tls/generate_cert.go
// https://github.com/mitmproxy/mitmproxy/blob/d4200a7c0d2f4efd77c44651645b59662a29a54a/mitmproxy/certs.py#L176
func (s *Store) generateCA() (err error) {
	s.caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "mitmproxy",
			Organization: []string{"mitmproxy"},
		},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour * 365 * 10),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// If parent is equal to template then the certificate is self-signed.
	s.caCer, err = generateCert(&tmpl, &tmpl, s.caKey.Public(), s.caKey)
	return err
}

// An end-entity certificate is sometimes called a leaf certificate.
// Set Subject.CommonName from first Subject Alternate Name(DNSNames and IPAddresses).
func (s *Store) generateLeaf(dns []string, ips []net.IP) (*x509.Certificate, crypto.Signer, error) {
	if len(dns) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("ca: missing Subject Alternate Name for leaf certificate")
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   pickCommonName(dns, ips),
			Organization: []string{"mitmproxy"},
		},
		NotBefore:          now.Add(-48 * time.Hour),
		NotAfter:           now.Add(24 * time.Hour * 365),
		DNSNames:           dns,
		IPAddresses:        ips,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// https://github.com/mitmproxy/mitmproxy/blob/d4200a7c0d2f4efd77c44651645b59662a29a54a/mitmproxy/certs.py#L281
	cer, err := generateCert(&tmpl, s.caCer, s.caKey.Public(), s.caKey)
	return cer, s.caKey, err
}

func (s *Store) Cer() *x509.Certificate {
	return s.caCer
}

func (s *Store) Key() crypto.Signer {
	return s.caKey
}

func (s *Store) GetLeaf(serverName string) (*x509.Certificate, crypto.Signer, error) {
	var dns []string
	var ips []net.IP
	ip := net.ParseIP(serverName)
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		dns = asteriskFor(serverName)
		serverName = dns[0]
	}

	if cer, ok := s.Cache.Load(serverName); ok {
		global.LOG.Debug("",
			global.LogAttrMap["CERT"],
			global.LogAttrMap["LOAD"],
			slog.String("name", serverName),
		)
		return cer, s.caKey, nil
	}
	if cer, _, err := s.generateLeaf(dns, ips); err == nil {
		global.LOG.Debug("",
			global.LogAttrMap["CERT"],
			global.LogAttrMap["STORE"],
			slog.String("name", serverName),
		)
		s.Cache.LoadOrStore(serverName, cer)
		return cer, s.caKey, nil
	} else {
		return nil, nil, err
	}
}
