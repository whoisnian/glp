// https://docs.mitmproxy.org/stable/concepts-certificates/
// https://github.com/mitmproxy/mitmproxy/blob/89189849c0134cb4dd8a229035ea5e892100b775/mitmproxy/certs.py
package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whoisnian/glb/util/fsutil"
	"github.com/whoisnian/glb/util/osutil"
	"github.com/whoisnian/glp/global"
)

func Setup(caCertPath string) (*x509.Certificate, crypto.Signer, error) {
	fullPath, err := fsutil.ExpandHomeDir(caCertPath)
	if err != nil {
		return nil, nil, err
	}

	global.LOG.Infof("loading ca certificate from %s", fullPath)
	cer, key, err := loadCA(fullPath)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		global.LOG.Warnf("%s, generating new certificate", err.Error())
		if cer, key, err = generateCA(); err != nil {
			return nil, nil, err
		}
		err = saveCA(fullPath, cer, key)
	}
	return cer, key, err
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/tls.go;l=245
func loadCA(caCertPath string) (*x509.Certificate, crypto.Signer, error) {
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, err
	}

	var (
		block *pem.Block
		cer   *x509.Certificate
		key   crypto.Signer
	)
	for len(data) > 0 {
		if block, data = pem.Decode(data); block == nil {
			return nil, nil, errors.New("cert: failed to parse pem block")
		}

		if cer == nil && block.Type == "CERTIFICATE" {
			if cer, err = x509.ParseCertificate(block.Bytes); err != nil {
				return nil, nil, err
			}
		} else if key == nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
			if key, err = parsePrivateKey(block.Bytes); err != nil {
				return nil, nil, err
			}
		}
	}

	if cer == nil {
		return nil, nil, errors.New("cert: missing ca certificate in pem blocks")
	} else if key == nil {
		return nil, nil, errors.New("cert: missing private key in pem blocks")
	}
	return cer, key, verify(cer, key)
}

func saveCA(caCertPath string, cer *x509.Certificate, key crypto.Signer) error {
	if err := os.MkdirAll(filepath.Dir(caCertPath), osutil.DefaultDirMode); err != nil {
		return err
	}

	fi, err := os.OpenFile(caCertPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer fi.Close()

	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	if err = pem.Encode(fi, &pem.Block{Type: "PRIVATE KEY", Bytes: data}); err != nil {
		return err
	}
	return pem.Encode(fi, &pem.Block{Type: "CERTIFICATE", Bytes: cer.Raw})
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/crypto/tls/generate_cert.go
// https://github.com/mitmproxy/mitmproxy/blob/89189849c0134cb4dd8a229035ea5e892100b775/mitmproxy/certs.py#L176
func generateCA() (*x509.Certificate, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
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
	cer, err := generateCert(&tmpl, &tmpl, key.Public(), key)
	return cer, key, err
}

// An end-entity certificate is sometimes called a leaf certificate.
// Set Subject.CommonName from first Subject Alternate Name(DNSNames and IPAddresses).
func GenerateLeaf(caCer *x509.Certificate, caKey crypto.Signer, dns []string, ips []net.IP) (*x509.Certificate, crypto.Signer, error) {
	if len(dns) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("cert: missing Subject Alternate Name for leaf certificate")
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   validateCommonName(dns, ips),
			Organization: []string{"mitmproxy"},
		},
		NotBefore:          now.Add(-48 * time.Hour),
		NotAfter:           now.Add(24 * time.Hour * 365),
		DNSNames:           dns,
		IPAddresses:        ips,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// https://github.com/mitmproxy/mitmproxy/blob/89189849c0134cb4dd8a229035ea5e892100b775/mitmproxy/certs.py#L281
	cer, err := generateCert(&tmpl, caCer, caKey.Public(), caKey)
	return cer, caKey, err
}
