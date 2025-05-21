// https://docs.mitmproxy.org/stable/concepts-certificates/
// https://github.com/mitmproxy/mitmproxy/blob/d4200a7c0d2f4efd77c44651645b59662a29a54a/mitmproxy/certs.py
package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whoisnian/glb/logger"
	"github.com/whoisnian/glb/util/fsutil"
	"github.com/whoisnian/glb/util/osutil"
	"github.com/whoisnian/glp/global"
)

var (
	caCer *x509.Certificate
	caKey crypto.Signer

	tlsCerCache *Cache
)

func Setup(ctx context.Context) {
	fpath, err := fsutil.ExpandHomeDir(global.CFG.CACertPath)
	if err != nil {
		global.LOG.Fatal(ctx, "fsutil.ExpandHomeDir", logger.Error(err))
	}

	global.LOG.Infof(ctx, "loading ca certificate from %s", fpath)
	if err = loadFrom(fpath); err != nil && errors.Is(err, fs.ErrNotExist) {
		global.LOG.Warn(ctx, "generating new certificate because of ErrNotExist")
		if err = generateRoot(); err != nil {
			global.LOG.Fatal(ctx, "ca.generateRoot", logger.Error(err))
		}
		if err = saveAs(fpath); err != nil {
			global.LOG.Fatal(ctx, "ca.saveAs", logger.Error(err))
		}
	}

	tlsCerCache = NewCache(128)
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/tls.go;l=255
func loadFrom(certPath string) error {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}

	var block *pem.Block
	for len(data) > 0 {
		if block, data = pem.Decode(data); block == nil {
			return errors.New("ca: failed to parse pem block")
		}

		if caCer == nil && block.Type == "CERTIFICATE" {
			if caCer, err = x509.ParseCertificate(block.Bytes); err != nil {
				return fmt.Errorf("x509.ParseCertificate: %w", err)
			}
		} else if caKey == nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
			if caKey, err = parsePrivateKey(block.Bytes); err != nil {
				return fmt.Errorf("ca.parsePrivateKey: %w", err)
			}
		}
	}

	if caCer == nil {
		return errors.New("ca: missing ca certificate in pem blocks")
	} else if caKey == nil {
		return errors.New("ca: missing private key in pem blocks")
	}
	return verify(caCer, caKey)
}

func saveAs(certPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), osutil.DefaultDirMode); err != nil {
		return fmt.Errorf("os.MkdirAll: %w", err)
	}

	fi, err := os.OpenFile(certPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("os.OpenFile: %w", err)
	}
	defer fi.Close()

	data, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("x509.MarshalPKCS8PrivateKey: %w", err)
	}

	if err = pem.Encode(fi, &pem.Block{Type: "PRIVATE KEY", Bytes: data}); err != nil {
		return fmt.Errorf("caKey pem.Encode: %w", err)
	}
	if err = pem.Encode(fi, &pem.Block{Type: "CERTIFICATE", Bytes: caCer.Raw}); err != nil {
		return fmt.Errorf("caCer pem.Encode: %w", err)
	}
	return nil
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/generate_cert.go
// https://github.com/mitmproxy/mitmproxy/blob/d4200a7c0d2f4efd77c44651645b59662a29a54a/mitmproxy/certs.py#L176
func generateRoot() (err error) {
	caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("ca.generateSerialNumber: %w", err)
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
	if caCer, err = generateCert(&tmpl, &tmpl, caKey.Public(), caKey); err != nil {
		return fmt.Errorf("ca.generateCert: %w", err)
	}
	return nil
}

// An end-entity certificate is sometimes called a leaf certificate.
// Set Subject.CommonName from first Subject Alternate Name(DNSNames and IPAddresses).
func generateLeaf(dns []string, ips []net.IP) (*x509.Certificate, crypto.Signer, error) {
	if len(dns) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("ca: missing Subject Alternate Name for leaf certificate")
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("ca.generateSerialNumber: %w", err)
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
	if cer, err := generateCert(&tmpl, caCer, caKey.Public(), caKey); err != nil {
		return nil, nil, fmt.Errorf("ca.generateCert: %w", err)
	} else {
		return cer, caKey, nil
	}
}

func GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	var dns []string
	var ips []net.IP
	ip := net.ParseIP(serverName)
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		dns = asteriskFor(serverName)
		serverName = dns[0]
	}

	if cer, ok := tlsCerCache.Load(serverName); ok {
		global.LOG.Debug(ctx, "",
			global.LogAttrTag("CERT"),
			global.LogAttrMethod("LOAD"),
			slog.String("name", serverName),
		)
		return cer, nil
	}
	if cer, _, err := generateLeaf(dns, ips); err == nil {
		global.LOG.Debug(ctx, "",
			global.LogAttrTag("CERT"),
			global.LogAttrMethod("STORE"),
			slog.String("name", serverName),
		)
		tlsCer := &tls.Certificate{
			Certificate: [][]byte{cer.Raw, caCer.Raw},
			PrivateKey:  caKey,
			Leaf:        cer,
		}
		tlsCerCache.LoadOrStore(serverName, tlsCer)
		return tlsCer, nil
	} else {
		return nil, fmt.Errorf("ca.generateLeaf: %w", err)
	}
}

func CacheStatus() (length int, capacity int) {
	if tlsCerCache == nil {
		return 0, 0
	}
	return tlsCerCache.Status()
}
