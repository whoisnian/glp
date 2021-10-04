package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCerName string = "ca.pem"
	caKeyName string = "ca.key"
)

func LoadCA(dir string) (cer *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	cer, err = LoadCer(filepath.Join(dir, caCerName))
	if err != nil {
		return nil, nil, err
	}

	key, err = LoadKey(filepath.Join(dir, caKeyName))
	if err != nil {
		return nil, nil, err
	}

	err = Verify(cer, key)
	if err != nil {
		return cer, key, err
	}
	return cer, key, nil
}

func SaveCA(dir string, cer *x509.Certificate, key *ecdsa.PrivateKey) (err error) {
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	if err = SaveCer(cer, filepath.Join(dir, caCerName)); err != nil {
		return err
	}
	if err = SaveKey(key, filepath.Join(dir, caKeyName)); err != nil {
		return err
	}

	return nil
}

func GenerateCA() (cer *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := certTemplate()
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	cer, err = GenerateCert(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return cer, key, nil
}

func GenerateChild(parentCer *x509.Certificate, parentKey *ecdsa.PrivateKey, dnsNames []string) (cer *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := certTemplate()
	tmpl.DNSNames = dnsNames
	tmpl.Subject = pkix.Name{CommonName: dnsNames[0]}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	cer, err = GenerateCert(tmpl, parentCer, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return cer, key, nil
}

func certTemplate() *x509.Certificate {
	now := time.Now()
	notBefore := now
	notAfter := now.AddDate(100, 0, 0)
	orgCA := pkix.Name{
		Organization: []string{"Localhost Root CA"},
		CommonName:   "LCA",
	}
	return &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixMicro()),
		Issuer:                orgCA,
		Subject:               orgCA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
}
