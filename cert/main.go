package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertName string = "ca.pem"
	caKeyName  string = "ca.key"
)

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certF, err := os.Open(filepath.Join(dir, caCertName))
	if err != nil {
		return nil, nil, err
	}
	defer certF.Close()

	var buf bytes.Buffer
	buf.ReadFrom(certF)
	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		return nil, nil, errors.New("failed to parse ca cert")
	}
	arr := strings.Split(strings.TrimSpace(buf.String()), "\n")
	log.Println("about:certificate?cert=" + url.QueryEscape(strings.Join(arr[1:len(arr)-1], "")))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyF, err := os.Open(filepath.Join(dir, caKeyName))
	if err != nil {
		return nil, nil, err
	}
	defer keyF.Close()

	buf.Reset()
	buf.ReadFrom(keyF)
	block, _ = pem.Decode(buf.Bytes())
	if block == nil {
		return nil, nil, errors.New("failed to parse ca key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	hash := []byte("hello")
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, nil, err
	}
	if !ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), hash, r, s) {
		return nil, nil, errors.New("failed to verify ca cert with key")
	}
	return cert, key, nil
}

func saveCA(dir string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certF, err := os.Create(filepath.Join(dir, caCertName))
	if err != nil {
		return err
	}
	defer certF.Close()

	err = pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return err
	}

	keyF, err := os.Create(filepath.Join(dir, caKeyName))
	if err != nil {
		return err
	}
	defer keyF.Close()

	body, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	err = pem.Encode(keyF, &pem.Block{Type: "EC PRIVATE KEY", Bytes: body})
	if err != nil {
		return err
	}
	return err
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	now := time.Now()
	notBefore := now
	notAfter := now.AddDate(100, 0, 0)
	org := pkix.Name{
		Organization: []string{"Localhost Root CA"},
		CommonName:   "LCA",
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixMicro()),
		Issuer:                org,
		Subject:               org,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generateChild(ca *x509.Certificate, key *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	dnsNames := []string{
		"localhost",
		"localhost.localdomain",
	}
	ipAddresses := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}
	now := time.Now()
	notBefore := now
	notAfter := now.AddDate(100, 0, 0)
	orgCA := pkix.Name{
		Organization: []string{"Localhost Root CA"},
		CommonName:   "LCA",
	}
	orgChild := pkix.Name{
		CommonName: dnsNames[0],
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixMicro()),
		Issuer:                orgCA,
		Subject:               orgChild,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func printCert(cert *x509.Certificate) {
	body := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	arr := strings.Split(strings.TrimSpace(body), "\n")
	log.Println("about:certificate?cert=" + url.QueryEscape(strings.Join(arr[1:len(arr)-1], "")))
	log.Println(body)
}

func printKey(key *ecdsa.PrivateKey) {
	body, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: body})))
}

func main() {
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Fatalln(err)
	}
	dir = filepath.Join(dir, "lca")
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatalln(err)
	}

	cert, key, err := loadCA(dir)
	if err != nil {
		log.Println(err)
		log.Println("generate...")
		cert, key, err = generateCA()
		if err != nil {
			log.Fatalln(err)
		}
	}

	newCert, newKey, err := generateChild(cert, key)
	if err != nil {
		log.Fatalln(err)
	}
	printCert(newCert)
	printKey(newKey)

	err = saveCA(dir, cert, key)
	if err != nil {
		log.Fatalln(err)
	}
}
