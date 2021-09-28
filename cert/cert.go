package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"strings"
)

func LoadCer(fPath string) (cer *x509.Certificate, err error) {
	data, err := os.ReadFile(fPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse " + fPath)
	}
	return x509.ParseCertificate(block.Bytes)
}

func LoadKey(fPath string) (key *ecdsa.PrivateKey, err error) {
	data, err := os.ReadFile(fPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse " + fPath)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func Verify(cer *x509.Certificate, key *ecdsa.PrivateKey) error {
	hash := []byte("verify")
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(cer.PublicKey.(*ecdsa.PublicKey), hash, r, s) {
		return errors.New("failed to verify cert with key")
	}
	return nil
}

func SaveCer(cer *x509.Certificate, fPath string) error {
	cerF, err := os.Create(fPath)
	if err != nil {
		return err
	}
	defer cerF.Close()

	err = pem.Encode(cerF, &pem.Block{Type: "CERTIFICATE", Bytes: cer.Raw})
	return err
}

func SaveKey(key *ecdsa.PrivateKey, fPath string) error {
	keyF, err := os.Create(fPath)
	if err != nil {
		return err
	}
	defer keyF.Close()

	body, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	err = pem.Encode(keyF, &pem.Block{Type: "EC PRIVATE KEY", Bytes: body})
	return err
}

func CerToString(cer *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cer.Raw}))
}

func CerToFireFoxLink(cer *x509.Certificate) string {
	arr := strings.Split(strings.TrimSpace(CerToString(cer)), "\n")
	return "about:certificate?cert=" + url.QueryEscape(strings.Join(arr[1:len(arr)-1], ""))
}

func KeyToString(key *ecdsa.PrivateKey) string {
	body, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: body}))
}

func GenerateCert(template *x509.Certificate, parent *x509.Certificate, pub interface{}, priv interface{}) (*x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
