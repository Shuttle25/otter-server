// Package pinning implements SPKI pinning for node TLS (docs/11 D27).
package pinning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

var ErrPinMismatch = errors.New("certificate does not match any pinned key")

func SPKIPin(cert *x509.Certificate) []byte {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:]
}

// ClientConfig returns a TLS config for dialing host. With pins, the CA chain is ignored and the
// leaf must match a pin, be valid now and name host. Without pins, normal verification applies.
func ClientConfig(host string, pins [][]byte) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if len(pins) == 0 {
		return cfg
	}
	cfg.InsecureSkipVerify = true // replaced by VerifyConnection below
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}
		leaf := cs.PeerCertificates[0]
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return fmt.Errorf("certificate not valid now (%v – %v)", leaf.NotBefore, leaf.NotAfter)
		}
		if err := leaf.VerifyHostname(host); err != nil {
			return err
		}
		got := SPKIPin(leaf)
		for _, p := range pins {
			if subtle.ConstantTimeCompare(p, got) == 1 {
				return nil
			}
		}
		return ErrPinMismatch
	}
	return cfg
}

// IssueCert creates a self-signed certificate for an existing key (re-issuing keeps the pin).
func IssueCert(key *ecdsa.PrivateKey, hosts []string, ips []net.IP, validity time.Duration) (certPEM, pin []byte, err error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	cn := ""
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(validity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: hosts, IPAddresses: ips, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), SPKIPin(cert), nil
}

// GenerateCert creates a self-signed ECDSA P-256 certificate (new key) for hosts and ips.
func GenerateCert(hosts []string, ips []net.IP, validity time.Duration) (certPEM, keyPEM, pin []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, pin, err = IssueCert(key, hosts, ips, validity)
	if err != nil {
		return nil, nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), pin, nil
}

// ReadKeyPEM parses an "EC PRIVATE KEY" PEM file written by GenerateCert.
func ReadKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// CertPin returns the SPKI pin of a PEM certificate.
func CertPin(certPEM []byte) ([]byte, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return SPKIPin(c), nil
}
