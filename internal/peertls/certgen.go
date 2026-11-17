package peertls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// GenerateDevDirectory creates a dedicated CA and one identity per ordered player.
// The output directory must be new, so an existing CA is never replaced.
func GenerateDevDirectory(dir string, players []party.ID) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "MPC development CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caKey, err := issue(dir, "ca", ca, ca, nil)
	if err != nil {
		return err
	}
	for index, player := range players {
		nodeDir := filepath.Join(dir, fmt.Sprintf("node-%d", index+1))
		if err := os.Mkdir(nodeDir, 0700); err != nil {
			return err
		}
		leaf := &x509.Certificate{
			DNSNames:  []string{Name(player)},
			NotBefore: ca.NotBefore, NotAfter: now.AddDate(0, 0, 90),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if _, err := issue(nodeDir, "node", leaf, ca, caKey); err != nil {
			return err
		}
	}
	return nil
}

func issue(dir, filename string, template, issuer *x509.Certificate, signer *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serial.Add(serial, big.NewInt(1))
	if signer == nil {
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	if template.IsCA {
		// Use the generated subject key ID when signing the node certificates.
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		template.SubjectKeyId = cert.SubjectKeyId
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	if err := os.WriteFile(filepath.Join(dir, filename+".key"), keyPEM, 0600); err != nil {
		return nil, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, os.WriteFile(filepath.Join(dir, filename+".crt"), cert, 0644)
}
