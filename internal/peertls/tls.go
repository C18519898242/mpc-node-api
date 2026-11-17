package peertls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Name maps a party ID to a single DNS SAN without relying on IP addresses or DNS resolution.
func Name(id party.ID) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(id))
	return "mpc-node-" + strings.ToLower(encoded)
}

type Identity struct {
	cert tls.Certificate
	cas  *x509.CertPool
}

func Load(id party.ID, caFile, certFile, keyFile string) (*Identity, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read peer CA: %w", err)
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(ca) {
		return nil, errors.New("MPC CA file contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load MPC identity: %w", err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != Name(id) {
		return nil, errors.New("MPC certificate SAN does not match the local party ID")
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(intermediate)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: cas, Intermediates: intermediates, DNSName: Name(id), KeyUsages: []x509.ExtKeyUsage{usage},
		}); err != nil {
			return nil, fmt.Errorf("verify local MPC certificate: %w", err)
		}
	}
	return &Identity{cert: cert, cas: cas}, nil
}

func (i *Identity) Client(peer party.ID) *tls.Config {
	name := Name(peer)
	allowed := map[string]party.ID{name: peer}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: i.cas, ServerName: name,
		Certificates: []tls.Certificate{i.cert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if Peer(state, allowed) != peer {
				return errors.New("MPC server certificate does not identify the expected peer")
			}
			return nil
		},
	}
}

func (i *Identity) Server(allowed map[string]party.ID) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: i.cas, Certificates: []tls.Certificate{i.cert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if Peer(state, allowed) == "" {
				return errors.New("MPC client certificate does not identify a configured peer")
			}
			return nil
		},
	}
}

func Peer(state tls.ConnectionState, allowed map[string]party.ID) party.ID {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return ""
	}
	names := state.PeerCertificates[0].DNSNames
	if len(names) != 1 {
		return ""
	}
	return allowed[names[0]]
}
