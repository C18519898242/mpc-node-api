package node

import (
	"crypto/tls"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func (n *node) configurePeerTLS() (*tls.Config, error) {
	cfg := n.config.MPCTLS
	if cfg == nil {
		return nil, nil
	}
	identity, err := peertls.Load(n.config.PartyID, cfg.CAFile, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	n.peerClients = make(map[party.ID]*http.Client, len(n.config.Peers))
	n.peerNames = make(map[string]party.ID, len(n.config.Peers))
	for _, peer := range n.configuredPlayers() {
		if peer == n.config.PartyID {
			continue
		}
		n.peerNames[peertls.Name(peer)] = peer
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.TLSClientConfig = identity.Client(peer)
		n.peerClients[peer] = &http.Client{
			Transport: transport, Timeout: n.client.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return identity.Server(n.peerNames), nil
}

func (n *node) verifiedPeer(r *http.Request) party.ID {
	if r.TLS == nil {
		return ""
	}
	return peertls.Peer(*r.TLS, n.peerNames)
}
