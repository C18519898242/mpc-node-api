package node

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func TestMPCPeerTLSBindsNodeIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := peertls.GenerateDevDirectory(dir, []party.ID{"1", "2", "3", "4"}); err != nil {
		t.Fatal(err)
	}
	files := func(i int) *config.MPCTLSConfig {
		folder := filepath.Join(dir, fmt.Sprintf("node-%d", i))
		return &config.MPCTLSConfig{
			CAFile: filepath.Join(dir, "ca.crt"), CertFile: filepath.Join(folder, "node.crt"), KeyFile: filepath.Join(folder, "node.key"),
		}
	}
	identity := func(id party.ID, i int) *peertls.Identity {
		t.Helper()
		f := files(i)
		value, err := peertls.Load(id, f.CAFile, f.CertFile, f.KeyFile)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	node2 := newNode(config.Config{PartyID: "2", Peers: map[party.ID]string{"1": "node1", "3": "node3"}, MPCTLS: files(2)})
	server, err := node2.configurePeerTLS()
	if err != nil {
		t.Fatal(err)
	}
	client := identity("1", 1).Client("2")
	state, serverErr, clientErr := handshakePeerTLS(server, client)
	if serverErr != nil || clientErr != nil {
		t.Fatalf("correct MPC peer was rejected: %v, %v", serverErr, clientErr)
	}

	noCert := client.Clone()
	noCert.Certificates = nil
	if _, err, _ := handshakePeerTLS(server, noCert); err == nil {
		t.Fatal("server accepted a peer with no certificate")
	}
	if _, err, _ := handshakePeerTLS(server, identity("4", 4).Client("2")); err == nil {
		t.Fatal("server accepted a CA-signed certificate from an unconfigured node")
	}
	if _, _, err := handshakePeerTLS(server, identity("1", 1).Client("3")); err == nil {
		t.Fatal("client accepted the wrong server identity")
	}
	badLocal := newNode(config.Config{PartyID: "2", MPCTLS: files(1)})
	if _, err := badLocal.configurePeerTLS(); err == nil {
		t.Fatal("node accepted a certificate issued to a different party")
	}

	inbox := make(chan *protocol.Message, 1)
	node2.sessions[sessionKey{defaultApplication, "frost.demo"}] = &keygenSession{incoming: inbox}
	handler := node2.peerHandler()
	for _, test := range []struct {
		name string
		from party.ID
		tls  *tls.ConnectionState
		want int
	}{
		{"no TLS", "1", nil, http.StatusForbidden},
		{"different sender", "3", &state, http.StatusForbidden},
		{"matching sender", "1", &state, http.StatusNoContent},
	} {
		msg, err := json.Marshal(protocol.Message{From: test.from, To: "2"})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/internal/mpc/frost.demo", bytes.NewReader(msg))
		request.TLS = test.tls
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("%s: got %d, want %d", test.name, response.Code, test.want)
		}
	}
	select {
	case message := <-inbox:
		if message.From != "1" || len(inbox) != 0 {
			t.Fatal("an unexpected sender reached the MPC inbox")
		}
	default:
		t.Fatal("the authenticated message did not reach the MPC inbox")
	}
}

func handshakePeerTLS(serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error, error) {
	incoming, outgoing := net.Pipe()
	defer incoming.Close()
	defer outgoing.Close()
	deadline := time.Now().Add(2 * time.Second)
	_ = incoming.SetDeadline(deadline)
	_ = outgoing.SetDeadline(deadline)
	server := tls.Server(incoming, serverConfig)
	client := tls.Client(outgoing, clientConfig)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	clientErr := client.Handshake()
	serverErr := <-serverResult
	return server.ConnectionState(), serverErr, clientErr
}
