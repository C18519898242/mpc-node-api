package node

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func TestSigningBroadcastOnlyReachesParticipants(t *testing.T) {
	n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "node2", "3": "node3"}})
	var destinations []string
	accept := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			destinations = append(destinations, name)
			w.WriteHeader(http.StatusNoContent)
		})
	}
	n.client.Transport = localPeerTransport{"node2": accept("2"), "node3": accept("3")}
	err := n.sendMessage(context.Background(), "ecdsa-sign.test", &protocol.Message{From: "1", Broadcast: true},
		party.IDSlice{"1", "3"})
	if err != nil || len(destinations) != 1 || destinations[0] != "3" {
		t.Fatalf("broadcast destinations = %v, error = %v", destinations, err)
	}
}

func TestECDSAPublicKeyRejectsHardenedPath(t *testing.T) {
	n := newNode(config.Config{})
	request := httptest.NewRequest(http.MethodPost, "/ecdsa/keys/test/publickey",
		strings.NewReader(`{"chainPath":[2147483648]}`))
	response := httptest.NewRecorder()
	n.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestECDSASignRejectsShortDigest(t *testing.T) {
	n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "", "3": ""}})
	routingID := mpcRoutingID("test_sign")
	request := httptest.NewRequest(http.MethodPost, "/ecdsa/keys/test/sign?mpc_routing_id="+routingID,
		strings.NewReader(`{"chainPath":null,"messageHash":"AA=="}`))
	request.Header.Set("MPC-SessionID", "test_sign")
	request.Header.Set("MPC-RoutingID", routingID)
	request.Header.Add("MPC-Players", "1")
	request.Header.Add("MPC-Players", "2")
	response := httptest.NewRecorder()
	n.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestGenerateECDSAKeyRejectsDuplicatePlayers(t *testing.T) {
	n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "", "3": ""}})
	request := httptest.NewRequest(http.MethodPost, "/ecdsa/keys?mpc_routing_id=07ce376e2e4cf7f0",
		strings.NewReader(`{"threshold":1,"curve":"secp256k1","keyID":""}`))
	request.Header.Set("MPC-SessionID", "demo_keygen")
	request.Header.Set("MPC-RoutingID", "07ce376e2e4cf7f0")
	for _, player := range []string{"1", "2", "2"} {
		request.Header.Add("MPC-Players", player)
	}
	response := httptest.NewRecorder()
	n.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}
