package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

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
