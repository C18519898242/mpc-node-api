package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestGenerateFROSTKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes := make([]*node, 3)
	transport := make(map[string]http.Handler)
	for i, id := range []party.ID{"1", "2", "3"} {
		peers := map[party.ID]string{"1": "node1", "2": "node2", "3": "node3"}
		addr := peers[id]
		delete(peers, id)
		n := newNode(config.Config{PartyID: id, Peers: peers, DataDir: t.TempDir()})
		keys, err := keystore.OpenNodeSQLite(n.config.DataDir, string(id))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = keys.Close() })
		n.keys = keys
		nodes[i] = n
		transport[addr] = n.peerHandler()
	}
	type result struct {
		status int
		body   string
	}
	results := make(chan result, len(nodes))
	for _, n := range nodes {
		n.client.Transport = localPeerTransport(transport)
		go func() {
			r := httptest.NewRequest(http.MethodPost, "/frost/keys?mpc_routing_id=07ce376e2e4cf7f0",
				strings.NewReader(`{"threshold":1,"curve":"ed25519","keyID":""}`)).WithContext(ctx)
			r.Header.Set("MPC-SessionID", "demo_keygen")
			r.Header.Set("MPC-RoutingID", "07ce376e2e4cf7f0")
			for _, id := range []string{"3", "1", "2"} {
				r.Header.Add("MPC-Players", id)
			}
			w := httptest.NewRecorder()
			n.restHandler().ServeHTTP(w, r)
			results <- result{w.Code, w.Body.String()}
		}()
	}
	var keyID string
	for range nodes {
		got := <-results
		var body struct{ KeyID string }
		if got.status != http.StatusOK || json.Unmarshal([]byte(got.body), &body) != nil || body.KeyID == "" {
			t.Fatalf("unexpected response %d: %s", got.status, got.body)
		}
		if keyID != "" && keyID != body.KeyID {
			t.Fatal("nodes returned different key IDs")
		}
		keyID = body.KeyID
	}
	var publicKey string
	for _, n := range nodes {
		keys, err := keystore.OpenNodeSQLite(n.config.DataDir, string(n.config.PartyID))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = keys.Close() })
		data, err := keys.Load(ctx, "frost", keyID)
		if err != nil {
			t.Fatal(err)
		}
		var share keygen.Output
		if err := json.Unmarshal(data, &share); err != nil {
			t.Fatalf("node %s: decode FROST share: %v", n.config.PartyID, err)
		}
		public := share.Public
		if share.SecretKey == nil || public == nil || public.Shares[share.SecretKey.ID] == nil ||
			public.Shares[share.SecretKey.ID].Equal(&share.SecretKey.Public) != 1 {
			t.Fatalf("node %s has an inconsistent local share", n.config.PartyID)
		}
		got := string(public.GroupKey.ToEd25519())
		if public.Threshold != 1 || len(got) != 32 || (publicKey != "" && publicKey != got) {
			t.Fatalf("node %s has inconsistent public data", n.config.PartyID)
		}
		publicKey = got

		for _, tc := range []struct {
			keyID string
			body  string
			code  int
		}{
			{keyID, `{"chainPath":null}`, http.StatusOK},
			{keyID, `{"chainPath":[]}`, http.StatusOK},
			{keyID, `{"chainPath":[0]}`, http.StatusBadRequest},
			{"unknown-key", `{"chainPath":null}`, http.StatusNotFound},
		} {
			request := httptest.NewRequest(http.MethodPost, "/frost/keys/"+tc.keyID+"/publickey",
				strings.NewReader(tc.body))
			response := httptest.NewRecorder()
			n.restHandler().ServeHTTP(response, request)
			if response.Code != tc.code {
				t.Fatalf("node %s key %s body %s: status = %d, want %d",
					n.config.PartyID, tc.keyID, tc.body, response.Code, tc.code)
			}
			if tc.code == http.StatusOK {
				var body struct {
					Curve     string `json:"curve"`
					PublicKey []byte `json:"publicKey"`
				}
				if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Curve != "ed25519" || string(body.PublicKey) != got {
					t.Fatalf("node %s returned a different public key", n.config.PartyID)
				}
			}
		}
	}
}

type localPeerTransport map[string]http.Handler

func (t localPeerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t[r.URL.Host].ServeHTTP(w, r)
	return w.Result(), nil
}
