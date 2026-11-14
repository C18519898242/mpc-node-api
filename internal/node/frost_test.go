package node

import (
	"context"
	"crypto/ed25519"
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
			{keyID, `{"chainPath":[2147483648]}`, http.StatusBadRequest},
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

	presignSession := "frost_presign"
	presignRouting := mpcRoutingID(presignSession)
	presignPath := "/frost/keys/" + keyID + "/2/presiggen?mpc_routing_id=" + presignRouting
	presign := func(n *node, path string) result {
		r := httptest.NewRequest(http.MethodPost, path, nil).WithContext(ctx)
		r.Header.Set("MPC-SessionID", presignSession)
		r.Header.Set("MPC-RoutingID", presignRouting)
		r.Header.Add("MPC-Players", "3")
		r.Header.Add("MPC-Players", "1")
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return result{w.Code, w.Body.String()}
	}
	for _, n := range []*node{nodes[0], nodes[2]} {
		go func() { results <- presign(n, presignPath) }()
	}
	batch, otherBatch := <-results, <-results
	var batchResponse struct{ IDs []string }
	if batch.status != http.StatusOK || batch != otherBatch ||
		json.Unmarshal([]byte(batch.body), &batchResponse) != nil ||
		len(batchResponse.IDs) != 2 || batchResponse.IDs[0] == batchResponse.IDs[1] {
		t.Fatalf("unexpected FROST presign replies: %v, %v", batch, otherBatch)
	}
	reopened := newNode(nodes[0].config)
	reopened.keys = nodes[0].keys
	if replay := presign(reopened, presignPath); replay != batch {
		t.Fatalf("unexpected presign replay: %v", replay)
	}
	if conflict := presign(reopened, strings.Replace(presignPath, "/2/", "/1/", 1)); conflict.status != http.StatusConflict {
		t.Fatalf("changed presign count status = %d, want 409", conflict.status)
	}

	const message = "FROST signing test"
	sid := "frost_sign"
	rid := mpcRoutingID(sid)
	signPath := "/frost/keys/" + keyID + "/sign?mpc_routing_id=" + rid
	sign := func(n *node, body string, players ...string) result {
		r := httptest.NewRequest(http.MethodPost, signPath, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("MPC-SessionID", sid)
		r.Header.Set("MPC-RoutingID", rid)
		for _, player := range players {
			r.Header.Add("MPC-Players", player)
		}
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return result{w.Code, w.Body.String()}
	}
	const body = `{"chainPath":null,"message":"RlJPU1Qgc2lnbmluZyB0ZXN0"}`
	for _, n := range []*node{nodes[0], nodes[2]} {
		go func() { results <- sign(n, body, "3", "1") }()
	}
	first := <-results
	second := <-results
	if first.status != http.StatusOK || first != second {
		t.Fatalf("signing replies differ or failed: %v, %v", first, second)
	}
	var signature struct{ Signature []byte }
	if err := json.Unmarshal([]byte(first.body), &signature); err != nil ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature.Signature) {
		t.Fatalf("invalid Ed25519 signature: %v", err)
	}
	publicRequest := httptest.NewRequest(http.MethodPost, "/frost/keys/"+keyID+"/publickey",
		strings.NewReader(`{"chainPath":[0,1]}`))
	publicResponse := httptest.NewRecorder()
	nodes[1].restHandler().ServeHTTP(publicResponse, publicRequest)
	var child struct{ PublicKey []byte }
	if publicResponse.Code != http.StatusOK || json.Unmarshal(publicResponse.Body.Bytes(), &child) != nil ||
		len(child.PublicKey) != ed25519.PublicKeySize || string(child.PublicKey) == publicKey {
		t.Fatalf("unexpected derived public key response: %d", publicResponse.Code)
	}
	if conflict := sign(nodes[0], `{"chainPath":[0,1],"message":"RlJPU1Qgc2lnbmluZyB0ZXN0"}`, "1", "3"); conflict.status != http.StatusConflict {
		t.Fatalf("changed path status = %d, want 409", conflict.status)
	}
	sid = "frost_child_sign"
	rid = mpcRoutingID(sid)
	signPath = "/frost/keys/" + keyID + "/sign?mpc_routing_id=" + rid
	const childBody = `{"chainPath":[0,1],"message":"RlJPU1Qgc2lnbmluZyB0ZXN0"}`
	for _, n := range []*node{nodes[0], nodes[2]} {
		go func() { results <- sign(n, childBody, "1", "3") }()
	}
	first, second = <-results, <-results
	if first.status != http.StatusOK || first != second || json.Unmarshal([]byte(first.body), &signature) != nil ||
		!ed25519.Verify(ed25519.PublicKey(child.PublicKey), []byte(message), signature.Signature) ||
		ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature.Signature) {
		t.Fatalf("derived signing replies failed: %v, %v", first, second)
	}
	if replay := sign(nodes[0], childBody, "1", "3"); replay != first {
		t.Fatalf("unexpected signing replay: %v", replay)
	}
	if conflict := sign(nodes[0], `{"message":"YQ=="}`, "1", "3"); conflict.status != http.StatusConflict {
		t.Fatalf("changed message status = %d, want 409", conflict.status)
	}
}

type localPeerTransport map[string]http.Handler

func (t localPeerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t[r.URL.Host].ServeHTTP(w, r)
	return w.Result(), nil
}
