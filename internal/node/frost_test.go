package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
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
	presignPath := "/frost/keys/" + keyID + "/3/presiggen?mpc_routing_id=" + presignRouting
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
		len(batchResponse.IDs) != 3 || batchResponse.IDs[0] == batchResponse.IDs[1] {
		t.Fatalf("unexpected FROST presign replies: %v, %v", batch, otherBatch)
	}
	reopened := newNode(nodes[0].config)
	reopened.keys = nodes[0].keys
	if replay := presign(reopened, presignPath); replay != batch {
		t.Fatalf("unexpected presign replay: %v", replay)
	}
	if conflict := presign(reopened, strings.Replace(presignPath, "/3/", "/1/", 1)); conflict.status != http.StatusConflict {
		t.Fatalf("changed presign count status = %d, want 409", conflict.status)
	}
	countPresigs := func(n *node, keyID, body string) result {
		r := httptest.NewRequest(http.MethodPost, "/key/"+keyID+"/count/presigs", strings.NewReader(body))
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return result{w.Code, strings.TrimSpace(w.Body.String())}
	}
	for _, tc := range []struct {
		node  *node
		keyID string
		body  string
		code  int
		want  string
	}{
		{nodes[0], keyID, `{}`, http.StatusOK, "3"},
		{nodes[1], keyID, `{}`, http.StatusOK, "0"},
		{nodes[2], keyID, `{}`, http.StatusOK, "3"},
		{nodes[0], "unknown-key", `{}`, http.StatusNotFound, ""},
		{nodes[0], "bad!", `{}`, http.StatusBadRequest, ""},
		{nodes[0], keyID, ``, http.StatusBadRequest, ""},
		{nodes[0], keyID, `null`, http.StatusBadRequest, ""},
		{nodes[0], keyID, `{"extra":1}`, http.StatusBadRequest, ""},
	} {
		got := countPresigs(tc.node, tc.keyID, tc.body)
		if got.status != tc.code || (tc.code == http.StatusOK && got.body != tc.want) {
			t.Fatalf("countPresigs(%q, %q) = %v, want %d %q", tc.keyID, tc.body, got, tc.code, tc.want)
		}
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
	consume := func(n *node, id string, path []uint32, message []byte) result {
		body, err := json.Marshal(map[string]any{"presignatureId": id, "chainPath": path, "message": message})
		if err != nil {
			panic(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/frost/keys/"+keyID+"/signwithpresig", bytes.NewReader(body))
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return result{w.Code, w.Body.String()}
	}
	for _, tc := range []struct {
		name    string
		id      string
		path    []uint32
		message []byte
		code    int
	}{
		{"invalid id", "invalid", nil, []byte(message), http.StatusBadRequest},
		{"hardened path", batchResponse.IDs[0], []uint32{1 << 31}, []byte(message), http.StatusBadRequest},
		{"missing message", batchResponse.IDs[0], nil, nil, http.StatusBadRequest},
		{"unknown id", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), nil, []byte(message), http.StatusNotFound},
	} {
		if got := consume(nodes[0], tc.id, tc.path, tc.message); got.status != tc.code {
			t.Fatalf("%s: status = %d, want %d", tc.name, got.status, tc.code)
		}
	}
	if got := consume(nodes[1], batchResponse.IDs[0], nil, []byte(message)); got.status != http.StatusNotFound {
		t.Fatalf("nonparticipant: status = %d, want 404", got.status)
	}
	// Signing from precomputed material must work without reaching any peers.
	nodes[0].client.Transport = localPeerTransport(nil)
	nodes[2].client.Transport = localPeerTransport(nil)
	for i, tc := range []struct {
		path      []uint32
		publicKey []byte
		message   []byte
	}{{nil, []byte(publicKey), []byte(message)}, {[]uint32{0, 1}, child.PublicKey, []byte{}}} {
		id := batchResponse.IDs[i]
		var left result
		if i == 0 {
			left = consume(nodes[0], "", tc.path, tc.message)
		} else {
			for range 2 {
				go func() { results <- consume(nodes[0], id, tc.path, tc.message) }()
			}
			var retry result
			left, retry = <-results, <-results
			if retry.status == http.StatusOK {
				left, retry = retry, left
			}
			if retry.status != http.StatusNotFound {
				t.Fatalf("concurrent reuse: status = %d, want 404", retry.status)
			}
		}
		right := consume(nodes[2], id, tc.path, tc.message)
		sum := ristretto.NewScalar()
		var nonce, challenge []byte
		for j, reply := range []result{left, right} {
			var part struct {
				PresignatureID, Curve, Sharing  string
				Variant                         string `json:"schnorr_variant"`
				PlayerIndex, Threshold          int
				R, PublicKey, SShare, Challenge []byte
			}
			if reply.status != http.StatusOK || json.Unmarshal([]byte(reply.body), &part) != nil ||
				part.PresignatureID != id || part.Curve != "ed25519" || part.Variant != "Ed25519" ||
				part.Sharing != "additive" || part.Threshold != 1 || part.PlayerIndex != j*2 ||
				!bytes.Equal(part.PublicKey, tc.publicKey) || len(part.R) != 32 || len(part.Challenge) != 32 {
				t.Fatalf("unexpected FROST partial signature response from player %d: %d", j, reply.status)
			}
			if j == 0 {
				nonce, challenge = part.R, part.Challenge
			} else if !bytes.Equal(part.R, nonce) || !bytes.Equal(part.Challenge, challenge) {
				t.Fatal("FROST partial signatures disagree on the transcript")
			}
			slices.Reverse(part.SShare)
			s, err := ristretto.NewScalar().SetCanonicalBytes(part.SShare)
			if err != nil {
				t.Fatal(err)
			}
			sum.Add(sum, s)
		}
		if !ed25519.Verify(tc.publicKey, tc.message, append(nonce, sum.Bytes()...)) {
			t.Fatal("combined FROST signature failed Ed25519 verification")
		}
		for _, n := range []*node{reopened, nodes[2]} {
			if replay := consume(n, id, tc.path, tc.message); replay.status != http.StatusNotFound {
				t.Fatalf("consumed presignature status = %d, want 404", replay.status)
			}
			if got := countPresigs(n, keyID, `{}`); got.status != http.StatusOK || got.body != string(rune('2'-i)) {
				t.Fatalf("remaining presignature count = %v, want %d", got, 2-i)
			}
		}
	}
	deletePresigs := func(n *node, keyID, body string) int {
		r := httptest.NewRequest(http.MethodDelete, "/key/"+keyID+"/presigs", strings.NewReader(body))
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return w.Code
	}
	for _, tc := range []struct {
		node  *node
		keyID string
		body  string
		code  int
	}{
		{nodes[0], "unknown-key", "", http.StatusNotFound},
		{nodes[0], "bad!", "", http.StatusBadRequest},
		{nodes[0], keyID, "{}", http.StatusBadRequest},
		{nodes[1], keyID, "", http.StatusNoContent},
		{reopened, keyID, "", http.StatusNoContent},
		{nodes[2], keyID, "", http.StatusNoContent},
	} {
		if code := deletePresigs(tc.node, tc.keyID, tc.body); code != tc.code {
			t.Fatalf("deletePresigs(%q, %q) = %d, want %d", tc.keyID, tc.body, code, tc.code)
		}
	}
	if got := countPresigs(reopened, keyID, `{}`); got.status != http.StatusOK || got.body != "0" {
		t.Fatalf("count after delete = %v, want 0", got)
	}
	nodes[0].client.Transport = localPeerTransport(transport)
	nodes[2].client.Transport = localPeerTransport(transport)
	if replay := presign(reopened, presignPath); replay != batch {
		t.Fatalf("unexpected batch replay after consumption: %v", replay)
	}
	if got := consume(reopened, "", nil, []byte(message)); got.status != http.StatusNotFound {
		t.Fatalf("batch replay restored a consumed presignature: %d", got.status)
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
