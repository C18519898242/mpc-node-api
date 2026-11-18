package node

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestRESTApplicationIsolation(t *testing.T) {
	rest := make([]http.Handler, 2)
	peers := localPeerTransport{}
	token := func(app string, player int) string {
		sum := sha256.Sum256([]byte(fmt.Sprintf("test fixture %s on node %d", app, player)))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	for i := range rest {
		cfg := config.Config{
			PartyID: party.ID(fmt.Sprint(i + 1)), DataDir: t.TempDir(),
			Peers:    map[party.ID]string{party.ID(fmt.Sprint(2 - i)): fmt.Sprintf("node%d", 2-i)},
			RESTAuth: &config.RESTAuthConfig{},
		}
		for _, app := range []string{"wallet-a", "wallet-b", "default"} {
			sum := sha256.Sum256([]byte(token(app, i+1)))
			cfg.RESTAuth.APIKeys = append(cfg.RESTAuth.APIKeys, config.APIKey{
				ApplicationID: app, SHA256: base64.StdEncoding.EncodeToString(sum[:]),
			})
		}
		rotated := sha256.Sum256([]byte(token("wallet-a-rotated", i+1)))
		cfg.RESTAuth.APIKeys = append(cfg.RESTAuth.APIKeys, config.APIKey{
			ApplicationID: "wallet-a", SHA256: base64.StdEncoding.EncodeToString(rotated[:]),
		})
		n := newNode(cfg)
		db, err := keystore.OpenNodeSQLite(cfg.DataDir, string(cfg.PartyID))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		legacy := keystore.Key{Algorithm: "ecdsa", KeyID: "legacy", SessionID: "old", Threshold: 1}
		if state, err := db.Reserve(t.Context(), keystore.DefaultApplication, legacy); err != nil || state != keystore.Reserved {
			t.Fatalf("could not seed the existing database: %v, %v", state, err)
		}
		if err := db.Save(t.Context(), keystore.DefaultApplication, legacy, []byte("legacy fixture")); err != nil {
			t.Fatal(err)
		}
		n.client.Transport = peers
		n.keys = db
		if err := n.configureRESTAuth(); err != nil {
			t.Fatal(err)
		}
		rest[i], peers[fmt.Sprintf("node%d", i+1)] = n.restHandler(), n.peerHandler()
	}

	call := func(player int, method, path, credential, sid, body string) *httptest.ResponseRecorder {
		if sid != "" {
			path += "?mpc_routing_id=" + mpcRoutingID(sid)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(t.Context())
		if credential != "" {
			r.Header.Set("Authorization", "APIKEY "+credential)
		}
		if sid != "" {
			r.Header.Set("MPC-SessionID", sid)
			r.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
			r.Header.Add("MPC-Players", "1")
			r.Header.Add("MPC-Players", "2")
		}
		w := httptest.NewRecorder()
		rest[player-1].ServeHTTP(w, r)
		return w
	}
	for _, key := range []string{"", token("wallet-a", 2)} {
		if w := call(1, "DELETE", "/key/legacy", key, "", ""); w.Code != 401 {
			t.Fatalf("missing or wrong node credential returned %d", w.Code)
		}
	}
	if w := call(1, "POST", "/key/legacy/count/presigs", token("default", 1), "", "{}"); w.Code != 200 {
		t.Fatalf("default application cannot access existing records: %d", w.Code)
	}
	postToPlayers := func(app, path, sid, body string) []*httptest.ResponseRecorder {
		results := make(chan *httptest.ResponseRecorder, len(rest))
		for i := 1; i <= len(rest); i++ {
			go func() {
				results <- call(i, http.MethodPost, path, token(app, i), sid, body)
			}()
		}
		responses := make([]*httptest.ResponseRecorder, 0, len(rest))
		for range rest {
			responses = append(responses, <-results)
		}
		return responses
	}
	create := func(t *testing.T, app, algorithm, curve string) {
		t.Helper()
		body := fmt.Sprintf(`{"keyID":"same-key","threshold":1,"curve":%q}`, curve)
		for _, w := range postToPlayers(app, "/"+algorithm+"/keys", "same-session", body) {
			if w.Code != http.StatusOK {
				t.Fatalf("%s keygen: %d (%s)", app, w.Code, w.Body.String())
			}
		}
	}
	create(t, "wallet-a", "frost", "ed25519")
	for _, op := range []struct{ method, path, sid, body string }{
		{"POST", "/frost/keys/same-key/publickey", "", "{}"},
		{"POST", "/frost/keys/same-key/sign", "sign", `{"message":"aGVsbG8="}`},
		{"POST", "/frost/keys/same-key/signwithpresig", "", `{"message":"aGVsbG8="}`},
		{"POST", "/frost/keys/same-key/1/presiggen", "presig", ""},
		{"POST", "/frost/keys/same-key/reshare", "reshare", ""},
		{"POST", "/frost/keys/same-key/keycopy", "copy", `{"keyID":"foreign-copy","threshold":1}`},
		{"POST", "/key/same-key/count/presigs", "", "{}"},
		{"DELETE", "/key/same-key/presigs", "", ""},
		{"DELETE", "/key/same-key", "", ""},
	} {
		if w := call(1, op.method, op.path, token("wallet-b", 1), op.sid, op.body); w.Code != 404 {
			t.Errorf("foreign %s %s: got %d, want 404", op.method, op.path, w.Code)
		}
	}
	create(t, "wallet-b", "frost", "ed25519")
	publicKey := func(app string) string {
		w := call(1, "POST", "/frost/keys/same-key/publickey", token(app, 1), "", "{}")
		if w.Code != 200 {
			t.Fatalf("%s public key: %d", app, w.Code)
		}
		return w.Body.String()
	}
	before := publicKey("wallet-a")
	if w := call(1, "POST", "/frost/keys/same-key/publickey", token("wallet-a-rotated", 1), "", "{}"); w.Code != 200 || w.Body.String() != before {
		t.Fatalf("second credential for wallet-a did not return the same public key")
	}
	if before == publicKey("wallet-b") {
		t.Fatal("applications shared a key")
	}
	message := []byte("presignature application isolation")
	hash := sha256.Sum256(message)
	for _, tc := range []struct {
		algorithm    string
		messageField string
		message      []byte
	}{
		{"frost", "message", message},
		{"ecdsa", "messageHash", hash[:]},
	} {
		t.Run(tc.algorithm+"_presign_isolation", func(t *testing.T) {
			if tc.algorithm == "ecdsa" {
				for _, app := range []string{"wallet-a", "wallet-b"} {
					create(t, app, tc.algorithm, "secp256k1")
				}
			}
			path := "/" + tc.algorithm + "/keys/same-key"
			var id string
			for _, w := range postToPlayers("wallet-a", path+"/1/presiggen", "presign-isolation", "") {
				var reply struct{ IDs []string }
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &reply) != nil ||
					len(reply.IDs) != 1 || reply.IDs[0] == "" || (id != "" && id != reply.IDs[0]) {
					t.Fatalf("wallet-a presiggen returned %d: %s", w.Code, w.Body.String())
				}
				id = reply.IDs[0]
			}
			// Both apps have a key with this ID. Only A owns the presignature.
			explicit := fmt.Sprintf(`{"presignatureId":%q,%q:%q}`, id, tc.messageField, base64.StdEncoding.EncodeToString(tc.message))
			automatic := fmt.Sprintf(`{%q:%q}`, tc.messageField, base64.StdEncoding.EncodeToString(tc.message))
			for _, body := range []string{explicit, automatic} {
				for _, w := range postToPlayers("wallet-b", path+"/signwithpresig", "", body) {
					if w.Code != http.StatusNotFound {
						t.Fatalf("wallet-b consumed wallet-a presignature: HTTP %d", w.Code)
					}
				}
			}
			for _, w := range postToPlayers("wallet-a", path+"/signwithpresig", "", explicit) {
				var reply struct {
					PresignatureID string `json:"presignatureId"`
					SShare         []byte `json:"sShare"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &reply) != nil ||
					reply.PresignatureID != id || len(reply.SShare) == 0 {
					t.Fatalf("wallet-a could not consume its own presignature: HTTP %d", w.Code)
				}
			}
		})
	}
	if w := call(1, "DELETE", "/key/same-key", token("wallet-b", 1), "", ""); w.Code != 204 {
		t.Fatalf("wallet-b delete: %d", w.Code)
	}
	if after := publicKey("wallet-a"); after != before {
		t.Fatal("wallet-b deletion changed wallet-a's key")
	}
}
