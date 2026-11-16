package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type failingKeyCopyCommit struct{ shareStore }

func (failingKeyCopyCommit) Save(context.Context, keystore.Key, []byte) error {
	return errors.New("simulated key copy commit failure")
}

func TestKeyCopy(t *testing.T) {
	for _, algorithm := range []string{"ecdsa", "frost"} {
		t.Run(algorithm, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			nodes := make(map[string]*node)
			transport := localPeerTransport{}
			for _, id := range []string{"1", "2", "3"} {
				peers := map[party.ID]string{"1": "1", "2": "2", "3": "3"}
				delete(peers, party.ID(id))
				n := newNode(config.Config{PartyID: party.ID(id), Peers: peers, DataDir: t.TempDir()})
				db, err := keystore.OpenNodeSQLite(n.config.DataDir, id)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				n.keys, n.client.Transport = db, transport
				nodes[id], transport[id] = n, n.peerHandler()
			}
			api := "/" + algorithm + "/keys"
			curve, copyCurve, variant := "secp256k1", "secp256k1", ""
			if algorithm == "frost" {
				curve, copyCurve, variant = "ed25519", "ED-25519", "Ed25519"
			}
			call := func(id, path, sid string, players []string, body string) *httptest.ResponseRecorder {
				if sid != "" {
					path += "?mpc_routing_id=" + mpcRoutingID(sid)
				}
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
				if sid != "" {
					req.Header.Set("MPC-SessionID", sid)
					req.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
					for _, player := range players {
						req.Header.Add("MPC-Players", player)
					}
				}
				w := httptest.NewRecorder()
				nodes[id].restHandler().ServeHTTP(w, req)
				return w
			}
			all := func(players []string, sid string, request func(string) (string, string), want int) []*httptest.ResponseRecorder {
				t.Helper()
				results := make(chan *httptest.ResponseRecorder, len(players))
				for _, id := range players {
					go func() {
						path, body := request(id)
						results <- call(id, path, sid, players, body)
					}()
				}
				var responses []*httptest.ResponseRecorder
				for range players {
					responses = append(responses, <-results)
				}
				for _, got := range responses {
					if want != 0 && got.Code != want {
						t.Fatalf("%s returned %d (%s), want %d", sid, got.Code, got.Body.String(), want)
					}
				}
				return responses
			}
			sourcePlayers, target := []string{"1", "3"}, []string{"1", "2", "3"}
			all(sourcePlayers, "source", func(string) (string, string) {
				return api, fmt.Sprintf(`{"keyID":"source-key","curve":%q,"threshold":1}`, curve)
			}, 200)
			publicKey := func(id, key, path string) []byte {
				t.Helper()
				got := call(id, api+"/"+key+"/publickey", "", nil, path)
				var response struct{ PublicKey []byte }
				if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &response) != nil || len(response.PublicKey) == 0 {
					t.Fatalf("public key lookup returned %d", got.Code)
				}
				return response.PublicKey
			}
			const root, child = `{"chainPath":null}`, `{"chainPath":[0,1]}`
			rootKey, childKey := publicKey("1", "source-key", root), publicKey("1", "source-key", child)
			old, err := nodes["1"].keys.Load(ctx, algorithm, "source-key")
			if err != nil {
				t.Fatal(err)
			}
			copyTo := func(source, dest string, threshold int, missing ...string) func(string) (string, string) {
				return func(id string) (string, string) {
					body := map[string]any{"threshold": threshold, "keyID": dest, "curve": ""}
					segment := source
					if algorithm == "frost" {
						body["schnorr_variant"] = ""
					}
					for _, absent := range missing {
						if id == absent {
							segment, body["curve"] = "_", copyCurve
							if algorithm == "frost" {
								body["schnorr_variant"] = variant
							}
						}
					}
					data, _ := json.Marshal(body)
					return api + "/" + segment + "/keycopy", string(data)
				}
			}
			all(target, "too_few", copyTo("source-key", "rejected-key", 2, "2", "3"), 400)
			copyRequest := copyTo("source-key", "copy-key", 2, "2")
			if algorithm == "frost" {
				interrupted := copyTo("source-key", "interrupted-copy-key", 2, "2")
				failed := nodes["2"]
				failed.keys = failingKeyCopyCommit{failed.keys}
				failures, successes := 0, 0
				for _, response := range all(target, "interrupted", interrupted, 0) {
					switch response.Code {
					case 200:
						successes++
					case 500:
						failures++
					}
				}
				if failures != 1 || successes != 2 {
					t.Fatalf("partial copy gave %d successes and %d failures", successes, failures)
				}
				if got := call("2", api+"/interrupted-copy-key/publickey", "", nil, root); got.Code != 404 {
					t.Fatalf("uncommitted copy is visible: %d", got.Code)
				}
				reopened := newNode(failed.config)
				db, err := keystore.OpenNodeSQLite(failed.config.DataDir, "2")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				reopened.keys, reopened.client.Transport = db, transport
				nodes["2"], transport["2"] = reopened, reopened.peerHandler()
				path, body := interrupted("2")
				if got := call("2", path, "interrupted", target, body); got.Code != 409 {
					t.Fatalf("restarting an interrupted session returned %d", got.Code)
				}
			}
			for _, got := range all(target, "copy", copyRequest, 200) {
				var response generateKeyResponse
				if json.Unmarshal(got.Body.Bytes(), &response) != nil || response.KeyID != "copy-key" {
					t.Fatal("unexpected copy key ID")
				}
			}
			all(target, "copy", copyRequest, 200)
			path, body := copyTo("source-key", "other-key", 2, "2")("1")
			if got := call("1", path, "copy", target, body); got.Code != 409 {
				t.Fatalf("changed copy request returned %d", got.Code)
			}
			path, body = copyTo("different-source", "copy-key", 2, "2")("1")
			if got := call("1", path, "copy", target, body); got.Code != 409 {
				t.Fatalf("changed copy source returned %d", got.Code)
			}
			original, err := nodes["1"].keys.Load(ctx, algorithm, "source-key")
			if err != nil || !bytes.Equal(old, original) {
				t.Fatal("source share changed")
			}
			for _, id := range target {
				if !bytes.Equal(publicKey(id, "copy-key", root), rootKey) ||
					!bytes.Equal(publicKey(id, "copy-key", child), childKey) {
					t.Fatal("copied public key differs")
				}
			}
			newShare, err := nodes["1"].keys.Load(ctx, algorithm, "copy-key")
			if err != nil || bytes.Equal(newShare, old) {
				t.Fatal("copied key did not get fresh shares")
			}
			message := []byte("sign with the copied child key")
			digest := sha256.Sum256(message)
			signBody := map[string]any{"chainPath": []uint32{0, 1}, "message": message}
			if algorithm == "ecdsa" {
				delete(signBody, "message")
				signBody["messageHash"] = digest[:]
			}
			data, _ := json.Marshal(signBody)
			verifySign := func(players []string, keyID, session string) {
				t.Helper()
				for _, got := range all(players, session, func(string) (string, string) {
					return api + "/" + keyID + "/sign", string(data)
				}, 200) {
					var response struct{ Signature []byte }
					if json.Unmarshal(got.Body.Bytes(), &response) != nil {
						t.Fatal("invalid signature response")
					}
					if algorithm == "ecdsa" {
						key, err := secp256k1.ParsePubKey(childKey)
						if err != nil {
							t.Fatal(err)
						}
						sig, err := secpECDSA.ParseDERSignature(response.Signature)
						if err != nil || !sig.Verify(digest[:], key) {
							t.Fatal("invalid signature from copied ECDSA key")
						}
					} else if !ed25519.Verify(childKey, message, response.Signature) {
						t.Fatal("invalid signature from copied FROST key")
					}
				}
			}
			verifySign(target, "copy-key", "copied_sign")
			all(target, "lower_threshold", copyTo("copy-key", "lowered-key", 1), 200)
			finalPlayers := []string{"2", "3"}
			responses := all(finalPlayers, "smaller_group", copyTo("lowered-key", "", 1), 200)
			var final generateKeyResponse
			if !bytes.Equal(responses[0].Body.Bytes(), responses[1].Body.Bytes()) ||
				json.Unmarshal(responses[0].Body.Bytes(), &final) != nil || final.KeyID == "" {
				t.Fatal("target nodes did not agree on a generated ID")
			}
			all(finalPlayers, "final_presig", func(string) (string, string) {
				return api + "/" + final.KeyID + "/1/presiggen", ""
			}, 200)
			verifySign(finalPlayers, final.KeyID, "final_sign")
			all(finalPlayers, "final_reshare", func(string) (string, string) {
				return api + "/" + final.KeyID + "/reshare", ""
			}, 204)

			deleted := httptest.NewRecorder()
			nodes["1"].restHandler().ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/key/copy-key", nil))
			if deleted.Code != http.StatusNoContent {
				t.Fatalf("delete 3-of-3 copy returned %d", deleted.Code)
			}
			if got := call("1", api+"/copy-key/sign", "deleted_sign", target, string(data)); got.Code != http.StatusNotFound {
				t.Fatalf("sign on node with deleted share returned %d, want 404", got.Code)
			}
			all(finalPlayers, "insufficient_sign", func(string) (string, string) {
				return api + "/copy-key/sign", string(data)
			}, http.StatusBadRequest)
			keygen := fmt.Sprintf(`{"keyID":"copy-key","curve":%q,"threshold":2}`, curve)
			if got := call("1", api, "regenerate_deleted", target, keygen); got.Code != http.StatusConflict {
				t.Fatalf("reuse of deleted key ID returned %d, want 409", got.Code)
			}
		})
	}
}
