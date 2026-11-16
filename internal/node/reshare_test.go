package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type failingReshareCommit struct{ shareStore }

func (failingReshareCommit) CommitReshare(context.Context, keystore.Reshare) error {
	return errors.New("simulated reshare commit failure")
}

func TestReshare(t *testing.T) {
	for _, tc := range []struct {
		algorithm string
		curve     string
		threshold int
	}{{"ecdsa", "secp256k1", 1}, {"frost", "ed25519", 1}, {"frost", "ed25519", 2}} {
		t.Run(fmt.Sprintf("%s-%d", tc.algorithm, tc.threshold), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			nodes := make([]*node, 3)
			transport := localPeerTransport{}
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
				n.client.Transport = transport
				nodes[i], transport[addr] = n, n.peerHandler()
			}
			api := "/" + tc.algorithm + "/keys"
			key := api + "/refresh-key"
			type reply struct {
				code int
				body []byte
			}
			call := func(n *node, path, sid string, body []byte, players ...string) reply {
				if sid != "" {
					path += "?mpc_routing_id=" + mpcRoutingID(sid)
				}
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx)
				if sid != "" {
					req.Header.Set("MPC-SessionID", sid)
					req.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
					for _, player := range players {
						req.Header.Add("MPC-Players", player)
					}
				}
				w := httptest.NewRecorder()
				n.restHandler().ServeHTTP(w, req)
				return reply{w.Code, w.Body.Bytes()}
			}
			all := func(path, sid string, body []byte, want int) []reply {
				t.Helper()
				results := make(chan reply, 3)
				for _, n := range nodes {
					go func() { results <- call(n, path, sid, body, "3", "1", "2") }()
				}
				var replies []reply
				for range nodes {
					replies = append(replies, <-results)
				}
				for _, got := range replies {
					if want != 0 && (got.code != want || (want == http.StatusNoContent && len(got.body) != 0)) {
						t.Fatalf("%s returned %d, want %d", path, got.code, want)
					}
				}
				return replies
			}
			all(api, "keygen", fmt.Appendf(nil, `{"keyID":"refresh-key","curve":%q,"threshold":%d}`, tc.curve, tc.threshold), 200)
			pub := func(n *node, path string) []byte {
				t.Helper()
				got := call(n, key+"/publickey", "", []byte(path))
				var response struct{ PublicKey []byte }
				if got.code != 200 || json.Unmarshal(got.body, &response) != nil || len(response.PublicKey) == 0 {
					t.Fatal("public key lookup failed")
				}
				return response.PublicKey
			}
			const root = `{"chainPath":null}`
			const child = `{"chainPath":[0,1]}`
			rootKey, childKey := pub(nodes[0], root), pub(nodes[0], child)
			batch := all(key+"/1/presiggen", "presig", nil, 200)
			var ids struct{ IDs []string }
			if json.Unmarshal(batch[0].body, &ids) != nil || len(ids.IDs) != 1 {
				t.Fatal("missing presignature ID")
			}
			old := make([][]byte, len(nodes))
			for i, n := range nodes {
				var err error
				old[i], err = n.keys.Load(ctx, tc.algorithm, "refresh-key")
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := call(nodes[0], key+"/reshare", "bad", nil, "1", "2"); got.code != 400 {
				t.Fatalf("incomplete player list returned %d", got.code)
			}
			if got := call(nodes[0], key+"/reshare", "bad", []byte("{}"), "1", "2", "3"); got.code != 400 {
				t.Fatalf("nonempty body returned %d", got.code)
			}
			if got := call(nodes[0], api+"/unknown/reshare", "unknown", nil, "1", "2", "3"); got.code != 404 {
				t.Fatalf("unknown key returned %d", got.code)
			}
			if tc.algorithm == "frost" && tc.threshold == 2 {
				nodes[0].keys = failingReshareCommit{nodes[0].keys}
				replies := all(key+"/reshare", "refresh", nil, 0)
				successes, failures := 0, 0
				for _, got := range replies {
					switch got.code {
					case http.StatusNoContent:
						successes++
					case http.StatusInternalServerError:
						failures++
					}
				}
				if successes != 2 || failures != 1 {
					t.Fatalf("partial commit returned %d successes and %d failures", successes, failures)
				}
				got := call(nodes[0], key+"/signwithpresig", "", fmt.Appendf(nil, `{"message":"YQ==","presignatureId":%q}`, ids.IDs[0]))
				if got.code != http.StatusConflict {
					t.Fatalf("presign consumption while refresh is pending returned %d", got.code)
				}
				reopened := newNode(nodes[0].config)
				keys, err := keystore.OpenNodeSQLite(reopened.config.DataDir, string(reopened.config.PartyID))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = keys.Close() })
				reopened.keys, reopened.client.Transport = keys, transport
				nodes[0], transport["node1"] = reopened, reopened.peerHandler()
				got = call(reopened, key+"/reshare", "refresh", nil, "1", "2", "3")
				if got.code != http.StatusNoContent {
					t.Fatalf("resume after reopening SQLite returned %d", got.code)
				}
			}
			all(key+"/reshare", "refresh", nil, 204)
			all(key+"/reshare", "refresh", nil, 204)
			for i, n := range nodes {
				refreshed, err := n.keys.Load(ctx, tc.algorithm, "refresh-key")
				if err != nil || bytes.Equal(old[i], refreshed) ||
					!bytes.Equal(rootKey, pub(n, root)) || !bytes.Equal(childKey, pub(n, child)) {
					t.Fatal("unexpected share or public key after refresh")
				}
				consume := n.keys.ConsumeFROSTPresign
				if tc.algorithm == "ecdsa" {
					consume = n.keys.ConsumeECDSAPresign
				}
				if _, err := consume(ctx, "refresh-key", ids.IDs[0]); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("obsolete presignature is available: %v", err)
				}
			}
			all(key+"/1/presiggen", "presig", nil, 409)
			all(key+"/1/presiggen", "fresh-presig", nil, 200)
			message := []byte("after refresh")
			digest := sha256.Sum256(message)
			field, input := "message", message
			if tc.algorithm == "ecdsa" {
				field, input = "messageHash", digest[:]
			}
			body, _ := json.Marshal(map[string]any{"chainPath": []uint32{0, 1}, field: input})
			for _, reply := range all(key+"/sign", "fresh-sign", body, 200) {
				var response struct{ Signature []byte }
				if err := json.Unmarshal(reply.body, &response); err != nil {
					t.Fatal(err)
				}
				if tc.algorithm == "ecdsa" {
					pk, err := secp256k1.ParsePubKey(childKey)
					if err != nil {
						t.Fatal(err)
					}
					signature, err := secpECDSA.ParseDERSignature(response.Signature)
					if err != nil || !signature.Verify(digest[:], pk) {
						t.Fatal("ECDSA signing failed after refresh")
					}
				} else if !ed25519.Verify(childKey, message, response.Signature) {
					t.Fatal("FROST signing failed after refresh")
				}
			}
		})
	}
}
