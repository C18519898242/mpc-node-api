package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	cmpECDSA "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestEncryptedPresignSigningAfterRestart(t *testing.T) {
	for _, algorithm := range []string{"frost", "ecdsa"} {
		t.Run(algorithm, func(t *testing.T) {
			ctx := t.Context()
			peers := localPeerTransport{}
			nodes := make([]*node, 2)
			stores := make([]*keystore.SQLite, 2)
			cfgs := make([]config.Config, 2)
			open := func(i int) {
				t.Helper()
				n := newNode(cfgs[i])
				db, err := keystore.OpenNodeSQLite(cfgs[i].DataDir, string(cfgs[i].PartyID))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				mk, err := db.LoadOrCreateMasterKey(ctx, "encrypted presign integration fixture")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { clear(mk) })
				if err := db.EnableShareEncryption(ctx, keystore.NewShareCipher(mk, string(cfgs[i].PartyID))); err != nil {
					t.Fatal(err)
				}
				n.keys = db
				n.workerContext = ctx
				n.client.Transport = peers
				nodes[i], stores[i], peers[fmt.Sprint(i+1)] = n, db, n.peerHandler()
			}
			for i := range nodes {
				cfgs[i] = config.Config{PartyID: party.ID(fmt.Sprint(i + 1)), DataDir: t.TempDir(), Peers: map[party.ID]string{party.ID(fmt.Sprint(2 - i)): fmt.Sprint(2 - i)}}
				open(i)
			}
			call := func(i int, path, sid string, body []byte) *httptest.ResponseRecorder {
				if sid != "" {
					path += "?mpc_routing_id=" + mpcRoutingID(sid)
				}
				r := httptest.NewRequest("POST", path, bytes.NewReader(body)).WithContext(ctx)
				if sid != "" {
					r.Header.Set("MPC-SessionID", sid)
					r.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
					r.Header.Add("MPC-Players", "1")
					r.Header.Add("MPC-Players", "2")
				}
				w := httptest.NewRecorder()
				nodes[i].restHandler().ServeHTTP(w, r)
				return w
			}
			all := func(path, sid string, body []byte) []*httptest.ResponseRecorder {
				t.Helper()
				result := make(chan *httptest.ResponseRecorder, 2)
				for i := range nodes {
					go func() { result <- call(i, path, sid, body) }()
				}
				replies := []*httptest.ResponseRecorder{<-result, <-result}
				for _, w := range replies {
					if w.Code != 200 {
						t.Fatalf("%s returned HTTP %d", path, w.Code)
					}
				}
				return replies
			}
			curveName := "ed25519"
			if algorithm == "ecdsa" {
				curveName = "secp256k1"
			}
			base := "/" + algorithm + "/keys"
			keyPath := base + "/encrypted-key"
			all(base, "keygen", fmt.Appendf(nil, `{"keyID":"encrypted-key","curve":%q,"threshold":1}`, curveName))
			batch := all(keyPath+"/2/presiggen", "presign", nil)
			var ids struct {
				IDs []string `json:"ids"`
			}
			if json.Unmarshal(batch[0].Body.Bytes(), &ids) != nil || len(ids.IDs) != 2 || !bytes.Equal(batch[0].Body.Bytes(), batch[1].Body.Bytes()) {
				t.Fatal("invalid encrypted presign batch")
			}
			for i := range nodes {
				if err := stores[i].Close(); err != nil {
					t.Fatal(err)
				}
				open(i)
				db, err := sql.Open("sqlite", filepath.Join(cfgs[i].DataDir, "node.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				var count, encrypted int
				err = db.QueryRow("SELECT count(*),sum(share_format) FROM "+algorithm+"_presignatures").Scan(&count, &encrypted)
				db.Close()
				if err != nil || count != 2 || encrypted != 2 {
					t.Fatal("presignatures were not encrypted before restart", err)
				}
			}
			publicReply := call(0, keyPath+"/publickey", "", []byte(`{"chainPath":[0,1]}`))
			var public struct{ PublicKey []byte }
			if publicReply.Code != 200 || json.Unmarshal(publicReply.Body.Bytes(), &public) != nil {
				t.Fatal("could not load derived public key")
			}
			message := []byte("encrypted presignatures after restart")
			request := map[string]any{"presignatureId": ids.IDs[0], "chainPath": []uint32{0, 1}, "message": message}
			if algorithm == "ecdsa" {
				digest := sha256.Sum256(message)
				delete(request, "message")
				request["messageHash"] = digest[:]
			}
			body, _ := json.Marshal(request)
			replies := all(keyPath+"/signwithpresig", "", body)
			verifyEncryptedPresignResult(t, algorithm, replies, public.PublicKey, message)
			for i := range nodes {
				if w := call(i, keyPath+"/signwithpresig", "", body); w.Code != 404 {
					t.Fatalf("reused encrypted presignature returned %d", w.Code)
				}
				if w := call(i, "/key/encrypted-key/count/presigs", "", []byte(`{}`)); w.Code != 200 || w.Body.String() != "1\n" {
					t.Fatal("incorrect remaining encrypted presignature count")
				}
				if replay := call(i, keyPath+"/2/presiggen", "presign", nil); replay.Code != 200 || !bytes.Equal(replay.Body.Bytes(), batch[0].Body.Bytes()) {
					t.Fatal("batch replay changed IDs after restart")
				}
			}
		})
	}
}

func verifyEncryptedPresignResult(t *testing.T, algorithm string, replies []*httptest.ResponseRecorder, public, message []byte) {
	t.Helper()
	var parts []struct {
		PresignatureID                  string
		R, PublicKey, SShare, Challenge []byte
	}
	for _, reply := range replies {
		var part struct {
			PresignatureID                  string
			R, PublicKey, SShare, Challenge []byte
		}
		if json.Unmarshal(reply.Body.Bytes(), &part) != nil || !bytes.Equal(part.PublicKey, public) {
			t.Fatal("invalid decrypted partial signature")
		}
		parts = append(parts, part)
	}
	if parts[0].PresignatureID != parts[1].PresignatureID || !bytes.Equal(parts[0].R, parts[1].R) || !bytes.Equal(parts[0].Challenge, parts[1].Challenge) {
		t.Fatal("decrypted partial signatures disagree")
	}
	if algorithm == "frost" {
		sum := ristretto.NewScalar()
		for _, part := range parts {
			slices.Reverse(part.SShare)
			scalar, err := ristretto.NewScalar().SetCanonicalBytes(part.SShare)
			if err != nil {
				t.Fatal(err)
			}
			sum.Add(sum, scalar)
		}
		if !ed25519.Verify(public, message, append(bytes.Clone(parts[0].R), sum.Bytes()...)) {
			t.Fatal("decrypted FROST presignatures failed combined verification")
		}
		return
	}
	group := curve.Secp256k1{}
	sum := group.NewScalar()
	for _, part := range parts {
		scalar := group.NewScalar()
		if err := scalar.UnmarshalBinary(part.SShare); err != nil {
			t.Fatal(err)
		}
		sum.Add(scalar)
	}
	toPoint := func(data []byte) curve.Point {
		t.Helper()
		point, err := secp256k1.ParsePubKey(data)
		if err != nil {
			t.Fatal(err)
		}
		p := group.NewPoint()
		if err := p.UnmarshalBinary(point.SerializeCompressed()); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hash := sha256.Sum256(message)
	if !(cmpECDSA.Signature{R: toPoint(parts[0].R), S: sum}).Verify(toPoint(public), hash[:]) {
		t.Fatal("decrypted ECDSA presignatures failed combined verification")
	}
}
