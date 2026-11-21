package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestKeyTransferRoundTrip(t *testing.T) {
	wrapping, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"frost", "ecdsa"} {
		t.Run(algorithm, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			peers := localPeerTransport{}
			nodes := make([]*node, 2)
			cfgs := make([]config.Config, 2)
			open := func(i int) {
				t.Helper()
				n := newNode(cfgs[i])
				db, err := keystore.OpenNodeSQLite(cfgs[i].DataDir, string(cfgs[i].PartyID))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				mk, err := db.LoadOrCreateMasterKey(ctx, "roundtrip test fixture")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { clear(mk) })
				if err := db.EnableShareEncryption(ctx, keystore.NewShareCipher(mk, string(cfgs[i].PartyID))); err != nil {
					t.Fatal(err)
				}
				n.keys, n.wrappingKey, n.client.Transport = db, wrapping, peers
				if err := n.configureRESTAuth(); err != nil {
					t.Fatal(err)
				}
				nodes[i], peers[fmt.Sprint(i+1)] = n, n.peerHandler()
			}
			for i := range cfgs {
				cfgs[i] = config.Config{
					PartyID: party.ID(fmt.Sprint(i + 1)), DataDir: t.TempDir(),
					Peers:    map[party.ID]string{party.ID(fmt.Sprint(2 - i)): fmt.Sprint(2 - i)},
					RESTAuth: &config.RESTAuthConfig{}, KeyTransfer: &config.KeyTransferConfig{},
				}
				for _, app := range []string{"a", "b"} {
					digest := sha256.Sum256([]byte("fixture-" + app))
					cfgs[i].RESTAuth.APIKeys = append(cfgs[i].RESTAuth.APIKeys,
						config.APIKey{ApplicationID: app, SHA256: base64.StdEncoding.EncodeToString(digest[:])})
				}
				open(i)
			}
			call := func(i int, app, path, sid string, body any) *httptest.ResponseRecorder {
				encoded, err := json.Marshal(body)
				if err != nil {
					panic(err)
				}
				if sid != "" {
					path += "?mpc_routing_id=" + mpcRoutingID(sid)
				}
				r := httptest.NewRequest("POST", path, bytes.NewReader(encoded)).WithContext(ctx)
				r.Header.Set("Authorization", "APIKEY fixture-"+app)
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
			all := func(path, sid string, bodies []any) []*httptest.ResponseRecorder {
				t.Helper()
				result := make([]chan *httptest.ResponseRecorder, 2)
				for i := range result {
					result[i] = make(chan *httptest.ResponseRecorder, 1)
					go func() { result[i] <- call(i, "a", path, sid, bodies[i]) }()
				}
				replies := []*httptest.ResponseRecorder{<-result[0], <-result[1]}
				for _, reply := range replies {
					if reply.Code != 200 {
						t.Fatalf("%s: HTTP %d (%s)", path, reply.Code, reply.Body.String())
					}
				}
				return replies
			}
			both := func(body any) []any { return []any{body, body} }
			curve := "ed25519"
			if algorithm == "ecdsa" {
				curve = "secp256k1"
			}
			base := "/" + algorithm + "/keys"
			all(base, "source", both(map[string]any{"curve": curve, "keyID": "source", "threshold": 1}))
			getPublic := func(key string, path []uint32) []byte {
				t.Helper()
				w := call(0, "a", base+"/"+key+"/publickey", "", map[string]any{"chainPath": path})
				var reply struct{ PublicKey []byte }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil {
					t.Fatalf("public key returned HTTP %d", w.Code)
				}
				return reply.PublicKey
			}
			original, err := nodes[0].keys.Load(ctx, "a", algorithm, "source")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(original)
			for _, path := range [][]uint32{nil, {0, 1}} {
				name := "root"
				if len(path) != 0 {
					name = "child"
				}
				body := map[string]any{"chainPath": path, "wrappingKey": der}
				if w := call(0, "b", base+"/source/exportkey", "foreign-"+name, body); w.Code != 404 {
					t.Fatalf("another application exported a key: %d", w.Code)
				}
				exported := all(base+"/source/exportkey", "export-"+name, both(body))
				requests := make([]any, 2)
				for i, reply := range exported {
					var wrapped wrappedKeyShare
					if err := json.Unmarshal(reply.Body.Bytes(), &wrapped); err != nil {
						t.Fatal(err)
					}
					plain, err := unwrapKeyShare(wrapping, wrapped)
					if err != nil {
						t.Fatal(err)
					}
					var payload keyTransferPayload
					if err := json.Unmarshal(plain, &payload); err != nil {
						t.Fatal(err)
					}
					clear(plain)
					clear(payload.Share)
					requests[i] = map[string]any{"keyID": name, "threshold": 1, "wrappedKeyShare": wrapped}
					if i == 0 {
						altered := wrapped
						altered.Ciphertext = bytes.Clone(wrapped.Ciphertext)
						altered.Ciphertext[0] ^= 1
						bad := map[string]any{"keyID": "bad", "threshold": 1, "wrappedKeyShare": altered}
						if got := call(0, "a", base+"/importkey", "tampered-"+name, bad); got.Code != 400 {
							t.Fatalf("tampered export accepted: %d", got.Code)
						}
					}
				}
				wrongNode := map[string]any{
					"keyID": "wrong-node", "threshold": 1,
					"wrappedKeyShare": requests[1].(map[string]any)["wrappedKeyShare"],
				}
				if got := call(0, "a", base+"/importkey", "wrong-node-"+name, wrongNode); got.Code != 400 {
					t.Fatalf("another node's share was accepted: %d", got.Code)
				}
				all(base+"/importkey", "import-"+name, requests)
				all(base+"/importkey", "import-"+name, requests)
				for i := range nodes {
					open(i)
				}
				want := getPublic("source", path)
				childPublic := getPublic("source", append(slices.Clone(path), 2))
				if !bytes.Equal(getPublic(name, nil), want) ||
					!bytes.Equal(getPublic(name, []uint32{2}), childPublic) {
					t.Fatalf("%s import changed the root or child chain code", name)
				}
				message := []byte("imported key signing")
				body = map[string]any{"message": message}
				if algorithm == "ecdsa" {
					hash := sha256.Sum256(message)
					body = map[string]any{"messageHash": hash[:]}
				}
				body["chainPath"] = []uint32{2}
				signed := all(base+"/"+name+"/sign", "sign-"+name, both(body))
				var signature struct{ Signature []byte }
				if json.Unmarshal(signed[0].Body.Bytes(), &signature) != nil ||
					!bytes.Equal(signed[0].Body.Bytes(), signed[1].Body.Bytes()) {
					t.Fatal("imported signing replies differ")
				}
				if algorithm == "frost" {
					if !ed25519.Verify(childPublic, message, signature.Signature) {
						t.Fatal("invalid imported Ed25519 signature")
					}
				} else {
					public, err := secp256k1.ParsePubKey(childPublic)
					if err != nil {
						t.Fatal(err)
					}
					sig, err := secpECDSA.ParseDERSignature(signature.Signature)
					hash := sha256.Sum256(message)
					if err != nil || !sig.Verify(hash[:], public) {
						t.Fatal("invalid imported ECDSA signature")
					}
				}
				imported, err := nodes[0].keys.Load(ctx, "a", algorithm, name)
				if err != nil || bytes.Equal(imported, original) {
					t.Fatal("import did not produce a fresh sharing")
				}
				clear(imported)
			}
			after, err := nodes[0].keys.Load(ctx, "a", algorithm, "source")
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("export changed the original sharing")
			}
			clear(after)
		})
	}
}

func TestKeyWrapRejectsWrongKey(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := wrapKeyShare(&first.PublicKey, []byte(strings.Repeat("fixture", 1000)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unwrapKeyShare(second, sealed); err == nil {
		t.Fatal("another RSA key decrypted the export")
	}
	n := newNode(config.Config{KeyTransfer: &config.KeyTransferConfig{}})
	n.wrappingKey = first
	if !n.allowWrappingKey(&first.PublicKey) || n.allowWrappingKey(&second.PublicKey) {
		t.Fatal("export wrapping key policy did not enforce the allowlist")
	}
	allowed, err := x509.MarshalPKIXPublicKey(&second.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	n.config.KeyTransfer.ExportWrappingKeys = [][]byte{allowed}
	if !n.allowWrappingKey(&second.PublicKey) {
		t.Fatal("explicitly allowed wrapping key was rejected")
	}
}
