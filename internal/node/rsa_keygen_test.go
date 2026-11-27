package node

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestRSAKeygenRequiresProtectedNodes(t *testing.T) {
	w := httptest.NewRecorder()
	newNode(config.Config{}).restHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/rsa/keys", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("unprotected RSA keygen returned HTTP %d", w.Code)
	}
}

func TestRSAOperationsRequireProtectedNodes(t *testing.T) {
	handler := newNode(config.Config{}).restHandler()
	for _, operation := range []string{"publickey", "sign", "decrypt"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/rsa/keys/test-rsa/"+operation, nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("unprotected RSA %s returned HTTP %d", operation, w.Code)
		}
	}
}

func rsaTestNodes(t *testing.T, auth *config.RESTAuthConfig) (party.IDSlice, [3]*node) {
	t.Helper()
	players := party.IDSlice{"1", "2", "3"}
	certDir := filepath.Join(t.TempDir(), "certs")
	if err := peertls.GenerateDevDirectory(certDir, players); err != nil {
		t.Fatal(err)
	}
	var nodes [3]*node
	var servers [3]*httptest.Server
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(nil)
		t.Cleanup(servers[i].Close)
	}
	for i, id := range players {
		folder := filepath.Join(certDir, "node-"+string(id))
		cfg := config.Config{PartyID: id, Peers: map[party.ID]string{}, RESTAuth: auth, MPCTLS: &config.MPCTLSConfig{
			CAFile: filepath.Join(certDir, "ca.crt"), CertFile: filepath.Join(folder, "node.crt"), KeyFile: filepath.Join(folder, "node.key"),
		}}
		for j, peer := range players {
			if peer != id {
				cfg.Peers[peer] = servers[j].Listener.Addr().String()
			}
		}
		n := newNode(cfg)
		if err := n.configureRESTAuth(); err != nil {
			t.Fatal(err)
		}
		store, err := keystore.OpenNodeSQLite(t.TempDir(), string(id))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		mk, err := store.LoadOrCreateMasterKey(t.Context(), "RSA test fixture")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(mk) })
		n.shareCipher = keystore.NewShareCipher(mk, string(id))
		if err := store.EnableShareEncryption(t.Context(), n.shareCipher); err != nil {
			t.Fatal(err)
		}
		n.keys = store
		servers[i].TLS, err = n.configurePeerTLS()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeEmbeddedClients(n) })
		servers[i].Config.Handler = n.peerHandler()
		servers[i].StartTLS()
		nodes[i] = n
	}
	return players, nodes
}

func TestRSAKeygenDistributesDistinctShares(t *testing.T) {
	players, nodes := rsaTestNodes(t, nil)
	const session, keyID = "rsa-fixture", "fixture-rsa"
	request := func(i, bits int) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"threshold": 1, "bits": bits, "keyID": keyID})
		routingID := mpcRoutingID(session)
		r := httptest.NewRequest(http.MethodPost, "/rsa/keys?mpc_routing_id="+routingID, bytes.NewReader(body))
		r.Header.Set("MPC-SessionID", session)
		r.Header.Set("MPC-RoutingID", routingID)
		for _, player := range players {
			r.Header.Add("MPC-Players", string(player))
		}
		w := httptest.NewRecorder()
		nodes[i].restHandler().ServeHTTP(w, r)
		return w
	}
	if w := request(0, 1024); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid RSA size returned HTTP %d", w.Code)
	}
	replies := make(chan *httptest.ResponseRecorder, len(players))
	for i := range nodes {
		go func() { replies <- request(i, 2048) }()
	}
	for range nodes {
		w := <-replies
		var response generateKeyResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.KeyID != keyID {
			t.Fatalf("RSA keygen HTTP %d: %s", w.Code, w.Body.String())
		}
	}
	var public []byte
	seen := map[[32]byte]bool{}
	call := func(n *node, path string, body []byte, appID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/rsa/keys/"+keyID+"/"+path, bytes.NewReader(body))
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, withApplication(r, appID))
		return w
	}
	for i, n := range nodes {
		raw, err := n.keys.Load(t.Context(), defaultApplication, "rsa", keyID)
		if err != nil {
			t.Fatal(err)
		}
		var stored struct {
			Players   party.IDSlice `json:"players"`
			PublicKey []byte        `json:"publicKey"`
			Share     []byte        `json:"share"`
		}
		var share thresholdrsa.KeyShare
		if json.Unmarshal(raw, &stored) != nil || len(stored.PublicKey) == 0 || share.UnmarshalBinary(stored.Share) != nil {
			t.Fatalf("invalid or duplicate RSA share on node %d", i+1)
		}
		legacy, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeStoredRSAKeyShare(legacy, players[i])
		clear(legacy)
		if err != nil || decoded.usage != rsaUsageSign {
			t.Fatalf("legacy RSA key share was not recognized as a signing share on node %d", i+1)
		}
		clear(raw)
		fingerprint := sha256.Sum256(stored.Share)
		clear(stored.Share)
		if seen[fingerprint] || share.Index != uint(i+1) || share.Players != 3 || share.Threshold != 2 {
			t.Fatalf("unexpected RSA share metadata on node %d", i+1)
		}
		seen[fingerprint] = true
		if i == 0 {
			public = stored.PublicKey
		} else if !bytes.Equal(stored.PublicKey, public) {
			t.Fatalf("node %d has a different public key", i+1)
		}
		// A restarted node validates the original size against the stored key.
		n.sessions = make(map[sessionKey]*keygenSession)
		if w := request(i, 2048); w.Code != http.StatusOK {
			t.Fatalf("retry returned HTTP %d", w.Code)
		}
		if w := request(i, 3072); w.Code != http.StatusConflict {
			t.Fatalf("retry with a different RSA size returned HTTP %d", w.Code)
		}
		w := call(n, "publickey", []byte(`{}`), defaultApplication)
		var response struct {
			PublicKey       []byte
			Players         int
			RequiredSigners int
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil ||
			!bytes.Equal(response.PublicKey, public) || response.Players != 3 || response.RequiredSigners != 2 {
			t.Fatalf("invalid RSA public key response on node %d (HTTP %d)", i+1, w.Code)
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 2048 {
		t.Fatal("unexpected RSA public key")
	}
	message := []byte("verify two stored RSA key shares")
	padded, err := thresholdrsa.PadHash(thresholdrsa.PKCS1v15Padder{}, crypto.SHA256, key, message)
	if err != nil {
		t.Fatal(err)
	}
	var partials [2]thresholdrsa.SignShare
	digest := sha256.Sum256(message)
	body, err := json.Marshal(map[string][]byte{"messageHash": digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	if w := call(nodes[0], "sign", []byte(`{"messageHash":"AA=="}`), defaultApplication); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid RSA digest returned HTTP %d", w.Code)
	}
	if w := call(nodes[0], "sign", body, "other-app"); w.Code != http.StatusNotFound {
		t.Fatalf("another application signing returned HTTP %d", w.Code)
	}
	if w := call(nodes[0], "publickey", []byte(`{}`), "other-app"); w.Code != http.StatusNotFound {
		t.Fatalf("another application public key returned HTTP %d", w.Code)
	}
	for i, index := range []int{0, 2} {
		w := call(nodes[index], "sign", body, defaultApplication)
		var response struct{ PartialSignature []byte }
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" ||
			json.Unmarshal(w.Body.Bytes(), &response) != nil || partials[i].UnmarshalBinary(response.PartialSignature) != nil {
			t.Fatalf("invalid RSA partial signature on node %d (HTTP %d)", index+1, w.Code)
		}
	}
	signature, err := thresholdrsa.CombineSignShares(key, 3, 2, partials[:], padded)
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("stored RSA shares did not produce a valid signature")
	}
	n := nodes[0]
	n.config.RESTAuth = rsaTestRESTAuth()
	if err := n.configureRESTAuth(); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	decryptRequest, _ := json.Marshal(map[string][]byte{"ciphertext": ciphertext})
	r := httptest.NewRequest(http.MethodPost, "https://node.example/rsa/keys/"+keyID+"/decrypt", bytes.NewReader(decryptRequest))
	r.Header.Set("Authorization", "APIKEY "+rsaDecryptToken)
	w := httptest.NewRecorder()
	n.restHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("decryption with signing key returned HTTP %d", w.Code)
	}
}
