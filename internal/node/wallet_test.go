package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestCreateWalletRequiresBackupConfiguration(t *testing.T) {
	n := newNode(config.Config{})
	r := httptest.NewRequest(http.MethodPost, "/wallets", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	n.restHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wallet endpoint without backup configuration: %d, want 403", w.Code)
	}
}

func TestMnemonicWalletRoundTrip(t *testing.T) {
	players := party.IDSlice{"1", "2", "3"}
	certs := filepath.Join(t.TempDir(), "certs")
	if err := peertls.GenerateDevDirectory(certs, players); err != nil {
		t.Fatal(err)
	}
	var servers [3]*httptest.Server
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(nil)
		t.Cleanup(servers[i].Close)
	}
	var nodes [3]*node
	var privateKeys [3]*rsa.PrivateKey
	var configs [3]config.Config
	credential := sha256.Sum256([]byte("fixture"))
	for i, player := range players {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[i] = private
		der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		folder := filepath.Join(certs, "node-"+string(player))
		cfg := config.Config{
			PartyID: player, DataDir: t.TempDir(), Peers: map[party.ID]string{},
			MPCTLS:       &config.MPCTLSConfig{CAFile: filepath.Join(certs, "ca.crt"), CertFile: filepath.Join(folder, "node.crt"), KeyFile: filepath.Join(folder, "node.key")},
			RESTAuth:     &config.RESTAuthConfig{APIKeys: []config.APIKey{{ApplicationID: "wallet-app", SHA256: base64.StdEncoding.EncodeToString(credential[:])}}},
			WalletBackup: &config.WalletBackupConfig{PublicKey: der}, EncryptorMasterPasswordEnv: "WALLET_TEST_MASTER_PASSWORD",
		}
		for j, peer := range players {
			if peer != player {
				cfg.Peers[peer] = servers[j].Listener.Addr().String()
			}
		}
		configs[i] = cfg
		n := newNode(cfg)
		nodes[i] = n
		if err := n.configureWalletBackup(); err != nil {
			t.Fatal(err)
		}
		if err := n.configureRESTAuth(); err != nil {
			t.Fatal(err)
		}
		store, err := keystore.OpenNodeSQLite(cfg.DataDir, string(player))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		mk, err := store.LoadOrCreateMasterKey(t.Context(), "test master password")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(mk) })
		if err := store.EnableShareEncryption(t.Context(), keystore.NewShareCipher(mk, string(player))); err != nil {
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
	}
	call := func(n *node, path, session string, body []byte, roster party.IDSlice) *httptest.ResponseRecorder {
		routing := mpcRoutingID(session)
		r := httptest.NewRequest(http.MethodPost, path+"?mpc_routing_id="+routing, bytes.NewReader(body)).WithContext(t.Context())
		r.Header.Set("MPC-SessionID", session)
		r.Header.Set("MPC-RoutingID", routing)
		r.Header.Set("Authorization", "APIKEY fixture")
		for _, player := range roster {
			r.Header.Add("MPC-Players", string(player))
		}
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return w
	}
	all := func(path, session string, body []byte) []byte {
		t.Helper()
		results := make(chan *httptest.ResponseRecorder, 3)
		for _, n := range nodes {
			go func() { results <- call(n, path, session, body, players) }()
		}
		var response []byte
		for range nodes {
			result := <-results
			if result.Code != http.StatusOK {
				t.Errorf("%s: HTTP %d: %s", path, result.Code, result.Body.String())
			}
			if response == nil {
				response = result.Body.Bytes()
			} else if !bytes.Equal(response, result.Body.Bytes()) {
				t.Errorf("%s: nodes returned different results", path)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		return response
	}
	if got := call(nodes[0], "/wallets", "create", []byte(`{"mnemonic":"unexpected"}`), players); got.Code != http.StatusBadRequest {
		t.Fatalf("wallet accepted a caller-supplied mnemonic: %d", got.Code)
	}
	var receipt walletReceipt
	if err := json.Unmarshal(all("/wallets", "create", []byte(`{}`)), &receipt); err != nil || receipt != walletIDs("wallet-app", "create") {
		t.Fatalf("invalid wallet receipt: %v, %v", receipt, err)
	}
	var words [3]string
	var manifest walletManifest
	var manifestJSON []byte
	for i, cfg := range configs {
		db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "node.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		var raw, wrapped, ciphertext []byte
		var keyID string
		var version, encrypted int
		if err := db.QueryRow(`SELECT format_version, backup_key_id, wrapped_key, ciphertext, manifest FROM wallet_backups
			WHERE application_id = 'wallet-app' AND wallet_id = ?`, receipt.WalletID).Scan(&version, &keyID, &wrapped, &ciphertext, &raw); err != nil || version != 1 {
			t.Fatalf("missing encrypted wallet record: %v", err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM key_shares WHERE application_id = 'wallet-app' AND share_format = 1 AND share IS NOT NULL`).Scan(&encrypted); err != nil || encrypted != 2 {
			t.Fatalf("expected two encrypted shares: %d, %v", encrypted, err)
		}
		if i == 0 {
			manifestJSON = raw
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
		} else if !bytes.Equal(manifestJSON, raw) {
			t.Fatal("nodes stored different recovery manifests")
		}
		if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeys[(i+1)%3], wrapped, nil); err == nil {
			t.Fatal("the wrong node's RSA key could decrypt the backup")
		}
		dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeys[i], wrapped, nil)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(dek)
		clear(dek)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aead.Open(nil, nil, ciphertext, mnemonicBackupAAD("another-app", string(cfg.PartyID), receipt.WalletID, keyID)); err == nil {
			t.Fatal("another application's backup context authenticated")
		}
		plain, err := aead.Open(nil, nil, ciphertext, mnemonicBackupAAD("wallet-app", string(cfg.PartyID), receipt.WalletID, keyID))
		if err != nil {
			t.Fatal(err)
		}
		words[i] = string(plain)
		clear(plain)
	}
	cmpKey, err := recovery.RecoverCMPPrivateKey(words, manifest.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(cmpKey.Scalar[:])
	frostKey, err := recovery.RecoverEd25519PrivateKey(words, manifest.FROST)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frostKey.Scalar[:])
	restarted := newNode(configs[0])
	restarted.keys = nodes[0].keys
	if err := restarted.configureWalletBackup(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.configureRESTAuth(); err != nil {
		t.Fatal(err)
	}
	replay := call(restarted, "/wallets", "create", []byte(`{}`), players)
	var replayed walletReceipt
	if replay.Code != http.StatusOK || json.Unmarshal(replay.Body.Bytes(), &replayed) != nil || replayed != receipt {
		t.Fatalf("restart lost the wallet receipt: %d", replay.Code)
	}
	message := []byte("mnemonic wallet signing fixture")
	digest := sha256.Sum256(message)
	var signed struct{ Signature []byte }
	body, err := json.Marshal(ecdsaSignRequest{MessageHash: digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(all("/ecdsa/keys/"+receipt.ECDSAKeyID+"/sign", "sign-cmp", body), &signed); err != nil {
		t.Fatal(err)
	}
	signature, err := secpECDSA.ParseDERSignature(signed.Signature)
	if err != nil || !signature.Verify(digest[:], secp256k1.PrivKeyFromBytes(cmpKey.Scalar[:]).PubKey()) {
		t.Fatal("CMP signature did not verify against the recovered key")
	}
	path := []uint32{0, 1}
	body, err = json.Marshal(map[string]any{"chainPath": path, "message": message})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(all("/frost/keys/"+receipt.FROSTKeyID+"/sign", "sign-frost", body), &signed); err != nil {
		t.Fatal(err)
	}
	child, _, err := eddsa.DeriveSigningScalar(frostKey.Scalar, frostKey.ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(child[:])
	var scalar edwards25519.Scalar
	if _, err := scalar.SetCanonicalBytes(child[:]); err != nil {
		t.Fatal(err)
	}
	point := new(edwards25519.Point).ScalarBaseMult(&scalar)
	if !ed25519.Verify(point.Bytes(), message, signed.Signature) {
		t.Fatal("FROST child signature did not verify against offline recovery")
	}
}
