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

func TestWalletBackupRequiresRESTAuth(t *testing.T) {
	n := newNode(config.Config{})
	r := httptest.NewRequest(http.MethodGet, "/wallets/wallet/backup", nil)
	w := httptest.NewRecorder()
	n.restHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wallet backup without REST authentication: %d, want 403", w.Code)
	}
}

func TestMnemonicWalletRoundTrip(t *testing.T) {
	t.Run("configured-public-keys", func(t *testing.T) { testMnemonicWalletRoundTrip(t, false) })
	t.Run("uploaded-public-keys", func(t *testing.T) { testMnemonicWalletRoundTrip(t, true) })
}

func testMnemonicWalletRoundTrip(t *testing.T, uploaded bool) {
	t.Helper()
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
	var publicKeys [3][]byte
	var configs [3]config.Config
	credential := sha256.Sum256([]byte("fixture"))
	otherCredential := sha256.Sum256([]byte("other-fixture"))
	for i := range privateKeys {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[i] = private
		der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[i] = der
	}
	for i, player := range players {
		configuredKey := publicKeys[i]
		if uploaded {
			configuredKey = publicKeys[(i+1)%3]
			if i == 2 {
				configuredKey = nil
			}
		}
		folder := filepath.Join(certs, "node-"+string(player))
		cfg := config.Config{
			PartyID: player, DataDir: t.TempDir(), Peers: map[party.ID]string{},
			MPCTLS: &config.MPCTLSConfig{CAFile: filepath.Join(certs, "ca.crt"), CertFile: filepath.Join(folder, "node.crt"), KeyFile: filepath.Join(folder, "node.key")},
			RESTAuth: &config.RESTAuthConfig{APIKeys: []config.APIKey{
				{ApplicationID: "wallet-app", SHA256: base64.StdEncoding.EncodeToString(credential[:])},
				{ApplicationID: "other-app", SHA256: base64.StdEncoding.EncodeToString(otherCredential[:])},
			}},
			WalletBackup: &config.WalletBackupConfig{PublicKey: configuredKey, AllowRequestPublicKeys: uploaded}, EncryptorMasterPasswordEnv: "WALLET_TEST_MASTER_PASSWORD",
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
	walletBody := []byte(`{}`)
	uploadedBody := func(keys map[party.ID][]byte) []byte {
		t.Helper()
		body, err := json.Marshal(map[string]any{"backupPublicKeys": keys})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	submitted := uploadedBody(map[party.ID][]byte{"1": publicKeys[0], "2": publicKeys[1], "3": publicKeys[2]})
	if uploaded {
		walletBody = submitted
		invalidKey := privateKeys[0].PublicKey
		invalidKey.E++
		invalidDER, err := x509.MarshalPKIXPublicKey(&invalidKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, invalid := range [][]byte{
			[]byte(`{"backupPublicKeys":null}`),
			uploadedBody(map[party.ID][]byte{"1": publicKeys[0], "2": publicKeys[1]}),
			uploadedBody(map[party.ID][]byte{"1": publicKeys[0], "2": publicKeys[0], "3": publicKeys[2]}),
			uploadedBody(map[party.ID][]byte{"1": publicKeys[0], "2": publicKeys[1], "9": publicKeys[2]}),
			uploadedBody(map[party.ID][]byte{"1": invalidDER, "2": publicKeys[1], "3": publicKeys[2]}),
		} {
			if got := call(nodes[0], "/wallets", "create", invalid, players); got.Code != http.StatusBadRequest {
				t.Fatalf("invalid backup keys: HTTP %d, want 400", got.Code)
			}
		}
	} else if got := call(nodes[0], "/wallets", "disabled-upload", submitted, players); got.Code != http.StatusForbidden {
		t.Fatalf("public keys supplied with uploads disabled: HTTP %d, want 403", got.Code)
	}
	var receipt walletReceipt
	if err := json.Unmarshal(all("/wallets", "create", walletBody), &receipt); err != nil || receipt != walletIDs("wallet-app", "create") {
		t.Fatalf("invalid wallet receipt: %v, %v", receipt, err)
	}
	swapped := uploadedBody(map[party.ID][]byte{"1": publicKeys[0], "2": publicKeys[2], "3": publicKeys[1]})
	checkChangedKeys := func(n *node) {
		t.Helper()
		for _, body := range [][]byte{swapped, []byte(`{}`)} {
			if got := call(n, "/wallets", "create", body, players); got.Code != http.StatusConflict {
				t.Fatalf("wallet replay with changed backup keys: HTTP %d, want 409", got.Code)
			}
		}
	}
	if uploaded {
		checkChangedKeys(nodes[0])
	}
	getBackup := func(n *node, walletID, credential string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/wallets/"+walletID+"/backup", nil).WithContext(t.Context())
		if credential != "" {
			r.Header.Set("Authorization", "APIKEY "+credential)
		}
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return w
	}
	if uploaded {
		const mismatchSession = "different-backup-keys"
		results := make(chan int, len(nodes))
		for i, n := range nodes {
			body := walletBody
			if i == 2 {
				body = swapped
			}
			go func() { results <- call(n, "/wallets", mismatchSession, body, players).Code }()
		}
		for range nodes {
			if code := <-results; code < 400 {
				t.Errorf("wallet creation accepted different backup keys across nodes: HTTP %d", code)
			}
		}
		for _, n := range nodes {
			if result := getBackup(n, walletIDs("wallet-app", mismatchSession).WalletID, "fixture"); result.Code != http.StatusNotFound {
				t.Errorf("a backup was committed despite different keys across nodes: HTTP %d", result.Code)
			}
		}
	}
	pending := walletIDs("wallet-app", "pending").WalletID
	if ok, err := nodes[0].keys.ReserveWallet(t.Context(), "wallet-app", "pending", pending, nil); err != nil || !ok {
		t.Fatalf("reserve unfinished backup: %t, %v", ok, err)
	}
	for _, tc := range []struct {
		walletID, key string
		status        int
	}{
		{receipt.WalletID, "", http.StatusUnauthorized},
		{receipt.WalletID, "other-fixture", http.StatusNotFound},
		{"missing", "fixture", http.StatusNotFound},
		{pending, "fixture", http.StatusNotFound},
	} {
		if got := getBackup(nodes[0], tc.walletID, tc.key); got.Code != tc.status {
			t.Fatalf("wallet backup status = %d, want %d", got.Code, tc.status)
		}
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
		w := getBackup(nodes[i], receipt.WalletID, "fixture")
		var backup struct {
			FormatVersion                    int
			ApplicationID, PartyID, WalletID string
			BackupKeyID                      string
			WrappedKey, Ciphertext, AAD      []byte
			Manifest                         json.RawMessage
		}
		decoder := json.NewDecoder(w.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&backup); w.Code != http.StatusOK || err != nil || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("read wallet backup: HTTP %d, %v", w.Code, err)
		}
		partyID := string(cfg.PartyID)
		if backup.FormatVersion != 1 || backup.ApplicationID != "wallet-app" || backup.PartyID != partyID ||
			backup.WalletID != receipt.WalletID || !bytes.Equal(backup.AAD, mnemonicBackupAAD("wallet-app", partyID, receipt.WalletID, backup.BackupKeyID)) {
			t.Fatal("wallet backup metadata does not match the original wallet")
		}
		raw, wrapped, ciphertext := backup.Manifest, backup.WrappedKey, backup.Ciphertext
		var encrypted int
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
		if _, err := aead.Open(nil, nil, ciphertext, mnemonicBackupAAD("another-app", partyID, receipt.WalletID, backup.BackupKeyID)); err == nil {
			t.Fatal("another application's backup context authenticated")
		}
		plain, err := aead.Open(nil, nil, ciphertext, backup.AAD)
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
	replay := call(restarted, "/wallets", "create", walletBody, players)
	var replayed walletReceipt
	if replay.Code != http.StatusOK || json.Unmarshal(replay.Body.Bytes(), &replayed) != nil || replayed != receipt {
		t.Fatalf("restart lost the wallet receipt: %d", replay.Code)
	}
	if uploaded {
		checkChangedKeys(restarted)
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
