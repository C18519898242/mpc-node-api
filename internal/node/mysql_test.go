package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/go-sql-driver/mysql"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestOpenNodeStoreMySQLConfig(t *testing.T) {
	if _, err := openNodeStore(config.Config{
		PartyID:  "1",
		Database: &config.DatabaseConfig{Driver: "mysql", DSNEnv: "MISSING_MYSQL_DSN_TEST"},
	}); err == nil {
		t.Fatal("expected error for empty DSNEnv")
	}
	if _, err := openNodeStore(config.Config{
		PartyID:  "1",
		Database: &config.DatabaseConfig{Driver: "mysql", Addr: "127.0.0.1:3306", User: "root", PasswordEnv: "MISSING_MYSQL_PASS_TEST", DBName: "mpc_node_1"},
	}); err == nil {
		t.Fatal("expected error for empty PasswordEnv")
	}
	if err := Serve(config.Config{
		PartyID:  "1",
		RESTAddr: "127.0.0.1:0",
		MPCAddr:  "127.0.0.1:0",
		Peers:    map[party.ID]string{"2": "127.0.0.1:9082"},
		Database: &config.DatabaseConfig{Driver: "mysql", DSNEnv: "MISSING_MYSQL_DSN_TEST"},
	}); err == nil {
		t.Fatal("Serve accepted mysql config without encryptorMasterPasswordEnv")
	}
}

func TestMySQLThreeNodeClusterECDSAWorkflow(t *testing.T) {
	baseDSN := os.Getenv("MPC_TEST_MYSQL_DSN")
	if baseDSN == "" {
		t.Skip("set MPC_TEST_MYSQL_DSN to run 3-node MySQL integration test")
	}
	parsed, err := mysql.ParseDSN(baseDSN)
	if err != nil {
		t.Fatalf("parse MPC_TEST_MYSQL_DSN: %v", err)
	}
	adminCfg := parsed.Clone()
	adminCfg.DBName = ""
	if adminCfg.TLSConfig == "" {
		adminCfg.TLSConfig = "preferred"
	}
	admin, err := sql.Open("mysql", adminCfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "mpc_node_test_" + hex.EncodeToString(suffix[:]) + "_"
	t.Setenv("MPC_TEST_NODE_MYSQL_PASS", parsed.Passwd)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	peers := localPeerTransport{}
	nodes := make([]*node, 3)
	rest := make([]*httptest.Server, 3)
	var dbNames [3]string

	openNode := func(i int) {
		t.Helper()
		id := party.ID(string(rune('1' + i)))
		cfg := config.Config{
			PartyID: id,
			Peers:   map[party.ID]string{},
			Database: &config.DatabaseConfig{
				Driver:      "mysql",
				Addr:        parsed.Addr,
				User:        parsed.User,
				PasswordEnv: "MPC_TEST_NODE_MYSQL_PASS",
				DBName:      dbNames[i],
				TLSMode:     "preferred",
			},
			EncryptorMasterPasswordEnv: "MPC_TEST_NODE_MK_" + string(id),
		}
		for j := range 3 {
			if j != i {
				other := party.ID(string(rune('1' + j)))
				cfg.Peers[other] = string(other)
			}
		}
		store, err := openNodeStore(cfg)
		if err != nil {
			t.Fatalf("openNodeStore(%d): %v", i+1, err)
		}
		t.Cleanup(func() { _ = store.Close() })
		mk, err := loadMasterKey(store, cfg.EncryptorMasterPasswordEnv)
		if err != nil {
			t.Fatalf("loadMasterKey(%d): %v", i+1, err)
		}
		t.Cleanup(func() { clear(mk) })
		n := newNode(cfg)
		n.keys = store
		n.shareCipher = keystore.NewShareCipher(mk, string(id))
		if err := store.EnableShareEncryption(ctx, n.shareCipher); err != nil {
			t.Fatal(err)
		}
		n.client.Transport = peers
		nodes[i] = n
		peers[string(id)] = n.peerHandler()
		rest[i] = httptest.NewServer(n.restHandler())
		t.Cleanup(rest[i].Close)
	}

	for i := range 3 {
		id := string(rune('1' + i))
		dbNames[i] = prefix + id
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+dbNames[i]+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"); err != nil {
			t.Fatalf("create db %s: %v", dbNames[i], err)
		}
		dbName := dbNames[i]
		t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS `" + dbName + "`") })
		t.Setenv("MPC_TEST_NODE_MK_"+id, "mysql-node-master-"+id)
		openNode(i)
	}

	type callResult struct {
		idx  int
		code int
		body []byte
		err  error
	}
	call := func(i int, path, session string, selected []string, body any) callResult {
		raw, err := json.Marshal(body)
		if err != nil {
			return callResult{idx: i, err: err}
		}
		if session != "" {
			path += "?mpc_routing_id=" + mpcRoutingID(session)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rest[i].URL+path, bytes.NewReader(raw))
		if err != nil {
			return callResult{idx: i, err: err}
		}
		if session != "" {
			req.Header.Set("MPC-SessionID", session)
			req.Header.Set("MPC-RoutingID", mpcRoutingID(session))
			for _, p := range selected {
				req.Header.Add("MPC-Players", p)
			}
		}
		res, err := rest[i].Client().Do(req)
		if err != nil {
			return callResult{idx: i, err: err}
		}
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		return callResult{idx: i, code: res.StatusCode, body: out, err: err}
	}

	allPlayers := []string{"1", "2", "3"}
	keygenBody := map[string]any{"threshold": 1, "curve": "secp256k1", "keyID": "mysql-ecdsa"}
	ch := make(chan callResult, 3)
	for i := range 3 {
		go func() {
			ch <- call(i, "/ecdsa/keys", "mysql-kg-1", allPlayers, keygenBody)
		}()
	}
	for range 3 {
		res := <-ch
		if res.err != nil || res.code != http.StatusOK {
			t.Fatalf("node %d keygen failed: HTTP %d, err=%v, body=%s", res.idx+1, res.code, res.err, res.body)
		}
	}

	// Reopen all 3 nodes to prove key shares & master key persist in MySQL across restarts.
	for i := range 3 {
		openNode(i)
	}

	pubRes := call(0, "/ecdsa/keys/mysql-ecdsa/publickey", "", nil, map[string]any{"chainPath": nil})
	if pubRes.err != nil || pubRes.code != http.StatusOK {
		t.Fatalf("publickey failed: HTTP %d, err=%v, body=%s", pubRes.code, pubRes.err, pubRes.body)
	}
	var pubResp struct {
		PublicKey []byte `json:"publicKey"`
	}
	if err := json.Unmarshal(pubRes.body, &pubResp); err != nil {
		t.Fatal(err)
	}
	pubKey, err := secp256k1.ParsePubKey(pubResp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("mysql 2-of-3 signing"))
	signPlayers := []string{"1", "3"}
	signBody := map[string]any{"chainPath": nil, "messageHash": digest[:]}
	signCh := make(chan callResult, 2)
	for _, idx := range []int{0, 2} {
		go func() {
			signCh <- call(idx, "/ecdsa/keys/mysql-ecdsa/sign", "mysql-sign-1", signPlayers, signBody)
		}()
	}
	signReplies := [2]callResult{<-signCh, <-signCh}
	for _, res := range signReplies {
		if res.err != nil || res.code != http.StatusOK {
			t.Fatalf("node %d sign failed: HTTP %d, err=%v, body=%s", res.idx+1, res.code, res.err, res.body)
		}
	}
	var sigResp struct {
		Signature []byte `json:"signature"`
	}
	if !bytes.Equal(signReplies[0].body, signReplies[1].body) || json.Unmarshal(signReplies[0].body, &sigResp) != nil {
		t.Fatalf("unexpected MySQL sign responses: %s vs %s", signReplies[0].body, signReplies[1].body)
	}
	sig, err := secpECDSA.ParseDERSignature(sigResp.Signature)
	if err != nil || !sig.Verify(digest[:], pubKey) {
		t.Fatalf("ECDSA signature from MySQL cluster failed verification: %v", fmt.Errorf("%v", err))
	}
}
