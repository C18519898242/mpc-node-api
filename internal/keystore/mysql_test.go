package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func createTestMySQLDatabase(t *testing.T, collation string) (*mysql.Config, string) {
	t.Helper()
	baseDSN := os.Getenv("MPC_TEST_MYSQL_DSN")
	if baseDSN == "" {
		t.Skip("set MPC_TEST_MYSQL_DSN to run MySQL keystore tests")
	}
	parsed, err := mysql.ParseDSN(baseDSN)
	if err != nil {
		t.Fatalf("parse MPC_TEST_MYSQL_DSN: %v", err)
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	dbName := "mpc_test_" + hex.EncodeToString(suffix[:])
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
	if _, err := admin.ExecContext(t.Context(), "CREATE DATABASE `"+dbName+"` CHARACTER SET utf8mb4 COLLATE "+collation); err != nil {
		t.Fatalf("create temp database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS `" + dbName + "`")
	})
	nodeCfg := parsed.Clone()
	nodeCfg.DBName = dbName
	if nodeCfg.TLSConfig == "" {
		nodeCfg.TLSConfig = "preferred"
	}
	return nodeCfg, dbName
}

func openRawTestMySQL(t *testing.T, partyID string) (*Store, string) {
	t.Helper()
	nodeCfg, dbName := createTestMySQLDatabase(t, "utf8mb4_0900_bin")
	dsn := nodeCfg.FormatDSN()
	store, err := OpenMySQL(dsn, partyID)
	if err != nil {
		t.Fatalf("OpenMySQL(%s): %v", dbName, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dsn
}

func openTestMySQL(t *testing.T, partyID string) (*Store, string) {
	t.Helper()
	store, dsn := openRawTestMySQL(t, partyID)
	mk, err := store.LoadOrCreateMasterKey(t.Context(), "test-mysql-mk-"+partyID)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey: %v", err)
	}
	t.Cleanup(func() { clear(mk) })
	if err := store.EnableShareEncryption(t.Context(), NewShareCipher(mk, partyID)); err != nil {
		t.Fatalf("EnableShareEncryption: %v", err)
	}
	return store, dsn
}

func TestBuildMySQLConfigTLSAndAutocommit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mysql-test-ca"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mysql-test-ca"},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	// DSN with tls=preferred + allowFallbackToPlaintext=true + autocommit=0 overridden by strict tlsMode="true".
	cfg, err := buildMySQLConfig("user:pass@tcp(db.example:3306)/mpc?tls=preferred&allowFallbackToPlaintext=true&autocommit=0", "1", MySQLOptions{
		TLSMode: "true",
	})
	if err != nil {
		t.Fatalf("buildMySQLConfig(true): %v", err)
	}
	if cfg.TLSConfig != "true" || cfg.AllowFallbackToPlaintext {
		t.Fatalf("strict TLS override left TLSConfig=%q AllowFallbackToPlaintext=%v", cfg.TLSConfig, cfg.AllowFallbackToPlaintext)
	}
	if cfg.Params["autocommit"] != "1" {
		t.Fatalf("autocommit param = %q, want 1", cfg.Params["autocommit"])
	}

	// DSN with tls=preferred + allowFallbackToPlaintext=true overridden by custom CAFile.
	cfgCA, err := buildMySQLConfig("user:pass@tcp(db.example:3306)/mpc?tls=preferred&allowFallbackToPlaintext=true", "1", MySQLOptions{
		CAFile: caPath,
	})
	if err != nil {
		t.Fatalf("buildMySQLConfig(caFile): %v", err)
	}
	if !strings.HasPrefix(cfgCA.TLSConfig, "mpc-mysql-") || cfgCA.AllowFallbackToPlaintext {
		t.Fatalf("CA override left TLSConfig=%q AllowFallbackToPlaintext=%v", cfgCA.TLSConfig, cfgCA.AllowFallbackToPlaintext)
	}

	// DSN with tls=true&allowFallbackToPlaintext=true and empty TLSMode must still disable fallback.
	cfgNoFallback, err := buildMySQLConfig("user:pass@tcp(db.example:3306)/mpc?tls=true&allowFallbackToPlaintext=true", "1", MySQLOptions{})
	if err != nil {
		t.Fatalf("buildMySQLConfig(dsn strict): %v", err)
	}
	if cfgNoFallback.TLSConfig != "true" || cfgNoFallback.AllowFallbackToPlaintext {
		t.Fatalf("strict DSN left TLSConfig=%q AllowFallbackToPlaintext=%v", cfgNoFallback.TLSConfig, cfgNoFallback.AllowFallbackToPlaintext)
	}

	// Remote TCP without TLSMode defaults to strict TLS ("true") with no plaintext fallback.
	cfgDefault, err := buildMySQLConfig("user:pass@tcp(db.example:3306)/mpc", "1", MySQLOptions{})
	if err != nil {
		t.Fatalf("buildMySQLConfig(default): %v", err)
	}
	if cfgDefault.TLSConfig != "true" || cfgDefault.AllowFallbackToPlaintext {
		t.Fatalf("default remote TLS = %q, AllowFallbackToPlaintext=%v", cfgDefault.TLSConfig, cfgDefault.AllowFallbackToPlaintext)
	}

	// Explicit tlsMode="preferred" enables fallback.
	cfgPref, err := buildMySQLConfig("user:pass@tcp(127.0.0.1:3306)/mpc", "1", MySQLOptions{TLSMode: "preferred"})
	if err != nil {
		t.Fatalf("buildMySQLConfig(preferred): %v", err)
	}
	if cfgPref.TLSConfig != "preferred" || !cfgPref.AllowFallbackToPlaintext {
		t.Fatalf("preferred TLS = %q, AllowFallbackToPlaintext=%v", cfgPref.TLSConfig, cfgPref.AllowFallbackToPlaintext)
	}

	if _, err := buildMySQLConfig("user:pass@tcp(db.example:3306)/mpc", "1", MySQLOptions{TLSMode: "preferred", CAFile: caPath}); err == nil {
		t.Fatal("accepted conflicting caFile and tlsMode=preferred")
	}
}

func TestOpenMySQLValidation(t *testing.T) {
	if _, err := OpenMySQL("user:pass@tcp(127.0.0.1:3306)/db", ""); err == nil {
		t.Fatal("accepted empty partyID")
	}
	if _, err := OpenMySQL("user:pass@tcp(127.0.0.1:3306)/", "1"); err == nil {
		t.Fatal("accepted DSN without database name")
	}
	if _, err := OpenMySQLWithOptions("user:pass@tcp(127.0.0.1:3306)/db", "1", MySQLOptions{TLSMode: "false", CAFile: "ca.pem"}); err == nil {
		t.Fatal("accepted conflicting caFile and tlsMode")
	}
	if _, err := OpenMySQLWithOptions("user:pass@tcp(127.0.0.1:3306)/db", "1", MySQLOptions{TLSMode: "bad"}); err == nil {
		t.Fatal("accepted invalid tlsMode")
	}
}

func TestMySQLAutocommitZeroOverriddenAndReopen(t *testing.T) {
	ctx := t.Context()
	nodeCfg, _ := createTestMySQLDatabase(t, "utf8mb4_0900_bin")
	if nodeCfg.Params == nil {
		nodeCfg.Params = map[string]string{}
	}
	nodeCfg.Params["autocommit"] = "0"
	dsn := nodeCfg.FormatDSN()

	store, err := OpenMySQL(dsn, "1")
	if err != nil {
		t.Fatalf("OpenMySQL with autocommit=0 in DSN: %v", err)
	}
	mk, err := store.LoadOrCreateMasterKey(ctx, "autocommit-mk")
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	defer clear(mk)
	if err := store.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	key := Key{Algorithm: "ecdsa", SessionID: "ac-sess", KeyID: "ac-key", Threshold: 1}
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Reserved {
		t.Fatalf("Reserve = (%v, %v)", outcome, err)
	}
	if err := store.Save(ctx, DefaultApplication, key, []byte("autocommit-share")); err != nil {
		t.Fatal(err)
	}
	if fresh, err := store.ReserveSession(ctx, DefaultApplication, "ac-res"); err != nil || !fresh {
		t.Fatalf("ReserveSession = (%v, %v)", fresh, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenMySQL(dsn, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	mk2, err := reopened.LoadOrCreateMasterKey(ctx, "autocommit-mk")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk2)
	if err := reopened.EnableShareEncryption(ctx, NewShareCipher(mk2, "1")); err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Load(ctx, DefaultApplication, "ecdsa", "ac-key"); err != nil || string(got) != "autocommit-share" {
		t.Fatalf("reopened Load = (%q, %v)", got, err)
	}
	if outcome, err := reopened.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Completed {
		t.Fatalf("reopened Reserve replay = (%v, %v), want Completed", outcome, err)
	}
	if fresh, err := reopened.ReserveSession(ctx, DefaultApplication, "ac-res"); err != nil || fresh {
		t.Fatalf("reopened ReserveSession = (%v, %v), want false", fresh, err)
	}
}

func TestMySQLKeyShareCaseSensitivityAndOwnership(t *testing.T) {
	ctx := t.Context()
	store, dsn := openTestMySQL(t, "node-1")

	for _, tc := range []struct {
		app, sess, key string
		payload        []byte
	}{
		{"AppA", "SessA", "KeyA", []byte("upper-a")},
		{"appa", "sessa", "keya", []byte("lower-a")},
		{"AppA", "Sess ", "Key ", []byte("trailing-space")},
		{"AppA", "Sess", "Key", []byte("no-space")},
	} {
		key := Key{Algorithm: "frost", SessionID: tc.sess, KeyID: tc.key, Threshold: 1}
		if outcome, err := store.Reserve(ctx, tc.app, key); err != nil || outcome != Reserved {
			t.Fatalf("reserve %+v: (%v, %v)", tc, outcome, err)
		}
		if err := store.Save(ctx, tc.app, key, tc.payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		app, key string
		want     []byte
	}{
		{"AppA", "KeyA", []byte("upper-a")},
		{"appa", "keya", []byte("lower-a")},
		{"AppA", "Key ", []byte("trailing-space")},
		{"AppA", "Key", []byte("no-space")},
	} {
		got, err := store.Load(ctx, tc.app, "frost", tc.key)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("load %s/%q = (%q, %v), want %q", tc.app, tc.key, got, err, tc.want)
		}
	}

	reopened, err := OpenMySQL(dsn, "node-1")
	if err != nil {
		t.Fatalf("reopen same node: %v", err)
	}
	defer reopened.Close()
	if outcome, err := reopened.Reserve(ctx, "AppA", Key{Algorithm: "frost", SessionID: "SessA", KeyID: "KeyA", Threshold: 1}); err != nil || outcome != Completed {
		t.Fatalf("replay = (%v, %v), want Completed", outcome, err)
	}
	if other, err := OpenMySQL(dsn, "node-2"); err == nil {
		_ = other.Close()
		t.Fatal("another node opened the same MySQL database")
	}
}

func TestMySQLCollationUpgradeAndTrailingSpaceIDs(t *testing.T) {
	ctx := t.Context()
	nodeCfg, dbName := createTestMySQLDatabase(t, "utf8mb4_bin")
	dsn := nodeCfg.FormatDSN()

	legacyDB, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE node_owner (
			id TINYINT NOT NULL PRIMARY KEY,
			party_id VARCHAR(32) NOT NULL,
			CHECK (id = 1)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
		`INSERT INTO node_owner (id, party_id) VALUES (1, '1')`,
		`CREATE TABLE key_shares (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			algorithm VARCHAR(32) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			threshold INT NOT NULL,
			share LONGBLOB,
			share_format TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_key_shares_app_alg_key (application_id, algorithm, key_id),
			UNIQUE KEY uq_key_shares_app_alg_session (application_id, algorithm, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
		`CREATE TABLE session_reservations (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_session_reservations_app_session (application_id, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`,
	} {
		if _, err := legacyDB.ExecContext(ctx, stmt); err != nil {
			_ = legacyDB.Close()
			t.Fatal(err)
		}
	}

	// Wrong node must be rejected before creating missing tables or altering collations.
	if wrong, err := OpenMySQL(dsn, "2"); err == nil {
		_ = wrong.Close()
		_ = legacyDB.Close()
		t.Fatal("wrong node opened legacy database owned by node 1")
	}
	for _, table := range []string{"node_owner", "key_shares", "session_reservations"} {
		var coll string
		if err := legacyDB.QueryRowContext(ctx, `SELECT TABLE_COLLATION FROM information_schema.TABLES
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`, dbName, table).Scan(&coll); err != nil {
			_ = legacyDB.Close()
			t.Fatal(err)
		}
		if coll != "utf8mb4_bin" {
			_ = legacyDB.Close()
			t.Fatalf("rejected wrong-node open altered %s collation to %q", table, coll)
		}
	}
	var extraTables int
	if err := legacyDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'reshare_sessions'`, dbName).Scan(&extraTables); err != nil {
		_ = legacyDB.Close()
		t.Fatal(err)
	}
	if extraTables != 0 {
		_ = legacyDB.Close()
		t.Fatalf("rejected wrong-node open created %d extra tables", extraTables)
	}
	_ = legacyDB.Close()

	store, err := OpenMySQL(dsn, "1")
	if err != nil {
		t.Fatalf("OpenMySQL upgrade from utf8mb4_bin: %v", err)
	}
	defer store.Close()
	mk, err := store.LoadOrCreateMasterKey(ctx, "collation-mk")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk)
	if err := store.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
		t.Fatal(err)
	}

	for _, table := range mysqlTables {
		var coll string
		if err := store.db.QueryRowContext(ctx, `SELECT TABLE_COLLATION FROM information_schema.TABLES
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`, dbName, table).Scan(&coll); err != nil {
			t.Fatal(err)
		}
		if coll != "utf8mb4_0900_bin" {
			t.Fatalf("table %s collation = %q, want utf8mb4_0900_bin", table, coll)
		}
	}

	// Trailing-space vs trimmed session/key IDs must both be stored and restored independently.
	for _, sid := range []string{"backup-sess", "backup-sess "} {
		fresh, err := store.ReserveSession(ctx, DefaultApplication, sid)
		if err != nil || !fresh {
			t.Fatalf("ReserveSession(%q) = (%v, %v)", sid, fresh, err)
		}
		kid := "key-" + sid
		if err := store.RestoreKeyShare(ctx, DefaultApplication, KeyShareBackup{
			Key:   Key{Algorithm: "frost", SessionID: sid, KeyID: kid, Threshold: 1},
			Share: []byte("share-" + sid),
		}); err != nil {
			t.Fatalf("RestoreKeyShare(%q): %v", sid, err)
		}
		got, err := store.Load(ctx, DefaultApplication, "frost", kid)
		if err != nil || string(got) != "share-"+sid {
			t.Fatalf("Load(%q) = (%q, %v)", kid, got, err)
		}
	}
}

func TestMySQLApplicationIsolationPresignAndReshare(t *testing.T) {
	ctx := t.Context()
	db, _ := openTestMySQL(t, "1")

	wallets := []string{"a", "b"}
	key := Key{Algorithm: "ecdsa", SessionID: "same-session", KeyID: "same-key", Threshold: 1}
	reshare := Reshare{Algorithm: key.Algorithm, SessionID: "same-reshare", KeyID: key.KeyID}
	for _, wallet := range wallets {
		if outcome, err := db.Reserve(ctx, wallet, key); err != nil || outcome != Reserved {
			t.Fatalf("reserve key for %s: %v, %v", wallet, outcome, err)
		}
		if err := db.Save(ctx, wallet, key, []byte(wallet)); err != nil {
			t.Fatal(err)
		}
		presigs := []Presignature{
			{ID: "first", Share: []byte(wallet + "-1")},
			{ID: "second", Share: []byte(wallet + "-2")},
		}
		if outcome, _, err := db.ReserveECDSAPresign(ctx, wallet, "batch-1", key.KeyID, [32]byte{1}); err != nil || outcome != Reserved {
			t.Fatalf("reserve presign for %s: %v, %v", wallet, outcome, err)
		}
		if _, err := db.SaveECDSAPresign(ctx, wallet, "batch-1", presigs); err != nil {
			t.Fatal(err)
		}
		if outcome, _, err := db.ReserveReshare(ctx, wallet, reshare); err != nil || outcome != Reserved {
			t.Fatalf("reserve reshare for %s: %v, %v", wallet, outcome, err)
		}
		if err := db.StageReshare(ctx, wallet, reshare, [32]byte{2}, []byte(wallet+"-refreshed")); err != nil {
			t.Fatal(err)
		}
	}

	// Concurrent presignature consumption must succeed exactly once.
	results := make(chan error, 8)
	for range 8 {
		go func() {
			share, err := db.ConsumeECDSAPresign(ctx, "a", key.KeyID, "first")
			if err == nil && (share.ID != "first" || string(share.Share) != "a-1") {
				err = errors.New("unexpected consumed share")
			}
			results <- err
		}()
	}
	successes := 0
	for range 8 {
		switch err := <-results; {
		case err == nil:
			successes++
		case !errors.Is(err, sql.ErrNoRows):
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent presign successes = %d, want 1", successes)
	}
	if count, err := db.CountPresign(ctx, "a", key.KeyID); err != nil || count != 1 {
		t.Fatalf("CountPresign = (%d, %v), want 1", count, err)
	}
	if err := db.CommitReshare(ctx, "a", reshare); err != nil {
		t.Fatal(err)
	}
	if count, err := db.CountPresign(ctx, "a", key.KeyID); err != nil || count != 0 {
		t.Fatalf("CountPresign after commit = (%d, %v), want 0", count, err)
	}
	if share, err := db.Load(ctx, "a", key.Algorithm, key.KeyID); err != nil || string(share) != "a-refreshed" {
		t.Fatalf("refreshed share = (%q, %v)", share, err)
	}
	if share, err := db.Load(ctx, "b", key.Algorithm, key.KeyID); err != nil || string(share) != "b" {
		t.Fatalf("app b share changed = (%q, %v)", share, err)
	}
	if err := db.DeleteKeyShare(ctx, "a", key.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CountPresign(ctx, "a", key.KeyID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted key CountPresign = %v, want ErrNoRows", err)
	}
}

func TestMySQLReshareSupersededCannotCommit(t *testing.T) {
	ctx := t.Context()
	store1, dsn := openTestMySQL(t, "1")
	store2, err := OpenMySQL(dsn, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	mk, err := store2.LoadOrCreateMasterKey(ctx, "test-mysql-mk-1")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk)
	if err := store2.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
		t.Fatal(err)
	}

	key := Key{Algorithm: "ecdsa", SessionID: "s1", KeyID: "k-race", Threshold: 1}
	if _, err := store1.Reserve(ctx, DefaultApplication, key); err != nil {
		t.Fatal(err)
	}
	if err := store1.Save(ctx, DefaultApplication, key, []byte("initial-share")); err != nil {
		t.Fatal(err)
	}
	r1 := Reshare{Algorithm: "ecdsa", SessionID: "r1", KeyID: "k-race"}
	r2 := Reshare{Algorithm: "ecdsa", SessionID: "r2", KeyID: "k-race"}
	for _, op := range []Reshare{r1, r2} {
		if _, _, err := store1.ReserveReshare(ctx, DefaultApplication, op); err != nil {
			t.Fatal(err)
		}
		if err := store1.StageReshare(ctx, DefaultApplication, op, [32]byte{1}, []byte("share-"+op.SessionID)); err != nil {
			t.Fatal(err)
		}
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	store2.beforeReshareKeyHook = func() {
		close(entered)
		<-release
	}
	commit2Done := make(chan error, 1)
	go func() {
		commit2Done <- store2.CommitReshare(ctx, DefaultApplication, r2)
	}()
	select {
	case <-entered:
	case err := <-commit2Done:
		t.Fatalf("store2 CommitReshare(r2) finished before hook: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for store2 CommitReshare(r2) to reach hook")
	}
	if err := store1.CommitReshare(ctx, DefaultApplication, r1); err != nil {
		close(release)
		t.Fatalf("store1 CommitReshare(r1): %v", err)
	}
	close(release)
	select {
	case err := <-commit2Done:
		if err == nil {
			t.Fatal("superseded reshare r2 unexpectedly committed over r1")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for store2 CommitReshare(r2) completion")
	}

	got, err := store1.Load(ctx, DefaultApplication, "ecdsa", "k-race")
	if err != nil || string(got) != "share-r1" {
		t.Fatalf("effective share = (%q, %v), want share-r1", got, err)
	}
	st1, err := store1.LoadReshare(ctx, DefaultApplication, r1)
	if err != nil || !st1.Committed {
		t.Fatalf("r1 state = (%+v, %v), want committed", st1, err)
	}
	if _, err := store1.LoadReshare(ctx, DefaultApplication, r2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("r2 LoadReshare = %v, want sql.ErrNoRows (superseded)", err)
	}
}

func TestMySQLRequiresMKFromFirstWriteAndRejectsPlaintextRows(t *testing.T) {
	ctx := t.Context()
	rawStore, dsn := openRawTestMySQL(t, "1")

	key := Key{Algorithm: "frost", SessionID: "s1", KeyID: "k1", Threshold: 1}
	if _, err := rawStore.Reserve(ctx, DefaultApplication, key); err != nil {
		t.Fatal(err)
	}
	// Plaintext write to MySQL before MK encryption is enabled must be rejected.
	if err := rawStore.Save(ctx, DefaultApplication, key, []byte("plain-key")); err == nil {
		t.Fatal("mysql allowed plaintext key share write before MK encryption")
	}

	mk, err := rawStore.LoadOrCreateMasterKey(ctx, "mysql-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk)
	if err := rawStore.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
		t.Fatalf("EnableShareEncryption: %v", err)
	}
	if err := rawStore.Save(ctx, DefaultApplication, key, []byte("secret-key")); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var format int
	if err := rawStore.db.QueryRowContext(ctx, `SELECT share, share_format FROM key_shares
		WHERE application_id = ? AND algorithm = ? AND key_id = ?`, DefaultApplication, "frost", "k1").Scan(&stored, &format); err != nil {
		t.Fatal(err)
	}
	if format != encryptedShare || bytes.Equal(stored, []byte("secret-key")) {
		t.Fatalf("first MySQL write was not encrypted: format=%d, equal=%v", format, bytes.Equal(stored, []byte("secret-key")))
	}

	if _, _, err := rawStore.ReserveFROSTPresign(ctx, DefaultApplication, "pb1", "k1", [32]byte{3}); err != nil {
		t.Fatal(err)
	}
	if _, err := rawStore.SaveFROSTPresign(ctx, DefaultApplication, "pb1", []Presignature{{ID: "p1", Share: []byte("secret-presig")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rawStore.LoadOrCreateMasterKey(ctx, "wrong-secret"); err == nil {
		t.Fatal("wrong master password unlocked database")
	}

	reopened, err := OpenMySQL(dsn, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	mk2, err := reopened.LoadOrCreateMasterKey(ctx, "mysql-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk2)
	if !bytes.Equal(mk, mk2) {
		t.Fatal("reopened master key mismatch")
	}
	if err := reopened.EnableShareEncryption(ctx, NewShareCipher(mk2, "1")); err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Load(ctx, DefaultApplication, "frost", "k1"); err != nil || string(got) != "secret-key" {
		t.Fatalf("Load encrypted key = (%q, %v)", got, err)
	}
	if p, err := reopened.ConsumeFROSTPresign(ctx, DefaultApplication, "k1", "p1"); err != nil || string(p.Share) != "secret-presig" {
		t.Fatalf("ConsumeFROSTPresign encrypted = (%q, %v)", p.Share, err)
	}
	backup, err := reopened.ExportKeyShare(ctx, DefaultApplication, "frost", "k1")
	if err != nil || string(backup.Share) != "secret-key" {
		t.Fatalf("ExportKeyShare = (%q, %v)", backup.Share, err)
	}

	// Restore backup into a separate encrypted MySQL store.
	restoredStore, _ := openTestMySQL(t, "1")
	if err := restoredStore.RestoreKeyShare(ctx, DefaultApplication, backup); err != nil {
		t.Fatalf("RestoreKeyShare: %v", err)
	}
	if got, err := restoredStore.Load(ctx, DefaultApplication, "frost", "k1"); err != nil || string(got) != "secret-key" {
		t.Fatalf("restored Load = (%q, %v)", got, err)
	}

	// Session reservations & wallet backups.
	if fresh, err := reopened.ReserveSession(ctx, DefaultApplication, "sess-1"); err != nil || !fresh {
		t.Fatalf("ReserveSession fresh = (%v, %v)", fresh, err)
	}
	if fresh, err := reopened.ReserveSession(ctx, DefaultApplication, "sess-1"); err != nil || fresh {
		t.Fatalf("ReserveSession duplicate = (%v, %v)", fresh, err)
	}
	if has, err := reopened.HasSession(ctx, DefaultApplication, "sess-1"); err != nil || !has {
		t.Fatalf("HasSession = (%v, %v)", has, err)
	}
	if ok, err := reopened.ReserveWallet(ctx, DefaultApplication, "ws1", "w1", []byte{9, 9}); err != nil || !ok {
		t.Fatalf("ReserveWallet = (%v, %v)", ok, err)
	}
	wb := MnemonicBackup{Version: 1, KeyID: "bk1", WrappedKey: []byte("wk"), Ciphertext: bytes.Repeat([]byte{7}, 32)}
	if err := reopened.SaveWallet(ctx, DefaultApplication, "ws1", "w1", "we1", "wf1", []byte("manifest"), wb, []byte("es"), []byte("fs")); err != nil {
		t.Fatalf("SaveWallet: %v", err)
	}
	gotWB, gotManifest, err := reopened.LoadWalletBackup(ctx, DefaultApplication, "w1")
	if err != nil || !reflect.DeepEqual(gotWB, wb) || string(gotManifest) != "manifest" {
		t.Fatalf("LoadWalletBackup = (%+v, %q, %v)", gotWB, gotManifest, err)
	}

	// Pre-existing plaintext rows in any sensitive table must fail EnableShareEncryption on MySQL.
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"key_shares", `INSERT INTO key_shares (application_id, algorithm, session_id, key_id, threshold, share, share_format) VALUES ('default', 'ecdsa', 'plain-s', 'plain-k', 1, X'01', 0)`},
		{"reshare_sessions", `INSERT INTO reshare_sessions (application_id, algorithm, session_id, key_id, state, share, share_format) VALUES ('default', 'ecdsa', 'plain-rs', 'plain-k', 'prepared', X'01', 0)`},
		{"ecdsa_presignatures", `INSERT INTO ecdsa_presignatures (application_id, presignature_id, key_id, share, share_format) VALUES ('default', 'plain-ep', 'plain-k', X'01', 0)`},
		{"frost_presignatures", `INSERT INTO frost_presignatures (application_id, presignature_id, key_id, share, share_format) VALUES ('default', 'plain-fp', 'plain-k', X'01', 0)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirty, _ := openRawTestMySQL(t, "1")
			dirtyMK, err := dirty.LoadOrCreateMasterKey(ctx, "dirty-secret")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(dirtyMK)
			if _, err := dirty.db.ExecContext(ctx, tc.query); err != nil {
				t.Fatal(err)
			}
			if err := dirty.EnableShareEncryption(ctx, NewShareCipher(dirtyMK, "1")); err == nil {
				t.Fatalf("EnableShareEncryption unexpectedly accepted plaintext row in %s", tc.name)
			}
		})
	}
}
