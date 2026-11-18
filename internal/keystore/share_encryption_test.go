package keystore

import (
	"bytes"
	"testing"
)

func TestEncryptKeySharesAndReload(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	db, err := OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := Key{Algorithm: "frost", KeyID: "key", SessionID: "keygen", Threshold: 1}
	app := "wallet-a"
	const password = "test fixture password"
	original := []byte("old private share")
	refreshed := []byte("refreshed private share")
	if _, err := db.Reserve(ctx, app, key); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(ctx, app, key, original); err != nil {
		t.Fatal(err)
	}
	op := Reshare{Algorithm: key.Algorithm, KeyID: key.KeyID, SessionID: "refresh"}
	if _, _, err := db.ReserveReshare(ctx, app, op); err != nil {
		t.Fatal(err)
	}
	if err := db.StageReshare(ctx, app, op, [32]byte{1}, refreshed); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopen := func() *SQLite {
		t.Helper()
		db, err := OpenNodeSQLite(dir, "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		mk, err := db.LoadOrCreateMasterKey(ctx, password)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(mk) })
		if err := db.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
			t.Fatal(err)
		}
		return db
	}
	db = reopen()
	atRest := func(table string, plaintext []byte) []byte {
		t.Helper()
		var raw []byte
		var version int
		if err := db.db.QueryRow("SELECT share, share_format FROM "+table+" WHERE share IS NOT NULL").
			Scan(&raw, &version); err != nil || version != 1 || bytes.Contains(raw, plaintext) {
			t.Fatalf("expected an encrypted share in %s: format=%d error=%v", table, version, err)
		}
		return raw
	}
	atRest("key_shares", original)
	staged := atRest("reshare_sessions", refreshed)
	if err := db.CommitReshare(ctx, app, op); err != nil {
		t.Fatal(err)
	}
	sealed := atRest("key_shares", refreshed)
	if bytes.Equal(staged, sealed) {
		t.Fatal("staged ciphertext was reused as the committed record")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = reopen()
	have, err := db.Load(ctx, app, key.Algorithm, key.KeyID)
	if err != nil || !bytes.Equal(have, refreshed) {
		t.Fatalf("after restart, load refreshed share: %v", err)
	}
	if !bytes.Equal(atRest("key_shares", refreshed), sealed) {
		t.Fatal("startup encrypted the same share twice")
	}
	if _, err := db.db.Exec("UPDATE key_shares SET application_id = 'wallet-b'"); err != nil {
		t.Fatal(err)
	}
	if share, err := db.Load(ctx, "wallet-b", key.Algorithm, key.KeyID); share != nil || err == nil {
		t.Fatal("ciphertext was accepted for another application")
	}
}
