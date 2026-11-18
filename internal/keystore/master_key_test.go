package keystore

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestMasterKeyStartup(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "node.sqlite")
	open := func() *SQLite {
		t.Helper()
		store, err := OpenSQLite(path, "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	store := open()
	if key, err := store.LoadOrCreateMasterKey(ctx, ""); key != nil || err != nil {
		t.Fatalf("unconfigured database: %v", err)
	}
	const password = "master key fixture password"
	key, err := store.LoadOrCreateMasterKey(ctx, password)
	if err != nil || len(key) != 32 {
		t.Fatalf("initialize master key: %v", err)
	}
	defer clear(key)
	var salt, ciphertext []byte
	if err := store.db.QueryRow("SELECT salt, ciphertext FROM node_master_key WHERE id = 1").Scan(&salt, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(salt) != 16 || len(ciphertext) != 60 || bytes.Contains(ciphertext, key) {
		t.Fatal("unexpected master key record")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = open()
	for _, invalid := range []string{"", "wrong password"} {
		if loaded, err := store.LoadOrCreateMasterKey(ctx, invalid); err == nil || loaded != nil {
			t.Fatal("invalid credentials unlocked the master key")
		}
	}
	reopened, err := store.LoadOrCreateMasterKey(ctx, password)
	defer clear(reopened)
	if err != nil || !bytes.Equal(reopened, key) {
		t.Fatalf("restart changed the master key: %v", err)
	}

	ciphertext[0] ^= 1
	if _, err := store.db.Exec("UPDATE node_master_key SET ciphertext = ? WHERE id = 1", ciphertext); err != nil {
		t.Fatal(err)
	}
	if key, err := store.LoadOrCreateMasterKey(ctx, password); err == nil || key != nil {
		t.Fatal("tampered record was accepted")
	}
	var saved []byte
	if err := store.db.QueryRow("SELECT ciphertext FROM node_master_key WHERE id = 1").Scan(&saved); err != nil ||
		!bytes.Equal(saved, ciphertext) {
		t.Fatalf("failed startup replaced the persisted record: %v", err)
	}
}
