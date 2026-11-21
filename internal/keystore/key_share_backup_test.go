package keystore

import (
	"bytes"
	"errors"
	"testing"
)

func TestLocalKeyShareBackup(t *testing.T) {
	ctx := t.Context()
	open := func() *SQLite {
		t.Helper()
		store, err := OpenNodeSQLite(t.TempDir(), "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.EnableShareEncryption(ctx, NewShareCipher(bytes.Repeat([]byte{1}, 32), "1")); err != nil {
			t.Fatal(err)
		}
		return store
	}
	source := open()
	key := Key{Algorithm: "frost", SessionID: "source", KeyID: "key", Threshold: 1}
	if _, err := source.Reserve(ctx, "a", key); err != nil {
		t.Fatal(err)
	}
	if err := source.Save(ctx, "a", key, []byte("original private share")); err != nil {
		t.Fatal(err)
	}
	backup, err := source.ExportKeyShare(ctx, "a", key.Algorithm, key.KeyID)
	if err != nil || backup.Key != key || backup.CreatedAt == nil {
		t.Fatalf("export: %v", err)
	}
	defer clear(backup.Share)
	if _, err := source.ExportKeyShare(ctx, "b", key.Algorithm, key.KeyID); err == nil {
		t.Fatal("another application read the source share")
	}
	target := open()
	for range 2 {
		if err := target.RestoreKeyShare(ctx, "a", backup); err != nil {
			t.Fatalf("restore: %v", err)
		}
	}
	restored, err := target.ExportKeyShare(ctx, "a", key.Algorithm, key.KeyID)
	if err != nil || restored.Key != backup.Key || !bytes.Equal(restored.Share, backup.Share) ||
		restored.CreatedAt == nil || *restored.CreatedAt != *backup.CreatedAt {
		t.Fatalf("restored metadata or secret changed: %v", err)
	}
	defer clear(restored.Share)
	var format int
	var ciphertext []byte
	if err := target.db.QueryRow("SELECT share_format, share FROM key_shares").Scan(&format, &ciphertext); err != nil ||
		format != 1 || bytes.Contains(ciphertext, backup.Share) {
		t.Fatalf("restored share was not encrypted: %v", err)
	}
	changed := backup
	changed.Share = []byte("another generation")
	if err := target.RestoreKeyShare(ctx, "a", changed); !errors.Is(err, ErrKeyShareConflict) {
		t.Fatalf("backup overwrote a different share: %v", err)
	}
	changed = backup
	changed.Key.KeyID = "other-key"
	if err := target.RestoreKeyShare(ctx, "a", changed); !errors.Is(err, ErrKeyShareConflict) {
		t.Fatalf("session reservation collision accepted: %v", err)
	}
	if err := target.DeleteKeyShare(ctx, "a", key.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := target.RestoreKeyShare(ctx, "a", backup); err != nil {
		t.Fatalf("could not restore a deleted share: %v", err)
	}
}
