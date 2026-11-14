package keystore

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "node.sqlite")
	store, err := OpenNodeSQLite(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Algorithm: "frost", SessionID: "session", KeyID: "Key", Threshold: 2}
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	if err := store.Save(ctx, key, []byte("test share")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLite(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Completed {
		t.Fatalf("replay = %v, %v", outcome, err)
	}
	if share, err := store.Load(ctx, key.Algorithm, key.KeyID); err != nil || !bytes.Equal(share, []byte("test share")) {
		t.Fatalf("saved share could not be loaded: %v", err)
	}
	key.SessionID = "other-session"
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Conflict {
		t.Fatalf("reuse key ID = %v, %v", outcome, err)
	}
	if other, err := OpenSQLite(path, "node-2"); err == nil {
		other.Close()
		t.Fatal("another node opened this database")
	}
}

func TestSQLiteRejectsIncompleteSessionReplay(t *testing.T) {
	ctx := context.Background()
	store, err := OpenNodeSQLite(t.TempDir(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := Key{Algorithm: "ecdsa", SessionID: "attempt", KeyID: "key", Threshold: 1}
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Conflict {
		t.Fatalf("incomplete replay = %v, %v", outcome, err)
	}
}
