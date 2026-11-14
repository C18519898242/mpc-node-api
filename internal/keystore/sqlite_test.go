package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
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

func TestSQLiteMigratesKeyShareIDsAndTimestamps(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "node.sqlite")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE key_shares (
		algorithm TEXT NOT NULL, session_id TEXT NOT NULL, key_id TEXT NOT NULL,
		threshold INTEGER NOT NULL, share BLOB, PRIMARY KEY (algorithm, key_id),
		UNIQUE (algorithm, session_id)
	);
	INSERT INTO key_shares VALUES ('ecdsa', 'saved', 'key-1', 2, X'0102'),
		('frost', 'pending', 'key-2', 2, NULL);`)
	closeErr := legacy.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("create legacy schema: %v, %v", err, closeErr)
	}

	for range 2 {
		store, err := OpenSQLite(path, "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		key := Key{Algorithm: "ecdsa", SessionID: "saved", KeyID: "key-1", Threshold: 2}
		if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Completed {
			t.Fatalf("completed replay = %v, %v", outcome, err)
		}
		if share, err := store.Load(ctx, key.Algorithm, key.KeyID); err != nil || !bytes.Equal(share, []byte{1, 2}) {
			t.Fatalf("legacy share did not survive migration: %v", err)
		}
		key = Key{Algorithm: "frost", SessionID: "pending", KeyID: "key-2", Threshold: 2}
		if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Conflict {
			t.Fatalf("incomplete replay = %v, %v", outcome, err)
		}
		var id int64
		var createdAt sql.NullString
		if err := store.db.QueryRow("SELECT id, created_at FROM key_shares WHERE key_id = 'key-2'").Scan(&id, &createdAt); err != nil {
			t.Fatal(err)
		}
		if id != 2 || createdAt.Valid {
			t.Fatalf("legacy ID = %d, timestamp = %v", id, createdAt)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}

	store, err := OpenSQLite(path, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := Key{Algorithm: "frost", SessionID: "new", KeyID: "key-3", Threshold: 2}
	if outcome, err := store.Reserve(ctx, key); err != nil || outcome != Reserved {
		t.Fatalf("new reservation = %v, %v", outcome, err)
	}
	var id int64
	var createdAt string
	if err := store.db.QueryRow("SELECT id, created_at FROM key_shares WHERE key_id = 'key-3'").Scan(&id, &createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse("2006-01-02 15:04:05", createdAt); err != nil || id <= 2 {
		t.Fatalf("new ID = %d, timestamp = %q", id, createdAt)
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
