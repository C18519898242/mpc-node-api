package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteApplicationIsolation(t *testing.T) {
	ctx := context.Background()
	db, err := OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	wallets := []string{"a", "b"}
	key := Key{Algorithm: "frost", SessionID: "same-session", KeyID: "same-key", Threshold: 2}
	reshare := Reshare{Algorithm: key.Algorithm, SessionID: "same-reshare", KeyID: key.KeyID}
	for _, wallet := range wallets {
		if outcome, err := db.Reserve(ctx, wallet, key); err != nil || outcome != Reserved {
			t.Fatalf("reserve key for %s: %v, %v", wallet, outcome, err)
		}
		if err := db.Save(ctx, wallet, key, []byte(wallet)); err != nil {
			t.Fatal(err)
		}
		presig := Presignature{ID: "same-presig", Share: []byte(wallet)}
		if outcome, _, err := db.ReserveFROSTPresign(ctx, wallet, "same-presig-session", key.KeyID, [32]byte{1}); err != nil || outcome != Reserved {
			t.Fatalf("reserve presign for %s: %v, %v", wallet, outcome, err)
		}
		if _, err := db.SaveFROSTPresign(ctx, wallet, "same-presig-session", []Presignature{presig}); err != nil {
			t.Fatal(err)
		}
		if outcome, _, err := db.ReserveReshare(ctx, wallet, reshare); err != nil || outcome != Reserved {
			t.Fatalf("reserve reshare for %s: %v, %v", wallet, outcome, err)
		}
		if err := db.StageReshare(ctx, wallet, reshare, [32]byte{1}, []byte(wallet+"-refreshed")); err != nil {
			t.Fatal(err)
		}
	}

	a, b := wallets[0], wallets[1]
	if err := db.CommitReshare(ctx, a, reshare); err != nil {
		t.Fatal(err)
	}
	if share, err := db.Load(ctx, a, key.Algorithm, key.KeyID); err != nil || string(share) != "a-refreshed" {
		t.Fatalf("refreshed share: %q, %v", share, err)
	}
	if share, err := db.Load(ctx, b, key.Algorithm, key.KeyID); err != nil || string(share) != "b" {
		t.Fatalf("wallet b share changed: %q, %v", share, err)
	}
	if err := db.DeleteKeyShare(ctx, a, key.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Load(ctx, DefaultApplication, key.Algorithm, key.KeyID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("default app accessed wallet key: %v", err)
	}
	if pending, err := db.PendingReshare(ctx, b, key.Algorithm, key.KeyID); err != nil || !pending {
		t.Fatalf("wallet b refresh lost: %v, %v", pending, err)
	}
	if presig, err := db.ConsumeFROSTPresign(ctx, b, key.KeyID, "same-presig"); err != nil || string(presig.Share) != "b" {
		t.Fatalf("wallet b presign lost: %v", err)
	}
}

func TestSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "node.sqlite")
	store, err := OpenNodeSQLite(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Algorithm: "frost", SessionID: "session", KeyID: "Key", Threshold: 2}
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	if err := store.Save(ctx, DefaultApplication, key, []byte("test share")); err != nil {
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
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Completed {
		t.Fatalf("replay = %v, %v", outcome, err)
	}
	if share, err := store.Load(ctx, DefaultApplication, key.Algorithm, key.KeyID); err != nil || !bytes.Equal(share, []byte("test share")) {
		t.Fatalf("saved share could not be loaded: %v", err)
	}
	key.SessionID = "other-session"
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Conflict {
		t.Fatalf("reuse key ID = %v, %v", outcome, err)
	}
	if other, err := OpenSQLite(path, "node-2"); err == nil {
		other.Close()
		t.Fatal("another node opened this database")
	}
}

func TestSQLiteRemovesCopySessionColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.sqlite")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(createKeyShares + `;
		ALTER TABLE key_shares ADD COLUMN request_binding TEXT NOT NULL DEFAULT '';
		ALTER TABLE key_shares ADD COLUMN copy_digest BLOB;
		ALTER TABLE key_shares ADD COLUMN copy_candidate BLOB;
		INSERT INTO key_shares (id, algorithm, session_id, key_id, threshold, share, created_at, request_binding, copy_digest)
			VALUES (4, 'frost', 'copy.saved', 'copy-key', 2, X'1234', '2026-11-16 15:48:13', 'request', X'1234');`)
	closeErr := old.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("create old copy schema: %v, %v", err, closeErr)
	}
	for range 2 {
		store, err := OpenSQLite(path, "1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		var columns, id int
		var createdAt string
		if err := store.db.QueryRow(`SELECT count(*) FROM pragma_table_info('key_shares')
			WHERE name IN ('request_binding', 'copy_digest', 'copy_candidate')`).Scan(&columns); err != nil || columns != 0 {
			t.Fatalf("obsolete copy columns: %d, %v", columns, err)
		}
		share, err := store.Load(context.Background(), DefaultApplication, "frost", "copy-key")
		if err != nil || !bytes.Equal(share, []byte{0x12, 0x34}) {
			t.Fatalf("completed copy lost: %v", err)
		}
		if err := store.db.QueryRow("SELECT id, created_at FROM key_shares WHERE key_id = 'copy-key'").
			Scan(&id, &createdAt); err != nil || id != 4 || createdAt != "2026-11-16 15:48:13" {
			t.Fatalf("completed copy metadata = %d, %q, %v", id, createdAt, err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
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
		if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Completed {
			t.Fatalf("completed replay = %v, %v", outcome, err)
		}
		if share, err := store.Load(ctx, DefaultApplication, key.Algorithm, key.KeyID); err != nil || !bytes.Equal(share, []byte{1, 2}) {
			t.Fatalf("legacy share did not survive migration: %v", err)
		}
		key = Key{Algorithm: "frost", SessionID: "pending", KeyID: "key-2", Threshold: 2}
		if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Conflict {
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
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Reserved {
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
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	if outcome, err := store.Reserve(ctx, DefaultApplication, key); err != nil || outcome != Conflict {
		t.Fatalf("incomplete replay = %v, %v", outcome, err)
	}
}
