package keystore

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

func TestConsumeECDSAPresignOnce(t *testing.T) {
	ctx := context.Background()
	store, err := OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := Key{Algorithm: "ecdsa", SessionID: "keygen", KeyID: "key", Threshold: 1}
	if _, err := store.Reserve(ctx, DefaultApplication, key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CountPresign(ctx, DefaultApplication, "key"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("pending key count: %v", err)
	}
	if err := store.DeletePresign(ctx, DefaultApplication, "key"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("pending key delete: %v", err)
	}
	if err := store.Save(ctx, DefaultApplication, key, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveECDSAPresign(ctx, DefaultApplication, "batch", "key", [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveECDSAPresign(ctx, DefaultApplication, "batch", []Presignature{{ID: "first", Share: []byte{1}}, {ID: "second", Share: []byte{2}}, {ID: "third", Share: []byte{3}}}); err != nil {
		t.Fatal(err)
	}
	if count, err := store.CountPresign(ctx, DefaultApplication, "key"); err != nil || count != 3 {
		t.Fatalf("count = %d, %v, want 3", count, err)
	}
	if _, err := store.ConsumeECDSAPresign(ctx, DefaultApplication, "other-key", "first"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-key consumption: %v", err)
	}
	results := make(chan error, 8)
	for range cap(results) {
		go func() {
			share, err := store.ConsumeECDSAPresign(ctx, DefaultApplication, "key", "first")
			if err == nil && (share.ID != "first" || !reflect.DeepEqual(share.Share, []byte{1})) {
				err = errors.New("unexpected consumed share")
			}
			results <- err
		}()
	}
	successes := 0
	for range cap(results) {
		switch err := <-results; {
		case err == nil:
			successes++
		case !errors.Is(err, sql.ErrNoRows):
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumptions = %d, want 1", successes)
	}
	if share, err := store.ConsumeECDSAPresign(ctx, DefaultApplication, "key", ""); err != nil || share.ID != "second" {
		t.Fatalf("automatic selection failed: %v", err)
	}
	if err := store.DeletePresign(ctx, DefaultApplication, "key"); err != nil {
		t.Fatal(err)
	}
	if count, err := store.CountPresign(ctx, DefaultApplication, "key"); err != nil || count != 0 {
		t.Fatalf("remaining count = %d, %v, want 0", count, err)
	}
	if _, err := store.ConsumeECDSAPresign(ctx, DefaultApplication, "key", "third"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("consumed deleted share: %v", err)
	}
}

func TestSQLitePresignBatchIsAtomic(t *testing.T) {
	ctx := context.Background()
	store, err := OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	binding := [32]byte{1}
	if outcome, _, err := store.ReserveECDSAPresign(ctx, DefaultApplication, "batch", "key", binding); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	shares := []Presignature{{ID: "first", Share: []byte{1}}, {ID: "first", Share: []byte{2}}}
	if _, err := store.SaveECDSAPresign(ctx, DefaultApplication, "batch", shares); err == nil {
		t.Fatal("accepted duplicate presignature ID")
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM ecdsa_presignatures").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial batch persisted: count = %d, error = %v", count, err)
	}
	if outcome, _, err := store.ReserveECDSAPresign(ctx, DefaultApplication, "batch", "key", binding); err != nil || outcome != Conflict {
		t.Fatalf("pending replay = %v, %v", outcome, err)
	}
	shares[1].ID = "second"
	if _, err := store.SaveECDSAPresign(ctx, DefaultApplication, "batch", shares); err != nil {
		t.Fatal(err)
	}
	if outcome, ids, err := store.ReserveECDSAPresign(ctx, DefaultApplication, "batch", "key", binding); err != nil || outcome != Completed ||
		!reflect.DeepEqual(ids, []string{"first", "second"}) {
		t.Fatalf("completed replay = %v, %v, %v", outcome, ids, err)
	}
}
