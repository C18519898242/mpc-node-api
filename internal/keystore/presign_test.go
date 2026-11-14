package keystore

import (
	"context"
	"reflect"
	"testing"
)

func TestSQLitePresignBatchIsAtomic(t *testing.T) {
	ctx := context.Background()
	store, err := OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	binding := [32]byte{1}
	if outcome, _, err := store.ReserveECDSAPresign(ctx, "batch", "key", binding); err != nil || outcome != Reserved {
		t.Fatalf("reserve = %v, %v", outcome, err)
	}
	shares := []Presignature{{ID: "first", Share: []byte{1}}, {ID: "first", Share: []byte{2}}}
	if _, err := store.SaveECDSAPresign(ctx, "batch", shares); err == nil {
		t.Fatal("accepted duplicate presignature ID")
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM ecdsa_presignatures").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial batch persisted: count = %d, error = %v", count, err)
	}
	if outcome, _, err := store.ReserveECDSAPresign(ctx, "batch", "key", binding); err != nil || outcome != Conflict {
		t.Fatalf("pending replay = %v, %v", outcome, err)
	}
	shares[1].ID = "second"
	if _, err := store.SaveECDSAPresign(ctx, "batch", shares); err != nil {
		t.Fatal(err)
	}
	if outcome, ids, err := store.ReserveECDSAPresign(ctx, "batch", "key", binding); err != nil || outcome != Completed ||
		!reflect.DeepEqual(ids, []string{"first", "second"}) {
		t.Fatalf("completed replay = %v, %v, %v", outcome, ids, err)
	}
}
