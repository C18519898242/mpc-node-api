package node

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

func TestDeleteLocalKeyShare(t *testing.T) {
	ctx := context.Background()
	keyID := "delete-key"
	algorithms := []string{"ecdsa", "frost"}
	keys := make(map[string]keystore.Key)
	stores := make([]*keystore.SQLite, 2)
	for i, player := range []string{"1", "2"} {
		store, err := keystore.OpenNodeSQLite(t.TempDir(), player)
		if err != nil {
			t.Fatal(err)
		}
		stores[i] = store
		t.Cleanup(func() { _ = store.Close() })
		for _, algorithm := range algorithms {
			key := keystore.Key{Algorithm: algorithm, SessionID: "old-keygen", KeyID: keyID, Threshold: 1}
			keys[algorithm] = key
			if outcome, err := store.Reserve(ctx, keystore.DefaultApplication, key); err != nil || outcome != keystore.Reserved {
				t.Fatalf("reserve %s: %v, %v", algorithm, outcome, err)
			}
			if err := store.Save(ctx, keystore.DefaultApplication, key, []byte("test share")); err != nil {
				t.Fatal(err)
			}
			reserve, save := store.ReserveECDSAPresign, store.SaveECDSAPresign
			if algorithm == "frost" {
				reserve, save = store.ReserveFROSTPresign, store.SaveFROSTPresign
			}
			if _, _, err := reserve(ctx, defaultApplication, "old-batch", keyID, [32]byte{}); err != nil {
				t.Fatal(err)
			}
			if _, err := save(ctx, defaultApplication, "old-batch", []keystore.Presignature{{ID: "presign", Share: []byte("test")}}); err != nil {
				t.Fatal(err)
			}
			op := keystore.Reshare{Algorithm: algorithm, SessionID: "old-reshare", KeyID: keyID}
			if _, _, err := store.ReserveReshare(ctx, keystore.DefaultApplication, op); err != nil {
				t.Fatal(err)
			}
			if err := store.StageReshare(ctx, keystore.DefaultApplication, op, [32]byte{}, []byte("candidate")); err != nil {
				t.Fatal(err)
			}
		}
	}
	n := newNode(config.Config{})
	n.keys = stores[0]
	other := keystore.Key{Algorithm: "ecdsa", SessionID: "copy.elsewhere", KeyID: "independent-copy", Threshold: 1}
	if outcome, err := stores[0].Reserve(ctx, keystore.DefaultApplication, other); err != nil || outcome != keystore.Reserved {
		t.Fatalf("reserve independent copy: %v, %v", outcome, err)
	}
	if err := stores[0].Save(ctx, keystore.DefaultApplication, other, []byte("independent share")); err != nil {
		t.Fatal(err)
	}
	for algorithm, key := range keys {
		n.sessions[sessionKey{defaultApplication, algorithm + ".old-keygen"}] = &keygenSession{key: key}
	}
	call := func(path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, strings.NewReader(body)))
		return w
	}
	for _, tc := range []struct {
		path, body string
		status     int
	}{{"/key/delete-key", "{}", 400}, {"/key/missing", "", 404}} {
		if got := call(tc.path, tc.body); got.Code != tc.status {
			t.Fatalf("delete %s: got %d, want %d", tc.path, got.Code, tc.status)
		}
	}
	release := n.lockKeyOperation(httptest.NewRecorder(), defaultApplication, "frost", keyID, false)
	if got := call("/key/delete-key", ""); got.Code != 409 {
		t.Fatalf("delete while key is in use: %d", got.Code)
	}
	release()
	if got := call("/key/delete-key", ""); got.Code != 204 || got.Body.Len() != 0 {
		t.Fatalf("delete got %d, want empty 204", got.Code)
	}
	if got := call("/key/delete-key", ""); got.Code != 404 {
		t.Fatalf("repeat delete got %d", got.Code)
	}
	for algorithm, key := range keys {
		if _, err := stores[0].Load(ctx, keystore.DefaultApplication, algorithm, keyID); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("local %s share remains: %v", algorithm, err)
		}
		if _, err := stores[1].Load(ctx, keystore.DefaultApplication, algorithm, keyID); err != nil {
			t.Fatalf("other node's %s share changed: %v", algorithm, err)
		}
		if actual, err := stores[0].Reserve(ctx, keystore.DefaultApplication, key); err != nil || actual != keystore.Conflict {
			t.Fatalf("deleted %s key could be recreated: %v, %v", algorithm, actual, err)
		}
		consume := stores[0].ConsumeECDSAPresign
		if algorithm == "frost" {
			consume = stores[0].ConsumeFROSTPresign
		}
		if _, err := consume(ctx, defaultApplication, keyID, "presign"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("local %s presign remains: %v", algorithm, err)
		}
		op := keystore.Reshare{Algorithm: algorithm, SessionID: "old-reshare", KeyID: keyID}
		if _, err := stores[0].LoadReshare(ctx, keystore.DefaultApplication, op); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("pending %s reshare remains: %v", algorithm, err)
		}
		if n.sessions[sessionKey{defaultApplication, algorithm + ".old-keygen"}] != nil {
			t.Fatalf("deleted %s keygen result remains cached", algorithm)
		}
	}
	if count, err := stores[1].CountPresign(ctx, keystore.DefaultApplication, keyID); err != nil || count != 2 {
		t.Fatalf("other node's presignatures changed: %d, %v", count, err)
	}
	if _, err := stores[0].Load(ctx, keystore.DefaultApplication, other.Algorithm, other.KeyID); err != nil {
		t.Fatalf("independent copy changed: %v", err)
	}
}
