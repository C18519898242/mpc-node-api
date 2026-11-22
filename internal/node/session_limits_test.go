package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

func TestBeginSignRejectsWhenSessionMapFull(t *testing.T) {
	n := newNode(config.Config{})
	for i := 0; i < maxSessions; i++ {
		n.sessions[sessionKey{defaultApplication, fmt.Sprintf("session-%d", i)}] = &keygenSession{}
	}
	_, err := n.beginSign(context.Background(), "frost-sign.overflow", [32]byte{}, func(context.Context, *keygenSession) ([]byte, error) {
		return nil, nil
	})
	if !errors.Is(err, errTooManySessions) {
		t.Fatalf("beginSign error = %v, want errTooManySessions", err)
	}
	if len(n.sessions) != maxSessions {
		t.Fatalf("session count = %d, want %d", len(n.sessions), maxSessions)
	}
}

func TestExpiredSignSessionCannotRunAgain(t *testing.T) {
	n := newNode(config.Config{PartyID: "1"})
	store, err := keystore.OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	n.keys = store
	var calls atomic.Int32
	run := func(context.Context, *keygenSession) ([]byte, error) { calls.Add(1); return []byte("signature"), nil }
	first, err := n.beginSign(t.Context(), "frost-sign.once", [32]byte{1}, run)
	if err != nil {
		t.Fatal(err)
	}
	<-first.done
	// Retry while cached returns the existing result without re-running the worker.
	cached, err := n.beginSign(t.Context(), "frost-sign.once", [32]byte{1}, run)
	if err != nil || cached != first {
		t.Fatalf("cached replay = %v, %v", cached, err)
	}
	if first.incoming != nil {
		t.Fatal("completed session retains its inbox")
	}
	// Expire the result cache, preserving the durable used-ID reservation.
	n.mu.Lock()
	first.completedAt = time.Now().Add(-sessionRetention)
	n.pruneSessionsLocked(time.Now())
	n.mu.Unlock()
	replayed, err := n.beginSign(t.Context(), "frost-sign.once", [32]byte{2}, run)
	if replayed != nil {
		<-replayed.done
		t.Fatal("expired session ID started another signing operation")
	}
	if calls.Load() != 1 {
		t.Fatal("signing worker restarted")
	}
	if err != nil {
		t.Fatal(err)
	}
	// A process restart loses the whole cache, but must still reject the old ID.
	restarted := newNode(config.Config{PartyID: "1"})
	restarted.keys = store
	if replayed, err := restarted.beginSign(t.Context(), "frost-sign.once", [32]byte{1}, run); err != nil || replayed != nil {
		t.Fatalf("restart accepted old signing session: %v, %v", replayed, err)
	}
}

func TestSessionCacheExpiresCompletedOnly(t *testing.T) {
	n := newNode(config.Config{})
	now := time.Now()
	n.sessions[sessionKey{"a", "expired"}] = &keygenSession{completedAt: now.Add(-sessionRetention)}
	n.sessions[sessionKey{"a", "recent"}] = &keygenSession{completedAt: now.Add(-time.Second)}
	n.sessions[sessionKey{"a", "running"}] = &keygenSession{}
	n.pruneSessionsLocked(now)
	if len(n.sessions) != 2 || n.sessions[sessionKey{"a", "expired"}] != nil || n.sessions[sessionKey{"a", "running"}] == nil {
		t.Fatal("expiry removed active/recent sessions or retained expired result")
	}
}

func TestSessionAdmissionLimitsAndEvictsResults(t *testing.T) {
	t.Run("application active quota", func(t *testing.T) {
		n := newNode(config.Config{})
		for i := 0; i < maxAppActiveSessions; i++ {
			n.sessions[sessionKey{"a", fmt.Sprint(i)}] = &keygenSession{}
		}
		if !errors.Is(n.checkSessionCapacityLocked("a"), errTooManySessions) {
			t.Fatal("application limit not enforced")
		}
		if err := n.checkSessionCapacityLocked("b"); err != nil {
			t.Fatal("one application blocked another", err)
		}
	})
	t.Run("global active quota", func(t *testing.T) {
		n := newNode(config.Config{})
		for i := 0; i < maxActiveSessions; i++ {
			n.sessions[sessionKey{fmt.Sprint(i), "running"}] = &keygenSession{}
		}
		if !errors.Is(n.checkSessionCapacityLocked("new"), errTooManySessions) {
			t.Fatal("global limit not enforced")
		}
	})
	for _, appLimit := range []bool{true, false} {
		t.Run(fmt.Sprint("evict completed, appLimit=", appLimit), func(t *testing.T) {
			n := newNode(config.Config{})
			limit := maxSessions
			if appLimit {
				limit = maxAppSessions
			}
			now := time.Now()
			oldest := sessionKey{"a", "0"}
			for i := 0; i < limit; i++ {
				app := "a"
				if !appLimit && i > 0 {
					app = fmt.Sprint(i)
				}
				n.sessions[sessionKey{app, fmt.Sprint(i)}] = &keygenSession{completedAt: now.Add(-time.Minute + time.Duration(i))}
			}
			// Keep an active session alongside the completed results.
			n.sessions[sessionKey{"a", "running"}] = &keygenSession{}
			if err := n.checkSessionCapacityLocked("a"); err != nil {
				t.Fatal(err)
			}
			if n.sessions[oldest] != nil || n.sessions[sessionKey{"a", "running"}] == nil {
				t.Fatal("wrong session evicted")
			}
			if len(n.sessions) >= limit {
				t.Fatal("no room left for new session")
			}
		})
	}
}

func TestLegacyMarkerCleanupPreservesReplayProtection(t *testing.T) {
	dir := t.TempDir()
	n := newNode(config.Config{PartyID: "1", DataDir: dir})
	store, err := keystore.OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	n.keys = store
	id := "0123456789abcdef0123456789abcdef"
	marker := n.sharePath(defaultApplication, id) + ".started"
	tmp := filepath.Join(dir, ".share-abandoned")
	for _, path := range []string{marker, tmp} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-legacyArtifactRetention - time.Hour)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.cleanupLegacyArtifacts(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{marker, tmp} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("artifact retained: %s: %v", path, err)
		}
	}
	status, err := n.loadKeygenStatus(defaultApplication, id)
	if err != nil || status.State != "failed" {
		t.Fatalf("old attempt forgotten: %+v %v", status, err)
	}
	if err := n.recordKeygenAttempt(t.Context(), defaultApplication, id); !errors.Is(err, os.ErrExist) {
		t.Fatalf("old attempt reused: %v", err)
	}
}
