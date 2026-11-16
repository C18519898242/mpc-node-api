package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

var (
	memorySessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	keyIDPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
)

type generateKeyRequest struct {
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyID     string `json:"keyID"`
}

type generateKeyResponse struct {
	KeyID string `json:"keyID"`
}

type generateShare func(context.Context, string, *keygenSession) ([]byte, error)

func (n *node) generateKey(w http.ResponseWriter, r *http.Request, prefix, curve string, generate generateShare) {
	sessionID := r.Header.Get("MPC-SessionID")
	if !memorySessionPattern.MatchString(sessionID) {
		http.Error(w, "invalid MPC-SessionID", http.StatusBadRequest)
		return
	}
	players := n.signingPlayers(w, r, sessionID)
	if players == nil {
		return
	}

	var request generateKeyRequest
	if decodeJSON(w, r, &request, 4096) != nil || request.Curve != curve ||
		(request.Threshold < 1 || request.Threshold >= len(players)) ||
		(request.KeyID != "" && !keyIDPattern.MatchString(request.KeyID)) {
		http.Error(w, "invalid "+curve+" keygen parameters", http.StatusBadRequest)
		return
	}
	if request.KeyID == "" {
		digest := sha256.Sum256([]byte(prefix + sessionID))
		request.KeyID = base64.RawURLEncoding.EncodeToString(digest[:21])
	}
	key := keystore.Key{
		Algorithm: prefix[:len(prefix)-1], SessionID: sessionID, KeyID: request.KeyID, Threshold: request.Threshold,
	}
	release := n.lockKeyOperation(w, key.Algorithm, key.KeyID, false)
	if release == nil {
		return
	}
	defer release()
	session, err := n.beginStoredKeygen(r.Context(), prefix+sessionID, key, players, generate)
	if err != nil {
		http.Error(w, "could not reserve keygen", http.StatusInternalServerError)
		return
	}
	if session == nil {
		http.Error(w, "session or key ID already used with different parameters", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		// The worker can still write a key after the client disconnects.
		<-session.done
		return
	case <-session.done:
		if session.status.State != "succeeded" {
			http.Error(w, curve+" keygen failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(generateKeyResponse{KeyID: session.key.KeyID})
	}
}

func mpcRoutingID(sessionID string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sessionID))
	return fmt.Sprintf("%016x", h.Sum64()&0x7fffffffffffffff)
}

func (n *node) beginStoredKeygen(ctx context.Context, id string, key keystore.Key, players party.IDSlice, generate generateShare) (*keygenSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.key == key && slices.Equal(session.players, players) {
			return session, nil
		}
		return nil, nil
	}
	outcome, err := n.keys.Reserve(ctx, key)
	if err != nil || outcome == keystore.Conflict {
		return nil, err
	}
	session := &keygenSession{
		incoming: make(chan *protocol.Message, 32),
		status:   keygenStatus{State: "running"},
		done:     make(chan struct{}),
		key:      key,
		players:  players,
	}
	if outcome == keystore.Completed {
		storedPlayers, err := n.keyPlayers(ctx, key.Algorithm, key.KeyID)
		if err != nil || !slices.Equal(storedPlayers, players) {
			return nil, err
		}
		session.status.State = "succeeded"
		close(session.done)
		return session, nil
	}
	n.sessions[id] = session
	go n.runStoredKeygen(id, session, generate)
	return session, nil
}

func (n *node) runStoredKeygen(id string, session *keygenSession, generate generateShare) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
	defer cancel()
	share, err := generate(ctx, id, session)
	defer clear(share)
	stage := "protocol"
	if err == nil {
		stage = "storage"
		err = n.keys.Save(ctx, session.key, share)
	}
	n.logMPCResult("keygen", session.key.Algorithm, stage, start, err)
	n.mu.Lock()
	defer n.mu.Unlock()
	defer close(session.done)
	if err != nil {
		session.status.State = "failed"
		return
	}
	session.status.State = "succeeded"
}
