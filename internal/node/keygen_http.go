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
	routingID := mpcRoutingID(sessionID)
	if r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID {
		http.Error(w, "invalid MPC routing ID", http.StatusBadRequest)
		return
	}
	if !n.validPlayers(r.Header.Values("MPC-Players")) {
		http.Error(w, "MPC-Players must match the configured node group", http.StatusBadRequest)
		return
	}

	var request generateKeyRequest
	if decodeJSON(w, r, &request, 4096) != nil || request.Curve != curve ||
		(request.Threshold != 1 && request.Threshold != 2) ||
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
	session, err := n.beginStoredKeygen(r.Context(), prefix+sessionID, key, generate)
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

func (n *node) validPlayers(players []string) bool {
	if len(players) != len(n.config.Peers)+1 {
		return false
	}
	seen := make(map[party.ID]bool, len(players))
	for _, player := range players {
		id := party.ID(player)
		_, isPeer := n.config.Peers[id]
		if seen[id] || (id != n.config.PartyID && !isPeer) {
			return false
		}
		seen[id] = true
	}
	return true
}

func (n *node) beginStoredKeygen(ctx context.Context, id string, key keystore.Key, generate generateShare) (*keygenSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.key == key {
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
	}
	if outcome == keystore.Completed {
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
