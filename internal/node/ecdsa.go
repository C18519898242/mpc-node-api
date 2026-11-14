package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"regexp"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const ecdsaSessionPrefix = "ecdsa."

var (
	ecdsaSessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	ecdsaKeyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
)

type ecdsaKeyRequest struct {
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyID     string `json:"keyID"`
}

type ecdsaKeyResponse struct {
	KeyID string `json:"keyID"`
}

func (n *node) generateECDSAKey(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("MPC-SessionID")
	if !ecdsaSessionPattern.MatchString(sessionID) {
		http.Error(w, "invalid MPC-SessionID", http.StatusBadRequest)
		return
	}
	routingID := ecdsaRoutingID(sessionID)
	if r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID {
		http.Error(w, "invalid MPC routing ID", http.StatusBadRequest)
		return
	}
	if !n.validECDSAPlayers(r.Header.Values("MPC-Players")) {
		http.Error(w, "MPC-Players must match the configured node group", http.StatusBadRequest)
		return
	}

	var request ecdsaKeyRequest
	if decodeJSON(w, r, &request, 4096) != nil || request.Curve != "secp256k1" ||
		(request.Threshold != 1 && request.Threshold != 2) ||
		(request.KeyID != "" && !ecdsaKeyIDPattern.MatchString(request.KeyID)) {
		http.Error(w, "invalid ECDSA keygen parameters", http.StatusBadRequest)
		return
	}
	if request.KeyID == "" {
		digest := sha256.Sum256([]byte(ecdsaSessionPrefix + sessionID))
		request.KeyID = base64.RawURLEncoding.EncodeToString(digest[:21])
	}
	session := n.beginECDSAKeygen(ecdsaSessionPrefix+sessionID, request)
	if session == nil {
		http.Error(w, "session or key ID already used with different parameters", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		return
	case <-session.done:
		if session.share == nil {
			http.Error(w, "ECDSA keygen failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ecdsaKeyResponse{KeyID: session.keyID})
	}
}

func ecdsaRoutingID(sessionID string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sessionID))
	return fmt.Sprintf("%016x", h.Sum64()&0x7fffffffffffffff)
}

func (n *node) validECDSAPlayers(players []string) bool {
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

func (n *node) beginECDSAKeygen(id string, request ecdsaKeyRequest) *keygenSession {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.keyID == request.KeyID && session.threshold == request.Threshold {
			return session
		}
		return nil
	}
	if _, exists := n.ecdsaKeys[request.KeyID]; exists {
		return nil
	}
	session := &keygenSession{
		incoming:  make(chan *protocol.Message, 32),
		status:    keygenStatus{State: "running"},
		done:      make(chan struct{}),
		keyID:     request.KeyID,
		threshold: request.Threshold,
	}
	n.sessions[id] = session
	n.ecdsaKeys[request.KeyID] = struct{}{}
	go n.runECDSAKeygen(id, session)
	return session
}

func (n *node) runECDSAKeygen(id string, session *keygenSession) {
	ctx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
	defer cancel()
	// A key ID mismatch must also change the CMP session identity.
	protocolID := sha256.Sum256([]byte(id + ":" + session.keyID))
	share, err := n.executeKeygen(ctx, id, protocolID[:], session.threshold, session.incoming)
	n.mu.Lock()
	defer n.mu.Unlock()
	defer close(session.done)
	if err != nil {
		log.Printf("node %s: ECDSA keygen %s failed: %v", n.config.PartyID, id, err)
		session.status.State = "failed"
		return
	}
	session.share = share
	session.status.State = "succeeded"
}
