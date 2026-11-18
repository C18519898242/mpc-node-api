package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func (n *node) signingPlayers(w http.ResponseWriter, r *http.Request, sessionID string) party.IDSlice {
	routingID := mpcRoutingID(sessionID)
	if r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID {
		http.Error(w, "invalid MPC routing ID", http.StatusBadRequest)
		return nil
	}
	signers := make(party.IDSlice, 0, len(n.config.Peers)+1)
	for _, player := range r.Header.Values("MPC-Players") {
		id := party.ID(player)
		_, peer := n.config.Peers[id]
		if (id != n.config.PartyID && !peer) || slices.Contains(signers, id) {
			http.Error(w, "invalid signing players", http.StatusBadRequest)
			return nil
		}
		signers = append(signers, id)
	}
	slices.Sort(signers)
	if len(signers) < 2 || !slices.Contains(signers, n.config.PartyID) {
		http.Error(w, "signing players must include this node and at least one peer", http.StatusBadRequest)
		return nil
	}

	return signers
}

type signOperation func(context.Context, *keygenSession) ([]byte, error)

func (n *node) serveSignature(w http.ResponseWriter, r *http.Request, id, keyID string, signers party.IDSlice, path []uint32, message []byte, algorithm string, run signOperation) {
	binding, err := json.Marshal(struct {
		SessionID string
		KeyID     string
		Signers   party.IDSlice
		Path      []uint32
		Digest    []byte
	}{id, keyID, signers, append([]uint32(nil), path...), message})
	if err != nil {
		http.Error(w, "could not encode signing parameters", http.StatusInternalServerError)
		return
	}
	session := n.beginSign(r.Context(), id, sha256.Sum256(binding), run)
	if session == nil {
		http.Error(w, "session ID already used with different signing parameters", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		// Keep the key locked until the detached MPC worker finishes.
		<-session.done
		return
	case <-session.done:
		if session.status.State != "succeeded" {
			http.Error(w, algorithm+" signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Signature []byte `json:"signature"`
		}{session.signature})
	}
}

func (n *node) beginSign(ctx context.Context, id string, binding [32]byte, run signOperation) *keygenSession {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[sessionKey{applicationID(ctx), id}]; session != nil {
		if session.signBinding == binding {
			return session
		}
		return nil
	}
	session := &keygenSession{
		incoming:    make(chan *protocol.Message, 32),
		status:      keygenStatus{State: "running"},
		done:        make(chan struct{}),
		signBinding: binding,
	}
	n.sessions[sessionKey{applicationID(ctx), id}] = session
	go n.runSign(context.WithoutCancel(ctx), id, session, run)
	return session
}

func (n *node) runSign(ctx context.Context, id string, session *keygenSession, run signOperation) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, keygenTimeout)
	defer cancel()
	signature, err := run(ctx, session)
	algorithm, _, _ := strings.Cut(id, "-sign.")
	n.logMPCResult("sign", algorithm, "protocol", start, err)
	n.mu.Lock()
	defer n.mu.Unlock()
	defer close(session.done)
	if err != nil {
		session.status.State = "failed"
		return
	}
	session.signature = signature
	session.status.State = "succeeded"
}
