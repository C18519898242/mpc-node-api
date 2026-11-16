package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func (n *node) peerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/mpc/{sessionId}", n.receiveMessage)
	mux.HandleFunc("POST /internal/reshare/{sessionId}/ready", n.reshareReady)
	return mux
}

func (n *node) receiveMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	batchID, slot, presign := splitPresignRoute(id)
	var message protocol.Message
	if !validPeerSessionID(id) || decodeJSON(w, r, &message, 1<<20) != nil ||
		n.config.Peers[message.From] == "" || !message.IsFor(n.config.PartyID) {
		http.Error(w, "invalid MPC message", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	session := n.sessions[batchID]
	if session == nil {
		http.Error(w, "waiting for local MPC request", http.StatusNotFound)
		return
	}
	switch session.status.State {
	case "succeeded":
		w.WriteHeader(http.StatusNoContent)
	case "failed":
		http.Error(w, "MPC session failed on this node", http.StatusConflict)
	default:
		incoming := session.incoming
		if presign {
			if slot >= len(session.presignInboxes) {
				http.Error(w, "invalid presign slot", http.StatusBadRequest)
				return
			}
			incoming = session.presignInboxes[slot]
		}
		select {
		case incoming <- &message:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "MPC inbox is full", http.StatusServiceUnavailable)
		}
	}
}

func validPeerSessionID(id string) bool {
	if _, _, ok := parseReshareRoute(id); ok {
		return true
	}
	if strings.HasPrefix(id, ecdsaPresignPrefix) || strings.HasPrefix(id, frostPresignPrefix) {
		_, _, ok := splitPresignRoute(id)
		return ok
	}
	if sessionID, ok := strings.CutPrefix(id, frostSignPrefix); ok {
		return memorySessionPattern.MatchString(sessionID)
	}
	if sessionID, ok := strings.CutPrefix(id, ecdsaSignPrefix); ok {
		return memorySessionPattern.MatchString(sessionID)
	}
	if sessionID, ok := strings.CutPrefix(id, ecdsaSessionPrefix); ok {
		return memorySessionPattern.MatchString(sessionID)
	}
	if sessionID, ok := strings.CutPrefix(id, frostSessionPrefix); ok {
		return memorySessionPattern.MatchString(sessionID)
	}
	return sessionIDPattern.MatchString(id)
}

func splitPresignRoute(id string) (batchID string, slot int, ok bool) {
	prefix := ecdsaPresignPrefix
	if strings.HasPrefix(id, frostPresignPrefix) {
		prefix = frostPresignPrefix
	}
	if !strings.HasPrefix(id, prefix) {
		return id, 0, false
	}
	batchID, rawSlot, ok := strings.Cut(id[len(prefix):], ".")
	index, err := strconv.ParseUint(rawSlot, 10, 8)
	return prefix + batchID, int(index), ok && err == nil && index < maxPresignCount && memorySessionPattern.MatchString(batchID)
}

func (n *node) sendMessage(ctx context.Context, id string, message *protocol.Message, participants party.IDSlice) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	for peer, addr := range n.config.Peers {
		if !message.IsFor(peer) || (participants != nil && !participants.Contains(peer)) {
			continue
		}
		url := "http://" + addr + "/internal/mpc/" + id
		if err := n.deliverMessage(ctx, url, body); err != nil {
			return fmt.Errorf("send to node %s: %w", peer, err)
		}
	}
	return nil
}

func (n *node) deliverMessage(ctx context.Context, url string, body []byte) error {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := n.client.Do(request)
		if err == nil {
			response.Body.Close()
			switch response.StatusCode {
			case http.StatusNoContent:
				return nil
			case http.StatusNotFound, http.StatusServiceUnavailable:
			default:
				return fmt.Errorf("peer returned HTTP %d", response.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
