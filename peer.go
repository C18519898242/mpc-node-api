package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func (n *node) peerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/mpc/{sessionId}", n.receiveMessage)
	return mux
}

func (n *node) receiveMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	var message protocol.Message
	if !sessionIDPattern.MatchString(id) || decodeJSON(w, r, &message, 1<<20) != nil ||
		n.config.Peers[message.From] == "" || !message.IsFor(n.config.PartyID) {
		http.Error(w, "invalid MPC message", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	session := n.sessions[id]
	if session == nil {
		http.Error(w, "waiting for local keygen request", http.StatusNotFound)
		return
	}
	switch session.status.State {
	case "succeeded":
		w.WriteHeader(http.StatusNoContent)
	case "failed":
		http.Error(w, "keygen failed on this node", http.StatusConflict)
	default:
		select {
		case session.incoming <- &message:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "MPC inbox is full", http.StatusServiceUnavailable)
		}
	}
}

func (n *node) sendMessage(ctx context.Context, id string, message *protocol.Message) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	for peer, addr := range n.config.Peers {
		if !message.IsFor(peer) {
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
