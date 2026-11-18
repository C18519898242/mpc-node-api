package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func (n *node) peerHandler() http.Handler {
	mux := http.NewServeMux()
	n.registerPeerRoute(mux, "/internal/mpc/{sessionId}", n.receiveMessage)
	n.registerPeerRoute(mux, "/internal/reshare/{sessionId}/ready", n.reshareReady)
	n.registerPeerRoute(mux, "/internal/keycopy/{sessionId}/ready", n.keyCopyReady)
	if n.config.MPCTLS == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.verifiedPeer(r) == "" {
			http.Error(w, "unverified MPC peer", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (n *node) registerPeerRoute(mux *http.ServeMux, path string, handler http.HandlerFunc) {
	if n.config.RESTAuth == nil {
		mux.HandleFunc("POST "+path, handler)
		return
	}
	mux.HandleFunc("POST "+peerApplicationPath+"{applicationID}"+path, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("applicationID")
		if _, allowed := n.applications[id]; !allowed {
			http.NotFound(w, r)
			return
		}
		handler(w, withApplication(r, id))
	})
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
	if n.config.MPCTLS != nil && n.verifiedPeer(r) != message.From {
		http.Error(w, "MPC sender does not match certificate identity", http.StatusForbidden)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	session := n.sessions[sessionKey{applicationID(r.Context()), batchID}]
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
		if session.copyIncoming != nil {
			if !session.players.Contains(message.From) {
				http.Error(w, "unexpected key copy player", http.StatusBadRequest)
				return
			}
			if strings.HasPrefix(message.Protocol, "keycopy/") {
				incoming = session.copyIncoming
			}
		}
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
	if _, _, ok := parseKeyCopyRoute(id); ok {
		return true
	}
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
	for peer := range n.config.Peers {
		if !message.IsFor(peer) || (participants != nil && !participants.Contains(peer)) {
			continue
		}
		if err := n.deliverMessage(ctx, peer, "/internal/mpc/"+id, body); err != nil {
			return fmt.Errorf("send to node %s: %w", peer, err)
		}
	}
	return nil
}

func (n *node) deliverMessage(ctx context.Context, peer party.ID, path string, body []byte) error {
	client, scheme := n.client, "http"
	if n.config.MPCTLS != nil {
		client, scheme = n.peerClients[peer], "https"
		if client == nil {
			return errors.New("MPC peer has no TLS configuration")
		}
	}
	if n.config.RESTAuth != nil {
		path = peerApplicationPath + applicationID(ctx) + path
	}
	endpoint := url.URL{Scheme: scheme, Host: n.config.Peers[peer], Path: path}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return err
		}
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
