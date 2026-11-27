package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	peerRetryInitial  = 100 * time.Millisecond
	peerRetryMax      = 2 * time.Second
	peerRetryBudget   = 30 * time.Second
	peerRetryAttempts = 20
)

func nextPeerRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return peerRetryInitial
	}
	delay *= 2
	if delay > peerRetryMax {
		return peerRetryMax
	}
	return delay
}

func jitterPeerRetryDelay(delay time.Duration) time.Duration {
	spread := int64(delay) / 5
	if spread <= 0 {
		return delay
	}
	return delay - time.Duration(spread) + time.Duration(rand.Int64N(spread*2+1))
}

func (n *node) peerHandler() http.Handler {
	mux := http.NewServeMux()
	n.registerPeerRoute(mux, "/internal/mpc/{sessionId}", n.receiveMessage)
	n.registerPeerRoute(mux, "/internal/reshare/{sessionId}/ready", n.reshareReady)
	n.registerPeerRoute(mux, "/internal/keycopy/{sessionId}/ready", n.keyCopyReady)
	n.registerMobileRoutes(mux)
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
		if app := n.config.MobilePeers[n.verifiedPeer(r)]; app != "" && app != id {
			http.NotFound(w, r)
			return
		}
		handler(w, withApplication(r, id))
	})
}

func (n *node) receiveMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	var message protocol.Message
	if !validPeerSessionID(id) || decodeJSON(w, r, &message, 1<<20) != nil ||
		!n.knownPeer(message.From) || !message.IsFor(n.config.PartyID) {
		http.Error(w, "invalid MPC message", http.StatusBadRequest)
		return
	}
	if n.config.MPCTLS != nil && n.verifiedPeer(r) != message.From {
		http.Error(w, "MPC sender does not match certificate identity", http.StatusForbidden)
		return
	}
	n.acceptMessage(w, r, id, &message)
}

func (n *node) acceptMessage(w http.ResponseWriter, r *http.Request, id string, message *protocol.Message) {
	batchID, slot, presign := splitPresignRoute(id)
	walletID, walletSlot, wallet := splitWalletRoute(id)
	if wallet {
		batchID = walletID
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
		if session.rsaBits != 0 && !session.players.Contains(message.From) {
			http.Error(w, "unexpected RSA keygen player", http.StatusBadRequest)
			return
		}
		if wallet {
			if !session.players.Contains(message.From) || n.config.Peers[message.From] == "" {
				http.Error(w, "unexpected wallet player", http.StatusBadRequest)
				return
			}
			if walletSlot >= 0 {
				incoming = session.walletInboxes[walletSlot]
			}
		}
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
		case incoming <- message:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "MPC inbox is full", http.StatusServiceUnavailable)
		}
	}
}

func validPeerSessionID(id string) bool {
	if _, _, ok := splitWalletRoute(id); ok {
		return true
	}
	if _, _, ok := parseKeyTransferRoute(id); ok {
		return true
	}
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
	if sessionID, ok := strings.CutPrefix(id, rsaSessionPrefix); ok {
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
	for _, peer := range n.configuredPlayers() {
		if peer == n.config.PartyID || !message.IsFor(peer) || (participants != nil && !participants.Contains(peer)) {
			continue
		}
		if err := n.deliverMessage(ctx, peer, "/internal/mpc/"+id, body); err != nil {
			return fmt.Errorf("send to node %s: %w", peer, err)
		}
	}
	return nil
}

func (n *node) deliverMessage(ctx context.Context, peer party.ID, path string, body []byte) error {
	if app := n.config.MobilePeers[peer]; app != "" {
		return n.enqueueMobile(ctx, peer, path, body)
	}
	client, scheme := n.client, "http"
	if n.config.MPCTLS != nil {
		client, scheme = n.peerClients[peer], "https"
		if client == nil {
			return errors.New("MPC peer has no TLS configuration")
		}
	}
	if n.config.RESTAuth != nil || n.embedded {
		path = peerApplicationPath + applicationID(ctx) + path
	}
	endpoint := url.URL{Scheme: scheme, Host: n.config.Peers[peer], Path: path}
	retryCtx, cancel := context.WithTimeout(ctx, peerRetryBudget)
	defer cancel()
	delay := peerRetryInitial
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := retryCtx.Err(); err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(retryCtx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
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
				lastErr = fmt.Errorf("peer returned HTTP %d", response.StatusCode)
			default:
				return fmt.Errorf("peer returned HTTP %d", response.StatusCode)
			}
		} else {
			lastErr = err
		}
		if attempt >= peerRetryAttempts && retryCtx.Err() == nil {
			return fmt.Errorf("peer delivery failed after %d attempts: %w", attempt, lastErr)
		}
		select {
		case <-retryCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("peer delivery retry budget exceeded: %w: %w", retryCtx.Err(), lastErr)
		case <-time.After(jitterPeerRetryDelay(delay)):
		}
		delay = nextPeerRetryDelay(delay)
	}
}
