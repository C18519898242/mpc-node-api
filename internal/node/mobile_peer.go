package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type mobileMailboxKey struct {
	applicationID string
	peer          party.ID
	route         string
}

func mobileRoute(route string) bool {
	if _, _, ok := splitPresignRoute(route); ok {
		return true
	}
	for _, prefix := range []string{ecdsaSessionPrefix, frostSessionPrefix, ecdsaSignPrefix, frostSignPrefix} {
		if sid, ok := strings.CutPrefix(route, prefix); ok {
			return memorySessionPattern.MatchString(sid)
		}
	}
	return false
}

func (n *node) enqueueMobile(ctx context.Context, peer party.ID, path string, body []byte) error {
	app := applicationID(ctx)
	route, ok := strings.CutPrefix(path, "/internal/mpc/")
	if !ok || !mobileRoute(route) || n.config.MobilePeers[peer] != app {
		return errors.New("unsupported or unauthorized mobile operation")
	}
	key := mobileMailboxKey{app, peer, route}
	n.mu.Lock()
	for key, box := range n.mobileMailboxes {
		if time.Now().After(box.expires) {
			delete(n.mobileMailboxes, key)
		}
	}
	box := n.mobileMailboxes[key]
	if box == nil {
		if len(n.mobileMailboxes) >= 128 {
			n.mu.Unlock()
			return errors.New("too many mobile sessions")
		}
		box = newMobileMailbox()
		n.mobileMailboxes[key] = box
	}
	n.mu.Unlock()
	return box.enqueue(body)
}

func (n *node) registerMobileRoutes(mux *http.ServeMux) {
	if len(n.config.MobilePeers) == 0 {
		return
	}
	for _, p := range []nodeProtocol{cmpProtocol{n}, frostProtocol{n}} {
		base := "POST /internal/mobile/" + p.Info().ID + "/keys"
		api := p.handlers()
		mux.HandleFunc(base, n.authorizeMobile(api.generateKey, true))
		mux.HandleFunc(base+"/{keyID}/sign", n.authorizeMobile(api.sign, true))
		mux.HandleFunc(base+"/{keyID}/{count}/presiggen", n.authorizeMobile(n.logRequest("presiggen", p.Info().ID, api.generatePresign), true))
		mux.HandleFunc(base+"/{keyID}/signwithpresig", n.authorizeMobile(n.logRequest("signwithpresig", p.Info().ID, api.signWithPresign), false))
	}
	mux.HandleFunc("POST /internal/mobile/poll", n.authorizeMobile(n.pollMobile, false))
}

func (n *node) authorizeMobile(handler http.HandlerFunc, control bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peer := n.verifiedPeer(r)
		allowed := n.config.MobilePeers[peer]
		app := n.authenticateAPIKey(r)
		if allowed == "" || app == "" || app != allowed {
			http.Error(w, "unauthorized mobile peer", http.StatusForbidden)
			return
		}
		if control && !slices.Contains(r.Header.Values("MPC-Players"), string(peer)) {
			http.Error(w, "mobile player must participate", http.StatusBadRequest)
			return
		}
		handler(w, withApplication(r, app))
	}
}

func (n *node) pollMobile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SessionID string `json:"sessionID"`
		Ack       uint64 `json:"ack"`
	}
	if decodeJSON(w, r, &request, 4096) != nil || !mobileRoute(request.SessionID) {
		http.Error(w, "invalid mobile poll", http.StatusBadRequest)
		return
	}
	key := mobileMailboxKey{applicationID(r.Context()), n.verifiedPeer(r), request.SessionID}
	n.mu.Lock()
	box := n.mobileMailboxes[key]
	n.mu.Unlock()
	if box == nil || time.Now().After(box.expires) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	message, err := box.poll(ctx, request.Ack)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		http.Error(w, "invalid mobile acknowledgment", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(message)
}
