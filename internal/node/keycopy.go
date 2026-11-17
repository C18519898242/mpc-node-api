package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type keyCopyRequest struct {
	generateKeyRequest
	SchnorrVariant string `json:"schnorr_variant"`
}

func (n *node) keyCopy(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sourceID := r.PathValue("sourceKeyID")
		sessionID := r.Header.Get("MPC-SessionID")
		var request keyCopyRequest
		if !keyIDPattern.MatchString(sourceID) || !memorySessionPattern.MatchString(sessionID) ||
			decodeJSON(w, r, &request, 4096) != nil || !request.validCurve(algorithm, sourceID == "_") ||
			(request.KeyID != "" && (!keyIDPattern.MatchString(request.KeyID) || request.KeyID == "_")) {
			http.Error(w, "invalid key copy request", http.StatusBadRequest)
			return
		}
		players := n.signingPlayers(w, r, sessionID)
		if players == nil {
			return
		}
		if request.Threshold < 1 || request.Threshold >= len(players) {
			http.Error(w, "invalid key copy threshold", http.StatusBadRequest)
			return
		}
		if sourceID == "_" {
			sourceID = ""
		}
		route := algorithm + "-keycopy." + sessionID
		if request.KeyID == "" {
			digest := sha256.Sum256([]byte(route))
			request.KeyID = base64.RawURLEncoding.EncodeToString(digest[:21])
		}
		if request.KeyID == sourceID {
			http.Error(w, "key copy needs a new key ID", http.StatusBadRequest)
			return
		}
		key := keystore.Key{
			Algorithm: algorithm, SessionID: "copy." + sessionID, KeyID: request.KeyID, Threshold: request.Threshold,
		}
		release := n.lockKeyOperation(w, algorithm, key.KeyID, true)
		if release == nil {
			return
		}
		defer release()
		if sourceID != "" {
			releaseSource := n.lockSigningKey(w, r, algorithm, sourceID)
			if releaseSource == nil {
				return
			}
			defer releaseSource()
		}

		reservation, err := n.keys.Reserve(r.Context(), key)
		if err != nil {
			http.Error(w, "could not reserve key copy", http.StatusInternalServerError)
			return
		}
		if reservation == keystore.Conflict || (reservation == keystore.Completed && !n.matchesCompletedCopy(route, key, sourceID, players)) {
			http.Error(w, "key copy session or key ID already used", http.StatusConflict)
			return
		}
		if reservation == keystore.Reserved {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), keygenTimeout)
			defer cancel()
			stage, err := n.runKeyCopy(ctx, key, route, sourceID, players)
			n.logMPCResult("keycopy", algorithm, stage, start, err)
			switch {
			case errors.Is(err, errCopySource):
				http.Error(w, errCopySource.Error(), http.StatusBadRequest)
				return
			case errors.Is(err, sql.ErrNoRows) && stage == "protocol":
				http.NotFound(w, r)
				return
			case err != nil:
				http.Error(w, "key copy failed", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(generateKeyResponse{KeyID: key.KeyID})
	}
}

func (r keyCopyRequest) validCurve(algorithm string, newPlayer bool) bool {
	if !newPlayer {
		return r.Curve == "" && r.SchnorrVariant == ""
	}
	if algorithm == "ecdsa" {
		return r.Curve == "secp256k1" && r.SchnorrVariant == ""
	}
	return (r.Curve == "ED-25519" || r.Curve == "ed25519") &&
		(r.SchnorrVariant == "Ed25519" || r.SchnorrVariant == "")
}

func parseKeyCopyRoute(route string) (algorithm, sessionID string, ok bool) {
	algorithm, sessionID, ok = strings.Cut(route, "-keycopy.")
	return algorithm, sessionID, ok && (algorithm == "ecdsa" || algorithm == "frost") && memorySessionPattern.MatchString(sessionID)
}

func (n *node) matchesCompletedCopy(route string, key keystore.Key, sourceID string, players party.IDSlice) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	session := n.sessions[route]
	return session != nil && session.status.State == "succeeded" && session.key == key &&
		session.copySourceID == sourceID && slices.Equal(session.players, players)
}

func (n *node) runKeyCopy(ctx context.Context, key keystore.Key, route, sourceID string, players party.IDSlice) (stage string, err error) {
	session := &keygenSession{
		key: key, players: players, copySourceID: sourceID, status: keygenStatus{State: "running"},
		incoming: make(chan *protocol.Message, 32), copyIncoming: make(chan *protocol.Message, 3*len(players)),
	}
	n.mu.Lock()
	n.sessions[route] = session
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		session.incoming, session.copyIncoming = nil, nil
		session.status.State = "succeeded"
		if err != nil {
			session.status.State = "failed"
		}
		n.mu.Unlock()
		// Slow peers can still confirm after this node has written its share.
		time.AfterFunc(keygenTimeout, func() {
			n.mu.Lock()
			delete(n.sessions, route)
			n.mu.Unlock()
		})
	}()
	binding := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%d:%q", route, key.KeyID, key.Threshold, players))
	exchange := &copyExchange{
		node: n, route: route, binding: binding, players: players, incoming: session.copyIncoming,
		received: map[string]map[party.ID][]byte{copySourceRound: {}, copyCommitRound: {}, copyShareRound: {}},
	}
	copyKey := n.copyECDSA
	if key.Algorithm == "frost" {
		copyKey = n.copyFROST
	}
	candidate, confirmation, err := copyKey(ctx, exchange, session, sourceID)
	defer clear(candidate)
	if err != nil {
		return "protocol", err
	}
	n.mu.Lock()
	session.copyDigest = &confirmation
	n.mu.Unlock()
	body, err := json.Marshal(reshareConfirmation{KeyID: key.KeyID, Digest: confirmation[:]})
	if err != nil {
		return "confirmation", err
	}
	for _, player := range players {
		if player == n.config.PartyID {
			continue
		}
		if err := n.deliverMessage(ctx, player, "/internal/keycopy/"+route+"/ready", body); err != nil {
			return "confirmation", err
		}
	}
	return "storage", n.keys.Save(ctx, key, candidate)
}

func (n *node) keyCopyReady(w http.ResponseWriter, r *http.Request) {
	route := r.PathValue("sessionId")
	_, _, ok := parseKeyCopyRoute(route)
	var request reshareConfirmation
	if !ok || decodeJSON(w, r, &request, 512) != nil ||
		!keyIDPattern.MatchString(request.KeyID) || len(request.Digest) != sha256.Size {
		http.Error(w, "invalid key copy confirmation", http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	session := n.sessions[route]
	var digest *[32]byte
	if session != nil && session.key.KeyID == request.KeyID {
		if n.config.MPCTLS != nil && !session.players.Contains(n.verifiedPeer(r)) {
			n.mu.Unlock()
			http.Error(w, "peer is not in the key copy session", http.StatusForbidden)
			return
		}
		digest = session.copyDigest
	}
	n.mu.Unlock()
	switch {
	case digest == nil:
		http.NotFound(w, r)
	case !bytes.Equal(request.Digest, digest[:]):
		http.Error(w, "key copy candidates disagree", http.StatusConflict)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
