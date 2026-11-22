package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func (n *node) reshareKey(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := keystore.Reshare{Algorithm: algorithm, SessionID: r.Header.Get("MPC-SessionID"), KeyID: r.PathValue("keyID")}
		routingID := mpcRoutingID(op.SessionID)
		var body [1]byte
		if !keyIDPattern.MatchString(op.KeyID) || !memorySessionPattern.MatchString(op.SessionID) ||
			r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID {
			http.Error(w, "invalid reshare session or players", http.StatusBadRequest)
			return
		}
		players := n.signingPlayers(w, r, op.SessionID)
		if players == nil {
			return
		}
		if read, err := io.ReadFull(r.Body, body[:]); read != 0 || err != io.EOF {
			http.Error(w, "reshare request body must be empty", http.StatusBadRequest)
			return
		}
		release := n.lockKeyOperation(w, applicationID(r.Context()), algorithm, op.KeyID, true)
		if release == nil {
			return
		}
		defer release()
		expected, err := n.keyPlayers(r.Context(), algorithm, op.KeyID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "could not load reshare key", http.StatusInternalServerError)
			return
		}
		if !slices.Equal(players, expected) {
			http.Error(w, "reshare requires all current share holders", http.StatusBadRequest)
			return
		}

		reservation, stored, session, err := n.beginReshare(r.Context(), op)
		switch {
		case errors.Is(err, errTooManySessions):
			http.Error(w, "too many concurrent MPC sessions", http.StatusServiceUnavailable)
			return
		case errors.Is(err, sql.ErrNoRows):
			http.NotFound(w, r)
			return
		case err != nil:
			http.Error(w, "could not reserve reshare", http.StatusInternalServerError)
			return
		case reservation == keystore.Conflict:
			http.Error(w, "reshare session already used", http.StatusConflict)
			return
		case stored.Committed:
			w.WriteHeader(http.StatusNoContent)
			return
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), keygenTimeout)
		defer cancel()
		stage, err := n.runReshare(ctx, op, players, stored.Digest, session)
		n.logMPCResult("reshare", algorithm, stage, start, err)
		if err != nil {
			http.Error(w, "reshare failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (n *node) keyPlayers(ctx context.Context, algorithm, keyID string) (party.IDSlice, error) {
	if algorithm == "frost" {
		share, err := n.loadFROSTSigningShare(ctx, keyID)
		if err != nil {
			return nil, err
		}
		return share.Players, nil
	}
	share, err := n.loadECDSAShare(ctx, keyID, nil)
	if err != nil {
		return nil, err
	}
	return share.PartyIDs(), nil
}

func (n *node) beginReshare(ctx context.Context, op keystore.Reshare) (keystore.Reservation, keystore.ReshareState, *keygenSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	stored, err := n.keys.LoadReshare(ctx, applicationID(ctx), op)
	if err == nil {
		return keystore.Completed, stored, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return keystore.Conflict, stored, nil, err
	}
	if err := n.checkSessionCapacityLocked(applicationID(ctx)); err != nil {
		return keystore.Conflict, stored, nil, err
	}
	reservation, stored, err := n.keys.ReserveReshare(ctx, applicationID(ctx), op)
	if err != nil || reservation != keystore.Reserved {
		return reservation, stored, nil, err
	}
	session := &keygenSession{incoming: make(chan *protocol.Message, 32), status: keygenStatus{State: "running"}}
	n.sessions[sessionKey{applicationID(ctx), op.Algorithm + "-reshare." + op.SessionID}] = session
	return reservation, stored, session, nil
}

func (n *node) runReshare(ctx context.Context, op keystore.Reshare, players party.IDSlice, digest []byte, session *keygenSession) (string, error) {
	route := op.Algorithm + "-reshare." + op.SessionID
	if digest == nil {
		lookup := sessionKey{applicationID(ctx), route}
		defer func() {
			n.mu.Lock()
			delete(n.sessions, lookup)
			n.mu.Unlock()
		}()

		refresh := n.refreshECDSA
		if op.Algorithm == "frost" {
			refresh = n.refreshFROST
		}
		share, epoch, err := refresh(ctx, op.KeyID, route, session)
		defer clear(share)
		if err != nil {
			return "protocol", err
		}
		confirmation := sha256.Sum256(append([]byte(route+":"+op.KeyID+":"), epoch[:]...))
		if err := n.keys.StageReshare(ctx, applicationID(ctx), op, confirmation, share); err != nil {
			return "storage", err
		}
		digest = confirmation[:]
	}
	// A peer can acknowledge durable preparation even after a restart.
	body, err := json.Marshal(reshareConfirmation{KeyID: op.KeyID, Digest: digest})
	if err != nil {
		return "confirmation", err
	}
	for _, player := range players {
		if player == n.config.PartyID {
			continue
		}
		if err := n.deliverMessage(ctx, player, "/internal/reshare/"+route+"/ready", body); err != nil {
			return "confirmation", err
		}
	}
	if err := n.keys.CommitReshare(ctx, applicationID(ctx), op); err != nil {
		return "storage", err
	}
	n.mu.Lock()
	for id, session := range n.sessions {
		if id.applicationID == applicationID(ctx) && session.presignIDs != nil && session.key.Algorithm == op.Algorithm && session.key.KeyID == op.KeyID {
			delete(n.sessions, id)
		}
	}
	n.mu.Unlock()
	return "storage", nil
}

type reshareConfirmation struct {
	KeyID  string `json:"keyID"`
	Digest []byte `json:"digest"`
}

func parseReshareRoute(route string) (algorithm, sessionID string, ok bool) {
	algorithm, sessionID, ok = strings.Cut(route, "-reshare.")
	return algorithm, sessionID, ok && (algorithm == "ecdsa" || algorithm == "frost") && memorySessionPattern.MatchString(sessionID)
}

func (n *node) reshareReady(w http.ResponseWriter, r *http.Request) {
	algorithm, sessionID, ok := parseReshareRoute(r.PathValue("sessionId"))
	var request reshareConfirmation
	if !ok || decodeJSON(w, r, &request, 512) != nil || !keyIDPattern.MatchString(request.KeyID) ||
		len(request.Digest) != sha256.Size {
		http.Error(w, "invalid reshare confirmation", http.StatusBadRequest)
		return
	}
	state, err := n.keys.LoadReshare(r.Context(), applicationID(r.Context()), keystore.Reshare{Algorithm: algorithm, SessionID: sessionID, KeyID: request.KeyID})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not read reshare status", http.StatusInternalServerError)
	case !bytes.Equal(state.Digest, request.Digest):
		http.Error(w, "reshare candidates disagree", http.StatusConflict)
	default:
		if n.config.MPCTLS != nil {
			players, err := n.keyPlayers(r.Context(), algorithm, request.KeyID)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				http.NotFound(w, r)
				return
			case err != nil:
				http.Error(w, "could not verify reshare players", http.StatusInternalServerError)
				return
			case !players.Contains(n.verifiedPeer(r)):
				http.Error(w, "peer is not in the reshare session", http.StatusForbidden)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (n *node) refreshECDSA(ctx context.Context, keyID, route string, session *keygenSession) ([]byte, [32]byte, error) {
	var epoch [32]byte
	current, err := n.loadECDSAShare(ctx, keyID, nil)
	if err != nil {
		return nil, epoch, err
	}
	binding := sha256.Sum256([]byte(route + ":" + keyID))
	result, err := n.runCMP(ctx, route, binding[:], cmp.Refresh(current, nil), session.incoming, current.PartyIDs())
	if err != nil {
		return nil, epoch, err
	}
	refreshed := result.(*cmp.Config)
	if !refreshed.PublicPoint().Equal(current.PublicPoint()) || !bytes.Equal(refreshed.ChainKey, current.ChainKey) {
		return nil, epoch, errors.New("CMP reshare changed the key")
	}
	hash := sha256.New()
	if _, err := refreshed.WriteTo(hash); err != nil {
		return nil, epoch, fmt.Errorf("hash refreshed CMP config: %w", err)
	}
	hash.Write(refreshed.ChainKey)
	copy(epoch[:], hash.Sum(nil))
	data, err := refreshed.MarshalBinary()
	return data, epoch, err
}

type keyOperation struct {
	applicationID string
	algorithm     string
	keyID         string
}

func (n *node) lockKeyOperation(w http.ResponseWriter, appID, algorithm, keyID string, exclusive bool) func() {
	key := keyOperation{appID, algorithm, keyID}
	n.mu.Lock()
	active := n.keyOperations[key]
	if active < 0 || (exclusive && active != 0) {
		n.mu.Unlock()
		http.Error(w, "key operation in progress", http.StatusConflict)
		return nil
	}
	if exclusive {
		n.keyOperations[key] = -1
	} else {
		n.keyOperations[key]++
	}
	n.mu.Unlock()
	return func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if exclusive || n.keyOperations[key] == 1 {
			delete(n.keyOperations, key)
		} else {
			n.keyOperations[key]--
		}
	}
}

func (n *node) lockSigningKey(w http.ResponseWriter, r *http.Request, algorithm, keyID string) func() {
	release := n.lockKeyOperation(w, applicationID(r.Context()), algorithm, keyID, false)
	if release == nil {
		return nil
	}
	pending, err := n.keys.PendingReshare(r.Context(), applicationID(r.Context()), algorithm, keyID)
	switch {
	case err != nil:
		http.Error(w, "could not check key status", http.StatusInternalServerError)
	case pending:
		http.Error(w, "reshare pending for this key", http.StatusConflict)
	default:
		return release
	}
	release()
	return nil
}
