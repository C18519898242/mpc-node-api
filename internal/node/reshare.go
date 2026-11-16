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
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func (n *node) reshareKey(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := keystore.Reshare{Algorithm: algorithm, SessionID: r.Header.Get("MPC-SessionID"), KeyID: r.PathValue("keyID")}
		routingID := mpcRoutingID(op.SessionID)
		var body [1]byte
		if !keyIDPattern.MatchString(op.KeyID) || !memorySessionPattern.MatchString(op.SessionID) ||
			r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID ||
			!n.validPlayers(r.Header.Values("MPC-Players")) {
			http.Error(w, "invalid reshare session or players", http.StatusBadRequest)
			return
		}
		if read, err := io.ReadFull(r.Body, body[:]); read != 0 || err != io.EOF {
			http.Error(w, "reshare request body must be empty", http.StatusBadRequest)
			return
		}
		release := n.lockKeyOperation(w, algorithm, op.KeyID, true)
		if release == nil {
			return
		}
		defer release()

		reservation, stored, err := n.keys.ReserveReshare(r.Context(), op)
		switch {
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
		stage, err := n.runReshare(ctx, op, stored.Digest)
		n.logMPCResult("reshare", algorithm, stage, start, err)
		if err != nil {
			http.Error(w, "reshare failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (n *node) runReshare(ctx context.Context, op keystore.Reshare, digest []byte) (string, error) {
	route := op.Algorithm + "-reshare." + op.SessionID
	if digest == nil {
		session := &keygenSession{incoming: make(chan *protocol.Message, 32), status: keygenStatus{State: "running"}}
		n.mu.Lock()
		n.sessions[route] = session
		n.mu.Unlock()
		defer func() {
			n.mu.Lock()
			delete(n.sessions, route)
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
		if err := n.keys.StageReshare(ctx, op, confirmation, share); err != nil {
			return "storage", err
		}
		digest = confirmation[:]
	}
	// A peer can acknowledge durable preparation even after a restart.
	body, err := json.Marshal(reshareConfirmation{KeyID: op.KeyID, Digest: digest})
	if err != nil {
		return "confirmation", err
	}
	for _, addr := range n.config.Peers {
		if err := n.deliverMessage(ctx, "http://"+addr+"/internal/reshare/"+route+"/ready", body); err != nil {
			return "confirmation", err
		}
	}
	if err := n.keys.CommitReshare(ctx, op); err != nil {
		return "storage", err
	}
	n.mu.Lock()
	for id, session := range n.sessions {
		if session.presignIDs != nil && session.key.Algorithm == op.Algorithm && session.key.KeyID == op.KeyID {
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
	state, err := n.keys.LoadReshare(r.Context(), keystore.Reshare{Algorithm: algorithm, SessionID: sessionID, KeyID: request.KeyID})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not read reshare status", http.StatusInternalServerError)
	case !bytes.Equal(state.Digest, request.Digest):
		http.Error(w, "reshare candidates disagree", http.StatusConflict)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (n *node) refreshECDSA(ctx context.Context, keyID, route string, session *keygenSession) ([]byte, [32]byte, error) {
	var epoch [32]byte
	current, err := n.loadECDSAShare(ctx, keyID, nil)
	if err != nil {
		return nil, epoch, err
	}
	roster, _, _ := n.frostRoster()
	if !slices.Equal(roster, current.PartyIDs()) || current.ID != n.config.PartyID {
		return nil, epoch, errors.New("stored CMP config does not match the node group")
	}
	binding := sha256.Sum256([]byte(route + ":" + keyID))
	result, err := n.runCMP(ctx, route, binding[:], cmp.Refresh(current, nil), session.incoming, nil)
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

func (n *node) lockKeyOperation(w http.ResponseWriter, algorithm, keyID string, exclusive bool) func() {
	key := algorithm + ":" + keyID
	n.mu.Lock()
	active := n.keyOperations[key]
	if active < 0 || (exclusive && active != 0) {
		n.mu.Unlock()
		http.Error(w, "key busy during reshare or signing", http.StatusConflict)
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
	release := n.lockKeyOperation(w, algorithm, keyID, false)
	if release == nil {
		return nil
	}
	pending, err := n.keys.PendingReshare(r.Context(), algorithm, keyID)
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
