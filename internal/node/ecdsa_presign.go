package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const (
	ecdsaPresignPrefix = "ecdsa-presign."
	maxPresignCount    = 8
)

func (n *node) generateECDSAPresign(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("MPC-SessionID")
	keyID := r.PathValue("keyID")
	count, err := strconv.ParseUint(r.PathValue("count"), 10, 8)
	if err != nil || count == 0 || count > maxPresignCount ||
		!keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sessionID) {
		http.Error(w, "invalid ECDSA presign request", http.StatusBadRequest)
		return
	}
	var body [1]byte
	if read, err := io.ReadFull(r.Body, body[:]); read != 0 || err != io.EOF {
		http.Error(w, "presign request body must be empty", http.StatusBadRequest)
		return
	}
	signers := n.signingPlayers(w, r, sessionID)
	if signers == nil {
		return
	}
	share, err := n.loadECDSAShare(r.Context(), keyID, nil)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load presign key", http.StatusInternalServerError)
		return
	}
	if !share.CanSign(signers) {
		http.Error(w, "players do not satisfy the key threshold or roster", http.StatusBadRequest)
		return
	}
	id := ecdsaPresignPrefix + sessionID
	parameters, err := json.Marshal(struct {
		Session, Key string
		Count        uint64
		Players      party.IDSlice
	}{id, keyID, count, signers})
	if err != nil {
		http.Error(w, "could not encode presign parameters", http.StatusInternalServerError)
		return
	}
	session, err := n.beginECDSAPresign(r.Context(), id, keyID, sha256.Sum256(parameters), int(count), share, signers)
	if err != nil {
		http.Error(w, "could not reserve presign batch", http.StatusInternalServerError)
		return
	}
	if session == nil {
		http.Error(w, "presign session already used", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		return
	case <-session.done:
		if session.status.State != "succeeded" || len(session.presignIDs) != int(count) {
			http.Error(w, "ECDSA presign failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			IDs []string `json:"ids"`
		}{session.presignIDs})
	}
}

func (n *node) beginECDSAPresign(ctx context.Context, id, keyID string, binding [32]byte, count int, share *cmp.Config, signers party.IDSlice) (*keygenSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.signBinding == binding {
			return session, nil
		}
		return nil, nil
	}
	outcome, ids, err := n.keys.ReserveECDSAPresign(ctx, id, keyID, binding)
	if err != nil || outcome == keystore.Conflict {
		return nil, err
	}
	session := &keygenSession{
		status: keygenStatus{State: "running"}, done: make(chan struct{}), signBinding: binding,
	}
	if outcome == keystore.Completed {
		session.status.State = "succeeded"
		session.presignIDs = ids
		close(session.done)
		return session, nil
	}
	session.presignInboxes = make([]chan *protocol.Message, count)
	for i := range session.presignInboxes {
		session.presignInboxes[i] = make(chan *protocol.Message, 32)
	}
	n.sessions[id] = session
	go n.runECDSAPresign(id, session, share, signers)
	return session, nil
}

func (n *node) runECDSAPresign(id string, session *keygenSession, share *cmp.Config, signers party.IDSlice) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
	defer cancel()
	shares := make([]keystore.Presignature, 0, len(session.presignInboxes))
	defer func() {
		for _, share := range shares {
			clear(share.Share)
		}
	}()
	stage := "protocol"
	var ids []string
	var err error
	for i, inbox := range session.presignInboxes {
		// Bind each slot independently so early messages for the next slot are queued separately.
		binding := sha256.Sum256(append(session.signBinding[:32:32], byte(i)))
		route := id + "." + strconv.Itoa(i)
		var result any
		result, err = n.runCMP(ctx, route, binding[:], cmp.Presign(share, signers, nil), inbox, signers)
		if err != nil {
			break
		}
		presign := result.(*ecdsa.PreSignature)
		if err = presign.Validate(); err != nil {
			break
		}
		var data []byte
		data, err = cbor.Marshal(presign)
		if err != nil {
			break
		}
		shares = append(shares, keystore.Presignature{ID: base64.RawURLEncoding.EncodeToString(presign.ID), Share: data})
	}
	if err == nil {
		stage = "storage"
		ids, err = n.keys.SaveECDSAPresign(ctx, id, shares)
	}
	n.logMPCResult("presiggen", "ecdsa", stage, start, err)
	n.mu.Lock()
	defer n.mu.Unlock()
	defer close(session.done)
	session.presignInboxes = nil
	if err != nil {
		session.status.State = "failed"
		return
	}
	session.presignIDs = ids
	session.status.State = "succeeded"
}
