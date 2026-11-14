package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const maxPresignCount = 8

var errPresignRoster = errors.New("players do not satisfy the key threshold or roster")

type generatePresignSlot func(context.Context, string, [32]byte, <-chan *protocol.Message) (keystore.Presignature, error)
type preparePresign func(context.Context, string, party.IDSlice) (generatePresignSlot, error)
type reservePresign func(context.Context, string, string, [32]byte) (keystore.Reservation, []string, error)
type savePresign func(context.Context, string, []keystore.Presignature) ([]string, error)

func (n *node) countPresign(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var request *struct{}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil || request == nil {
		http.Error(w, "invalid presign count request", http.StatusBadRequest)
		return
	}
	count, err := n.keys.CountPresign(r.Context(), keyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not count presignatures", http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(count)
	}
}

func (n *node) deletePresign(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var body [1]byte
	if !keyIDPattern.MatchString(keyID) {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}
	if read, err := io.ReadFull(r.Body, body[:]); read != 0 || err != io.EOF {
		http.Error(w, "presign delete request body must be empty", http.StatusBadRequest)
		return
	}
	switch err := n.keys.DeletePresign(r.Context(), keyID); {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not delete presignatures", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (n *node) generatePresign(w http.ResponseWriter, r *http.Request, algorithm, prefix string, prepare preparePresign) {
	sessionID := r.Header.Get("MPC-SessionID")
	keyID := r.PathValue("keyID")
	count, err := strconv.ParseUint(r.PathValue("count"), 10, 8)
	if err != nil || count == 0 || count > maxPresignCount ||
		!keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sessionID) {
		http.Error(w, "invalid presign request", http.StatusBadRequest)
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
	generate, err := prepare(r.Context(), keyID, signers)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case errors.Is(err, errPresignRoster):
		http.Error(w, errPresignRoster.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "could not load presign key", http.StatusInternalServerError)
		return
	}
	id := prefix + sessionID
	parameters, err := json.Marshal(struct {
		Session, Key string
		Count        uint64
		Players      party.IDSlice
	}{id, keyID, count, signers})
	if err != nil {
		http.Error(w, "could not encode presign parameters", http.StatusInternalServerError)
		return
	}
	reserve, save := n.keys.ReserveECDSAPresign, n.keys.SaveECDSAPresign
	if algorithm == "frost" {
		reserve, save = n.keys.ReserveFROSTPresign, n.keys.SaveFROSTPresign
	}
	session, err := n.beginPresign(r.Context(), id, keyID, sha256.Sum256(parameters), int(count), algorithm, generate, reserve, save)
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
			http.Error(w, "presign failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			IDs []string `json:"ids"`
		}{session.presignIDs})
	}
}

func (n *node) beginPresign(ctx context.Context, id, keyID string, binding [32]byte, count int, algorithm string, generate generatePresignSlot, reserve reservePresign, save savePresign) (*keygenSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.signBinding == binding {
			return session, nil
		}
		return nil, nil
	}
	outcome, ids, err := reserve(ctx, id, keyID, binding)
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
	go n.runPresign(id, session, algorithm, generate, save)
	return session, nil
}

func (n *node) runPresign(id string, session *keygenSession, algorithm string, generate generatePresignSlot, save savePresign) {
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
		// A separate inbox handles early messages for the next slot.
		binding := sha256.Sum256(append(session.signBinding[:32:32], byte(i)))
		route := id + "." + strconv.Itoa(i)
		var share keystore.Presignature
		share, err = generate(ctx, route, binding, inbox)
		if err != nil {
			break
		}
		shares = append(shares, share)
	}
	if err == nil {
		stage = "storage"
		ids, err = save(ctx, id, shares)
	}
	n.logMPCResult("presiggen", algorithm, stage, start, err)
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
