package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	cmpECDSA "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const ecdsaSignPrefix = "ecdsa-sign."

type ecdsaSignRequest struct {
	ChainPath   []uint32 `json:"chainPath"`
	MessageHash []byte   `json:"messageHash"`
}

func (n *node) signECDSA(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	sessionID := r.Header.Get("MPC-SessionID")
	var request ecdsaSignRequest
	if !keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sessionID) ||
		decodeJSON(w, r, &request, 4096) != nil || len(request.MessageHash) != sha256.Size {
		http.Error(w, "invalid ECDSA signing request", http.StatusBadRequest)
		return
	}
	routingID := mpcRoutingID(sessionID)
	if r.Header.Get("MPC-RoutingID") != routingID || r.URL.Query().Get("mpc_routing_id") != routingID {
		http.Error(w, "invalid MPC routing ID", http.StatusBadRequest)
		return
	}
	signers := make(party.IDSlice, 0, len(n.config.Peers)+1)
	for _, player := range r.Header.Values("MPC-Players") {
		id := party.ID(player)
		_, peer := n.config.Peers[id]
		if (id != n.config.PartyID && !peer) || slices.Contains(signers, id) {
			http.Error(w, "invalid signing players", http.StatusBadRequest)
			return
		}
		signers = append(signers, id)
	}
	slices.Sort(signers)
	if len(signers) < 2 || !slices.Contains(signers, n.config.PartyID) {
		http.Error(w, "signing players must include this node and at least one peer", http.StatusBadRequest)
		return
	}

	share, err := n.loadECDSAShare(r.Context(), keyID, request.ChainPath)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case errors.Is(err, errInvalidChainPath):
		http.Error(w, "invalid BIP32 derivation path", http.StatusBadRequest)
		return
	case err != nil:
		log.Printf("node %s: ECDSA signing key lookup for %s: %v", n.config.PartyID, keyID, err)
		http.Error(w, "could not load signing key", http.StatusInternalServerError)
		return
	}
	if !share.CanSign(signers) {
		http.Error(w, "signing players do not satisfy the key threshold or roster", http.StatusBadRequest)
		return
	}

	id := ecdsaSignPrefix + sessionID
	binding, err := json.Marshal(struct {
		SessionID string
		KeyID     string
		Signers   party.IDSlice
		Path      []uint32
		Digest    []byte
	}{id, keyID, signers, append([]uint32(nil), request.ChainPath...), request.MessageHash})
	if err != nil {
		http.Error(w, "could not encode signing parameters", http.StatusInternalServerError)
		return
	}
	session := n.beginECDSASign(id, sha256.Sum256(binding), share, signers, request.MessageHash)
	if session == nil {
		http.Error(w, "session ID already used with different signing parameters", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		return
	case <-session.done:
		if session.status.State != "succeeded" {
			http.Error(w, "ECDSA signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Signature []byte `json:"signature"`
		}{session.signature})
	}
}

func (n *node) beginECDSASign(id string, binding [32]byte, share *cmp.Config, signers party.IDSlice, digest []byte) *keygenSession {
	n.mu.Lock()
	defer n.mu.Unlock()
	if session := n.sessions[id]; session != nil {
		if session.signBinding == binding {
			return session
		}
		return nil
	}
	session := &keygenSession{
		incoming:    make(chan *protocol.Message, 32),
		status:      keygenStatus{State: "running"},
		done:        make(chan struct{}),
		signBinding: binding,
	}
	n.sessions[id] = session
	go n.runECDSASign(id, session, share, signers, digest)
	return session
}

func (n *node) runECDSASign(id string, session *keygenSession, share *cmp.Config, signers party.IDSlice, digest []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
	defer cancel()
	result, err := n.runCMP(ctx, id, session.signBinding[:], cmp.Sign(share, signers, digest, nil), session.incoming, signers)
	var der []byte
	if err == nil {
		der, err = encodeECDSASignature(result.(*cmpECDSA.Signature))
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	defer close(session.done)
	if err != nil {
		log.Printf("node %s: ECDSA sign %s failed: %v", n.config.PartyID, id, err)
		session.status.State = "failed"
		return
	}
	session.signature = der
	session.status.State = "succeeded"
}

func encodeECDSASignature(signature *cmpECDSA.Signature) ([]byte, error) {
	rBytes, err := signature.R.XScalar().MarshalBinary()
	if err != nil {
		return nil, err
	}
	sBytes, err := signature.S.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(rBytes) || s.SetByteSlice(sBytes) || r.IsZero() || s.IsZero() {
		return nil, errors.New("invalid ECDSA signature scalars")
	}
	return secpECDSA.NewSignature(&r, &s).Serialize(), nil
}
