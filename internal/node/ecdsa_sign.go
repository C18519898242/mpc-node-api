package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	cmpECDSA "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
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
	signers := n.signingPlayers(w, r, sessionID)
	if signers == nil {
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
	n.serveSignature(w, r, id, keyID, signers, request.ChainPath, request.MessageHash, "ECDSA",
		func(ctx context.Context, session *keygenSession) ([]byte, error) {
			result, err := n.runCMP(ctx, id, session.signBinding[:], cmp.Sign(share, signers, request.MessageHash, nil), session.incoming, signers)
			if err != nil {
				return nil, err
			}
			return encodeECDSASignature(result.(*cmpECDSA.Signature))
		})
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
