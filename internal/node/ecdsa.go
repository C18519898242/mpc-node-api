package node

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const ecdsaSessionPrefix = "ecdsa."

func (n *node) ecdsaPublicKey(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var request struct {
		ChainPath []uint32 `json:"chainPath"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil {
		http.Error(w, "invalid public key request", http.StatusBadRequest)
		return
	}
	for _, index := range request.ChainPath {
		if index >= 1<<31 {
			http.Error(w, "hardened BIP32 derivation is unsupported", http.StatusBadRequest)
			return
		}
	}
	point, err := n.loadECDSAPublicKey(r.Context(), keyID, request.ChainPath)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case errors.Is(err, errInvalidChainPath):
		http.Error(w, "invalid BIP32 derivation path", http.StatusBadRequest)
	case err != nil:
		log.Printf("node %s: ECDSA public key lookup for %s: %v", n.config.PartyID, keyID, err)
		http.Error(w, "could not read ECDSA public key", http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Curve     string `json:"curve"`
			PublicKey []byte `json:"publicKey"`
		}{"secp256k1", point})
	}
}

var errInvalidChainPath = errors.New("invalid BIP32 path")

func (n *node) loadECDSAPublicKey(ctx context.Context, keyID string, path []uint32) ([]byte, error) {
	share, err := n.loadECDSAShare(ctx, keyID, path)
	if err != nil {
		return nil, err
	}
	compressed, err := share.PublicPoint().MarshalBinary()
	if err != nil {
		return nil, err
	}
	point, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, err
	}
	return point.SerializeUncompressed(), nil
}

func (n *node) generateECDSAKey(w http.ResponseWriter, r *http.Request) {
	n.generateKey(w, r, ecdsaSessionPrefix, "secp256k1", n.generateECDSAShare)
}

func (n *node) generateECDSAShare(ctx context.Context, id string, session *keygenSession) ([]byte, error) {
	// A key ID mismatch must also change the CMP session identity.
	protocolID := sha256.Sum256([]byte(id + ":" + session.key.KeyID))
	share, err := n.executeKeygen(ctx, id, protocolID[:], session.key.Threshold, session.incoming)
	if err != nil {
		return nil, err
	}
	return share.MarshalBinary()
}
