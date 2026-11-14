package node

import (
	"context"
	"crypto/sha256"
	"net/http"
)

const ecdsaSessionPrefix = "ecdsa."

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
