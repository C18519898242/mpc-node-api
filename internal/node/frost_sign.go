package node

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

const frostSignPrefix = "frost-sign."

func (n *node) signFROST(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	sessionID := r.Header.Get("MPC-SessionID")
	var request struct {
		ChainPath []uint32 `json:"chainPath"`
		Message   []byte   `json:"message"`
	}
	if !keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sessionID) ||
		decodeJSON(w, r, &request, 4096) != nil || request.Message == nil {
		http.Error(w, "invalid FROST signing request", http.StatusBadRequest)
		return
	}
	if len(request.ChainPath) != 0 {
		http.Error(w, "FROST signing supports the root key only", http.StatusBadRequest)
		return
	}
	signers := n.signingPlayers(w, r, sessionID)
	if signers == nil {
		return
	}

	roster, ids, frostIDs := n.frostRoster()
	share, err := n.loadFROSTSigningShare(r.Context(), keyID, ids[n.config.PartyID], frostIDs)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case err != nil:
		log.Printf("node %s: FROST signing key lookup for %s: %v", n.config.PartyID, keyID, err)
		http.Error(w, "could not load signing key", http.StatusInternalServerError)
		return
	}
	if len(signers) <= int(share.Public.Threshold) {
		http.Error(w, "signing players do not satisfy the key threshold", http.StatusBadRequest)
		return
	}
	selected := make(frostparty.IDSlice, len(signers))
	for i, signer := range signers {
		selected[i] = ids[signer]
	}

	id := frostSignPrefix + sessionID
	n.serveSignature(w, r, id, keyID, signers, nil, request.Message, "FROST",
		func(ctx context.Context, session *keygenSession) ([]byte, error) {
			state, output, err := frost.NewSignState(selected, share.SecretKey, share.Public, request.Message, 0)
			if err != nil {
				return nil, err
			}
			if err := n.runFROST(ctx, id, session, session.signBinding, state, roster, ids, signers, true); err != nil {
				return nil, err
			}
			if output.Signature == nil {
				return nil, errors.New("FROST produced no signature")
			}
			signature := output.Signature.ToEd25519()
			if !ed25519.Verify(share.Public.GroupKey.ToEd25519(), request.Message, signature) {
				return nil, errors.New("FROST signature did not verify")
			}
			return signature, nil
		})
}

func (n *node) loadFROSTSigningShare(ctx context.Context, keyID string, self frostparty.ID, roster frostparty.IDSlice) (*keygen.Output, error) {
	data, err := n.keys.Load(ctx, "frost", keyID)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var share keygen.Output
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, err
	}
	if share.SecretKey == nil || share.Public == nil || share.Public.GroupKey == nil ||
		share.SecretKey.ID != self || !slices.Equal(share.Public.PartyIDs, roster) {
		return nil, errors.New("stored FROST share does not match the configured node group")
	}
	publicShare := share.Public.Shares[self]
	if publicShare == nil || publicShare.Equal(&share.SecretKey.Public) != 1 {
		return nil, errors.New("stored FROST public share does not match its secret share")
	}
	return &share, nil
}
