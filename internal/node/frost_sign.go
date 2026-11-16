package node

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
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
	if eddsa.ValidatePath(request.ChainPath) != nil {
		http.Error(w, "invalid FROST derivation path", http.StatusBadRequest)
		return
	}
	signers := n.signingPlayers(w, r, sessionID)
	if signers == nil {
		return
	}
	release := n.lockSigningKey(w, r, "frost", keyID)
	if release == nil {
		return
	}
	defer release()

	share, err := n.loadFROSTSigningShare(r.Context(), keyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "could not load signing key", http.StatusInternalServerError)
		return
	}
	if !canFROSTSign(share, signers) {
		http.Error(w, "signing players do not satisfy the key threshold or roster", http.StatusBadRequest)
		return
	}
	roster := share.Players
	ids, _ := frostIDsFor(roster)
	selected := make(frostparty.IDSlice, len(signers))
	for i, signer := range signers {
		selected[i] = ids[signer]
	}

	id := frostSignPrefix + sessionID
	n.serveSignature(w, r, id, keyID, signers, request.ChainPath, request.Message, "FROST",
		func(ctx context.Context, session *keygenSession) ([]byte, error) {
			if len(request.ChainPath) != 0 {
				secret, public, err := share.Public.DeriveShare(share.SecretKey, share.Public.GroupKey.DefaultChainCode(), request.ChainPath)
				if err != nil {
					return nil, err
				}
				share.Output = keygen.Output{SecretKey: secret, Public: public}
			}
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

func canFROSTSign(share *storedFROSTShare, signers party.IDSlice) bool {
	if len(signers) <= int(share.Public.Threshold) {
		return false
	}
	for _, id := range signers {
		if !share.Players.Contains(id) {
			return false
		}
	}
	return true
}

func (n *node) loadFROSTSigningShare(ctx context.Context, keyID string) (*storedFROSTShare, error) {
	data, err := n.keys.Load(ctx, "frost", keyID)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var share storedFROSTShare
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, err
	}
	if len(share.Players) == 0 {
		share.Players = n.configuredPlayers()
		if len(n.config.LegacyFROSTPlayers) != 0 {
			share.Players = party.NewIDSlice(n.config.LegacyFROSTPlayers)
		}
	}
	if !share.Players.Valid() {
		return nil, errors.New("invalid stored FROST player list")
	}
	ids, roster := frostIDsFor(share.Players)
	self := ids[n.config.PartyID]
	if share.SecretKey == nil || share.Public == nil || share.Public.GroupKey == nil ||
		self == 0 || share.SecretKey.ID != self || !slices.Equal(share.Public.PartyIDs, roster) {
		return nil, errors.New("stored FROST share does not match the configured node group")
	}
	publicShare := share.Public.Shares[self]
	if publicShare == nil || publicShare.Equal(&share.SecretKey.Public) != 1 {
		return nil, errors.New("stored FROST public share does not match its secret share")
	}
	return &share, nil
}
