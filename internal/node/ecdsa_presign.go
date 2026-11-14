package node

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const ecdsaPresignPrefix = "ecdsa-presign."

func (n *node) generateECDSAPresign(w http.ResponseWriter, r *http.Request) {
	n.generatePresign(w, r, "ecdsa", ecdsaPresignPrefix, n.prepareECDSAPresign)
}

func (n *node) prepareECDSAPresign(ctx context.Context, keyID string, signers party.IDSlice) (generatePresignSlot, error) {
	share, err := n.loadECDSAShare(ctx, keyID, nil)
	if err != nil {
		return nil, err
	}
	if !share.CanSign(signers) {
		return nil, errPresignRoster
	}
	return func(ctx context.Context, route string, binding [32]byte, inbox <-chan *protocol.Message) (keystore.Presignature, error) {
		result, err := n.runCMP(ctx, route, binding[:], cmp.Presign(share, signers, nil), inbox, signers)
		if err != nil {
			return keystore.Presignature{}, err
		}
		presign := result.(*ecdsa.PreSignature)
		if err := presign.Validate(); err != nil {
			return keystore.Presignature{}, err
		}
		data, err := cbor.Marshal(presign)
		return keystore.Presignature{ID: base64.RawURLEncoding.EncodeToString(presign.ID), Share: data}, err
	}, nil
}
