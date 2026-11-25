package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/fxamacker/cbor/v2"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	frostPresignPrefix = "frost-presign."
	frostCommitment    = "frost/presign/commitment"
	frostConfirmation  = "frost/presign/confirmation"
)

type frostPresignShare struct {
	Nonces      [2][32]byte
	Players     party.IDSlice
	Commitments [][]byte // Serialized FROST Sign1 messages in player order.
}

func (n *node) generateFROSTPresign(w http.ResponseWriter, r *http.Request) {
	n.generatePresign(w, r, "frost", frostPresignPrefix, n.prepareFROSTPresign)
}

func (n *node) prepareFROSTPresign(ctx context.Context, keyID string, signers party.IDSlice) (generatePresignSlot, error) {
	share, err := n.loadFROSTSigningShare(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if !canFROSTSign(share, signers) {
		return nil, errPresignRoster
	}
	ids, _ := frostIDsFor(share.Players)
	publicKey := share.Public.GroupKey.ToEd25519()
	return func(ctx context.Context, route string, binding [32]byte, inbox <-chan *protocol.Message) (keystore.Presignature, error) {
		keyBinding := sha256.Sum256(append(binding[:], publicKey...))
		return n.runFROSTPresignSlot(ctx, route, keyBinding, signers, ids, inbox)
	}, nil
}

func (n *node) runFROSTPresignSlot(ctx context.Context, route string, binding [32]byte, signers party.IDSlice, ids map[party.ID]frostparty.ID, inbox <-chan *protocol.Message) (keystore.Presignature, error) {
	var record frostPresignShare
	defer clear(record.Nonces[:])
	transcript, err := n.exchangeFROSTCommitments(ctx, route, binding, signers, ids, inbox, &record)
	if err != nil {
		return keystore.Presignature{}, err
	}
	data, err := cbor.Marshal(record)
	return keystore.Presignature{ID: base64.RawURLEncoding.EncodeToString(transcript), Share: data}, err
}

func (n *node) exchangeFROSTCommitments(ctx context.Context, route string, binding [32]byte, signers party.IDSlice, ids map[party.ID]frostparty.ID, inbox <-chan *protocol.Message, record *frostPresignShare) ([]byte, error) {
	copy(binding[:], applicationBinding(applicationID(ctx), binding[:]))
	record.Players = signers
	record.Commitments = make([][]byte, len(signers))
	var points [2]*ristretto.Element
	for i := range points {
		var random [64]byte
		_, err := rand.Read(random[:])
		if err != nil {
			return nil, err
		}
		nonce, err := ristretto.NewScalar().SetUniformBytes(random[:])
		clear(random[:])
		if err != nil || nonce.Equal(ristretto.NewScalar()) == 1 {
			return nil, errors.New("invalid FROST presign nonce")
		}
		copy(record.Nonces[i][:], nonce.Bytes())
		points[i] = ristretto.NewIdentityElement().ScalarBaseMult(nonce)
		nonce.Set(ristretto.NewScalar())
	}

	self := n.config.PartyID
	own, err := messages.NewSign1(ids[self], points[0], points[1]).MarshalBinary()
	if err != nil {
		return nil, err
	}
	send := func(kind string, data []byte) error {
		return n.sendMessage(ctx, route, &protocol.Message{SSID: binding[:], From: self, Protocol: kind, Data: data}, signers)
	}
	if err := send(frostCommitment, own); err != nil {
		return nil, err
	}

	commitments := map[party.ID][]byte{self: own}
	confirmations := make(map[party.ID][]byte)
	var transcript []byte
	for {
		if transcript == nil && len(commitments) == len(signers) {
			hash := sha256.New()
			hash.Write(binding[:])
			for i, id := range signers {
				record.Commitments[i] = commitments[id]
				hash.Write(commitments[id])
			}
			transcript = hash.Sum(nil)
			if err := send(frostConfirmation, transcript); err != nil {
				return nil, err
			}
		}
		if transcript != nil && len(confirmations) == len(signers)-1 {
			for _, confirmation := range confirmations {
				if !bytes.Equal(confirmation, transcript) {
					return nil, errors.New("FROST commitment views disagree")
				}
			}
			return transcript, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope := <-inbox:
			if !bytes.Equal(envelope.SSID, binding[:]) || !signers.Contains(envelope.From) || envelope.To != "" {
				return nil, errors.New("invalid FROST presign envelope")
			}
			var seen map[party.ID][]byte
			switch envelope.Protocol {
			case frostCommitment:
				message, err := decodeFROSTMessage(envelope.Data, true)
				identity := ristretto.NewIdentityElement()
				if err != nil || message.Sign1 == nil || message.From != ids[envelope.From] ||
					message.Sign1.Di.Equal(identity) == 1 || message.Sign1.Ei.Equal(identity) == 1 {
					return nil, errors.New("invalid FROST presign commitment")
				}
				seen = commitments
			case frostConfirmation:
				if len(envelope.Data) != sha256.Size {
					return nil, errors.New("invalid FROST presign confirmation")
				}
				seen = confirmations
			default:
				return nil, errors.New("unexpected FROST presign message")
			}
			if prior, exists := seen[envelope.From]; exists && !bytes.Equal(prior, envelope.Data) {
				return nil, errors.New("conflicting FROST presign message")
			}
			seen[envelope.From] = envelope.Data
		}
	}
}
