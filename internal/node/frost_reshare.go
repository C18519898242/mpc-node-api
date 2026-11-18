package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	frostReshareCommitment = "frost/reshare/commitment"
	frostReshareEvaluation = "frost/reshare/evaluation"
	frostScalarSize        = 32
)

type frostRefreshContribution struct {
	commitments      []ristretto.Element
	evaluation       ristretto.Scalar
	hasEvaluation    bool
	commitmentDigest [32]byte
}

func (n *node) refreshFROST(ctx context.Context, keyID, route string, session *keygenSession) ([]byte, [32]byte, error) {
	var epoch [32]byte
	current, err := n.loadFROSTSigningShare(ctx, keyID)
	if err != nil {
		return nil, epoch, err
	}
	roster := current.Players
	ids, frostIDs := frostIDsFor(roster)
	self := ids[n.config.PartyID]
	degree := int(current.Public.Threshold)
	if degree < 1 || degree >= len(roster) {
		return nil, epoch, errors.New("invalid FROST reshare threshold")
	}
	public, err := json.Marshal(current.Public)
	if err != nil {
		return nil, epoch, err
	}
	binding := sha256.Sum256(append([]byte(route+":"+keyID+":"), public...))
	copy(binding[:], n.applicationBinding(binding[:]))
	send := func(toIndex int, kind string, data []byte) error {
		msg := &protocol.Message{SSID: binding[:], From: n.config.PartyID, Protocol: kind, Data: data}
		if toIndex >= 0 {
			msg.To = roster[toIndex]
		}
		return n.sendMessage(ctx, route, msg, roster)
	}

	// Each dealer contributes a random degree-t polynomial with implicit zero
	// constant, and sends each evaluation only to its intended recipient.
	coefficients := make([]ristretto.Scalar, degree)
	defer clear(coefficients)
	local := &frostRefreshContribution{commitments: make([]ristretto.Element, degree), hasEvaluation: true}
	var commitmentBytes []byte
	for i := range coefficients {
		var random [64]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, epoch, err
		}
		_, _ = coefficients[i].SetUniformBytes(random[:])
		clear(random[:])
		local.commitments[i].ScalarBaseMult(&coefficients[i])
		commitmentBytes = append(commitmentBytes, local.commitments[i].Bytes()...)
	}
	if err := send(-1, frostReshareCommitment, commitmentBytes); err != nil {
		return nil, epoch, err
	}
	for i, id := range frostIDs {
		evaluation := evaluateFROSTRefresh(coefficients, id)
		if id == self {
			local.evaluation = evaluation
			continue
		}
		data := evaluation.Bytes()
		err := send(i, frostReshareEvaluation, data)
		clear(data)
		if err != nil {
			return nil, epoch, err
		}
	}

	contributions := make([]frostRefreshContribution, len(roster))
	contributions[self-1] = *local
	defer clear(contributions)
	if err := receiveFROSTRefresh(ctx, session, binding, ids, self, degree, contributions); err != nil {
		return nil, epoch, err
	}
	secret := current.SecretKey.Secret
	shares := make(map[frostparty.ID]*ristretto.Element, len(roster))
	for _, id := range frostIDs {
		shares[id] = new(ristretto.Element).Set(current.Public.Shares[id])
	}
	for i := range contributions {
		contribution := &contributions[i]
		actual := new(ristretto.Element).ScalarBaseMult(&contribution.evaluation)
		if actual.Equal(evaluateFROSTRefreshCommitment(contribution.commitments, self)) != 1 {
			return nil, epoch, errors.New("FROST reshare evaluation does not match commitment")
		}
		secret.Add(&secret, &contribution.evaluation)
		for _, id := range frostIDs {
			shares[id].Add(shares[id], evaluateFROSTRefreshCommitment(contribution.commitments, id))
		}
	}
	refreshed, err := eddsa.NewPublic(shares, current.Public.Threshold)
	if err != nil {
		return nil, epoch, err
	}
	localShare := eddsa.NewSecretShare(self, &secret)
	if !refreshed.GroupKey.Equal(current.Public.GroupKey) || localShare.Public.Equal(shares[self]) != 1 ||
		!validFROSTRefreshShares(current.Public, refreshed) {
		return nil, epoch, errors.New("invalid refreshed FROST public shares")
	}
	public, err = json.Marshal(refreshed)
	if err != nil {
		return nil, epoch, err
	}
	data, err := marshalFROSTShare(&keygen.Output{SecretKey: localShare, Public: refreshed}, roster)
	return data, sha256.Sum256(public), err
}

func receiveFROSTRefresh(ctx context.Context, session *keygenSession, binding [32]byte, ids map[party.ID]frostparty.ID, self frostparty.ID, degree int, contributions []frostRefreshContribution) error {
	for remaining := 2 * (len(contributions) - 1); remaining > 0; {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message := <-session.incoming:
			from := ids[message.From]
			if from == 0 || from == self || !bytes.Equal(message.SSID, binding[:]) {
				return errors.New("FROST reshare session or epoch disagrees")
			}
			contribution := &contributions[from-1]
			switch message.Protocol {
			case frostReshareCommitment:
				if message.To != "" || len(message.Data) != degree*frostScalarSize {
					return errors.New("invalid FROST reshare commitments")
				}
				digest := sha256.Sum256(message.Data)
				if contribution.commitments != nil {
					if contribution.commitmentDigest != digest {
						return errors.New("conflicting FROST reshare commitments")
					}
					continue
				}
				contribution.commitmentDigest = digest
				contribution.commitments = make([]ristretto.Element, degree)
				for i := range contribution.commitments {
					if _, err := contribution.commitments[i].SetCanonicalBytes(message.Data[i*frostScalarSize : (i+1)*frostScalarSize]); err != nil {
						return err
					}
				}
			case frostReshareEvaluation:
				if ids[message.To] != self || len(message.Data) != frostScalarSize {
					clear(message.Data)
					return errors.New("invalid FROST reshare evaluation")
				}
				var evaluation ristretto.Scalar
				_, err := evaluation.SetCanonicalBytes(message.Data)
				clear(message.Data)
				if err != nil {
					return err
				}
				if contribution.hasEvaluation {
					if contribution.evaluation.Equal(&evaluation) != 1 {
						return errors.New("conflicting FROST reshare evaluation")
					}
					continue
				}
				contribution.evaluation.Set(&evaluation)
				contribution.hasEvaluation = true
			default:
				return errors.New("unexpected FROST reshare message")
			}
			remaining--
		}
	}
	return nil
}

func evaluateFROSTRefresh(coefficients []ristretto.Scalar, recipient frostparty.ID) ristretto.Scalar {
	x := recipient.Scalar()
	var sum ristretto.Scalar
	for i := len(coefficients) - 1; i >= 0; i-- {
		sum.MultiplyAdd(&sum, x, &coefficients[i])
	}
	sum.Multiply(&sum, x)
	return sum
}

func evaluateFROSTRefreshCommitment(commitments []ristretto.Element, recipient frostparty.ID) *ristretto.Element {
	x := recipient.Scalar()
	sum := ristretto.NewIdentityElement()
	for i := len(commitments) - 1; i >= 0; i-- {
		sum.ScalarMult(x, sum)
		sum.Add(sum, &commitments[i])
	}
	return sum.ScalarMult(x, sum)
}

func validFROSTRefreshShares(old, refreshed *eddsa.Public) bool {
	identity := ristretto.NewIdentityElement()
	for _, id := range refreshed.PartyIDs {
		share := refreshed.Shares[id]
		if share.Equal(old.Shares[id]) == 1 || share.Equal(identity) == 1 ||
			refreshed.GroupKey.Equal(eddsa.NewPublicKeyFromPoint(share)) {
			return false
		}
	}
	if refreshed.Threshold == 1 {
		return true
	}
	// Equality at zero detects a missing leading coefficient.
	ids := refreshed.PartyIDs[:int(refreshed.Threshold)]
	linear := ristretto.NewIdentityElement()
	for _, id := range ids {
		weight, _ := id.Lagrange(ids)
		linear.Add(linear, new(ristretto.Element).ScalarMult(weight, refreshed.Shares[id]))
	}
	return !refreshed.GroupKey.Equal(eddsa.NewPublicKeyFromPoint(linear))
}
