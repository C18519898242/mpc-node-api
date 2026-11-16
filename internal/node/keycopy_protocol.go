package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

var errCopySource = errors.New("key copy requires matching source shares from at least the original threshold plus one target players")

const (
	copySourceRound = "keycopy/source"
	copyCommitRound = "keycopy/commitments"
	copyShareRound  = "keycopy/evaluation"
)

type copySource struct {
	KeyID     string
	Players   party.IDSlice
	Threshold int
	Root      []byte
	Points    [][]byte
	ChainCode []byte
}

type copyExchange struct {
	node     *node
	route    string
	binding  [32]byte
	players  party.IDSlice
	incoming <-chan *protocol.Message
	received map[string]map[party.ID][]byte
}

func (x *copyExchange) send(ctx context.Context, phase string, to party.ID, data []byte) error {
	return x.node.sendMessage(ctx, x.route, &protocol.Message{
		SSID: x.binding[:], From: x.node.config.PartyID, To: to, Protocol: phase, Data: data,
	}, x.players)
}

func (x *copyExchange) collect(ctx context.Context, phase string) (map[party.ID][]byte, error) {
	for len(x.received[phase]) < len(x.players)-1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case message := <-x.incoming:
			messages := x.received[message.Protocol]
			expectedTo := party.ID("")
			if message.Protocol == copyShareRound {
				expectedTo = x.node.config.PartyID
			}
			if messages == nil || message.To != expectedTo || !x.players.Contains(message.From) ||
				!bytes.Equal(message.SSID, x.binding[:]) {
				return nil, errors.New("invalid key copy protocol envelope")
			}
			if previous, exists := messages[message.From]; exists {
				if !bytes.Equal(previous, message.Data) {
					return nil, errors.New("conflicting key copy message")
				}
				continue
			}
			messages[message.From] = message.Data
		}
	}
	return x.received[phase], nil
}

func (x *copyExchange) agreeSource(ctx context.Context, source *copySource) (*copySource, party.IDSlice, error) {
	local, err := json.Marshal(source)
	if err != nil {
		return nil, nil, err
	}
	if err := x.send(ctx, copySourceRound, "", local); err != nil {
		return nil, nil, err
	}
	received, err := x.collect(ctx, copySourceRound)
	if err != nil {
		return nil, nil, err
	}
	received[x.node.config.PartyID] = local
	var holders party.IDSlice
	var agreed *copySource
	var manifest []byte
	for _, player := range x.players {
		data := received[player]
		if bytes.Equal(data, []byte("null")) {
			continue
		}
		if agreed == nil {
			if err := json.Unmarshal(data, &agreed); err != nil || agreed == nil {
				return nil, nil, errCopySource
			}
			manifest = data
		}
		if !bytes.Equal(manifest, data) || !agreed.Players.Contains(player) {
			return nil, nil, errCopySource
		}
		holders = append(holders, player)
	}
	if agreed == nil || !keyIDPattern.MatchString(agreed.KeyID) || agreed.KeyID == "_" ||
		!agreed.Players.Valid() || agreed.Threshold < 1 || len(holders) <= agreed.Threshold ||
		len(agreed.Points) != len(agreed.Players) {
		return nil, nil, errCopySource
	}
	for _, player := range agreed.Players {
		if len(player) == 0 || len(player) > 32 || player[0] == 0 {
			return nil, nil, errCopySource
		}
	}
	return agreed, holders, nil
}

type copyGroup[S, P any] struct {
	zero          func() S
	random        func() S
	coordinates   func(party.IDSlice) map[party.ID]S
	weights       func(party.IDSlice, party.IDSlice) map[party.ID]S
	add           func(S, S) S
	multiply      func(S, S) S
	encodeScalar  func(S) []byte
	decodeScalar  func([]byte) (S, error)
	identity      func() P
	baseMultiply  func(S) P
	pointAdd      func(P, P) P
	pointMultiply func(S, P) P
	pointEqual    func(P, P) bool
	encodePoint   func(P) []byte
	decodePoint   func([]byte) (P, error)
}

type copiedSharing[S, P any] struct {
	secret     S
	points     map[party.ID]P
	source     *copySource
	transcript [32]byte
}

func transferShares[S, P any](ctx context.Context, x *copyExchange, threshold int, group copyGroup[S, P], local *copySource, oldShare S) (*copiedSharing[S, P], error) {
	source, holders, err := x.agreeSource(ctx, local)
	if err != nil {
		return nil, err
	}
	self := x.node.config.PartyID
	identity := group.identity()
	root, err := group.decodePoint(source.Root)
	if err != nil || group.pointEqual(root, identity) {
		return nil, errCopySource
	}
	weights := group.weights(source.Players, holders)
	constants := make(map[party.ID]P, len(holders))
	rootFromHolders := group.identity()
	for _, holder := range holders {
		oldPoint, err := group.decodePoint(source.Points[slices.Index(source.Players, holder)])
		if err != nil {
			return nil, errCopySource
		}
		constant := group.pointMultiply(weights[holder], oldPoint)
		constants[holder] = constant
		rootFromHolders = group.pointAdd(rootFromHolders, constant)
	}
	if !group.pointEqual(root, rootFromHolders) {
		return nil, errCopySource
	}

	// Each old holder shares its interpolation contribution as the constant
	// of a new polynomial. Every target provides fresh higher coefficients.
	coefficients := make([]S, threshold+1)
	defer clear(coefficients)
	coefficients[0] = group.zero()
	if holders.Contains(self) {
		coefficients[0] = group.multiply(weights[self], oldShare)
	}
	for i := 1; i < len(coefficients); i++ {
		coefficients[i] = group.random()
	}
	commitments := make([][]byte, len(coefficients))
	for i, coefficient := range coefficients {
		commitments[i] = group.encodePoint(group.baseMultiply(coefficient))
	}
	encoded, err := json.Marshal(commitments)
	if err != nil {
		return nil, err
	}
	if err := x.send(ctx, copyCommitRound, "", encoded); err != nil {
		return nil, err
	}
	received, err := x.collect(ctx, copyCommitRound)
	if err != nil {
		return nil, err
	}
	received[self] = encoded
	aggregate := make([]P, len(coefficients))
	for i := range aggregate {
		aggregate[i] = group.identity()
	}
	byDealer := make(map[party.ID][]P, len(x.players))
	manifest, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	hash.Write(x.binding[:])
	sourceDigest := sha256.Sum256(manifest)
	hash.Write(sourceDigest[:])
	for _, player := range x.players {
		raw := received[player]
		var dealer [][]byte
		if err := json.Unmarshal(raw, &dealer); err != nil || len(dealer) != len(coefficients) {
			return nil, errors.New("invalid key copy commitments")
		}
		digest := sha256.Sum256(raw)
		hash.Write(digest[:])
		points := make([]P, len(dealer))
		for i, data := range dealer {
			point, err := group.decodePoint(data)
			if err != nil {
				return nil, err
			}
			points[i] = point
			aggregate[i] = group.pointAdd(aggregate[i], point)
		}
		expected, ok := constants[player]
		if !ok {
			expected = identity
		}
		if !group.pointEqual(points[0], expected) {
			return nil, errors.New("key copy constant does not match the source share")
		}
		byDealer[player] = points
	}
	if !group.pointEqual(aggregate[0], root) || group.pointEqual(aggregate[threshold], identity) {
		return nil, errors.New("invalid target polynomial or threshold")
	}

	targetCoordinates := group.coordinates(x.players)
	evaluations := x.received[copyShareRound]
	defer func() {
		for _, data := range evaluations {
			clear(data)
		}
	}()
	var own S
	for _, player := range x.players {
		coordinate := targetCoordinates[player]
		value := group.zero()
		for i := len(coefficients) - 1; i >= 0; i-- {
			value = group.add(group.multiply(value, coordinate), coefficients[i])
		}
		if player == self {
			own = value
			continue
		}
		data := group.encodeScalar(value)
		err := x.send(ctx, copyShareRound, player, data)
		clear(data)
		if err != nil {
			return nil, err
		}
	}
	if _, err := x.collect(ctx, copyShareRound); err != nil {
		return nil, err
	}
	evaluatePoints := func(points []P, coordinate S) P {
		value := group.identity()
		for i := len(points) - 1; i >= 0; i-- {
			value = group.pointAdd(group.pointMultiply(coordinate, value), points[i])
		}
		return value
	}
	secret := group.zero()
	for _, player := range x.players {
		value := own
		if player != self {
			value, err = group.decodeScalar(evaluations[player])
			if err != nil {
				return nil, err
			}
		}
		if !group.pointEqual(group.baseMultiply(value), evaluatePoints(byDealer[player], targetCoordinates[self])) {
			return nil, errors.New("key copy evaluation does not match its commitments")
		}
		secret = group.add(secret, value)
	}
	points := make(map[party.ID]P, len(x.players))
	for _, player := range x.players {
		point := evaluatePoints(aggregate, targetCoordinates[player])
		if group.pointEqual(point, identity) || group.pointEqual(point, root) {
			return nil, errors.New("degenerate copied public share")
		}
		points[player] = point
	}
	result := &copiedSharing[S, P]{secret: secret, points: points, source: source}
	copy(result.transcript[:], hash.Sum(nil))
	return result, nil
}
