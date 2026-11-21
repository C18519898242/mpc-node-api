package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func (n *node) copyECDSA(ctx context.Context, x *copyExchange, session *keygenSession, sourceID string) ([]byte, [32]byte, error) {
	return n.transferECDSA(ctx, x, session, sourceID, nil, nil)
}

func (n *node) transferECDSA(ctx context.Context, x *copyExchange, session *keygenSession, sourceID string, path []uint32, imported []byte) ([]byte, [32]byte, error) {
	var source *copySource
	var secret curve.Scalar
	var digest [32]byte
	group := curve.Secp256k1{}
	vss := secp256k1CopyGroup(group)
	if sourceID != "" {
		var key *cmp.Config
		var err error
		if imported != nil {
			key, err = n.decodeCMPShare(imported)
		} else {
			key, err = n.loadECDSAShare(ctx, sourceID, path)
		}
		if err != nil {
			return nil, digest, err
		}
		source = &copySource{
			KeyID: sourceID, Players: key.PartyIDs(), Threshold: key.Threshold,
			Root: vss.encodePoint(key.PublicPoint()), ChainCode: key.ChainKey,
		}
		for _, id := range source.Players {
			source.Points = append(source.Points, vss.encodePoint(key.Public[id].ECDSA))
		}
		secret = key.ECDSA
		defer secret.Set(group.NewScalar())
	}
	copied, err := transferShares(ctx, x, session.key.Threshold, vss, source, secret)
	if err != nil {
		return nil, digest, err
	}
	if len(copied.source.ChainCode) != 32 {
		return nil, digest, errors.New("invalid source ECDSA chain code")
	}
	// CMP keygen establishes fresh proven auxiliary keys for the target group.
	// The verified transfer supplies that group's ECDSA shares and chain code.
	protocolID := sha256.Sum256(append([]byte("keycopy/cmp-aux/"), copied.transcript[:]...))
	aux, err := n.executeKeygen(ctx, x.route, protocolID[:], session.key.Threshold, x.players, session.incoming)
	if err != nil {
		return nil, digest, err
	}
	aux.ECDSA = copied.secret
	aux.ChainKey = copied.source.ChainCode
	for player, point := range copied.points {
		aux.Public[player].ECDSA = point
	}
	if !bytes.Equal(vss.encodePoint(aux.PublicPoint()), copied.source.Root) {
		return nil, digest, errors.New("copied ECDSA public key differs from source")
	}
	hash := sha256.New()
	hash.Write(copied.transcript[:])
	if _, err := aux.WriteTo(hash); err != nil {
		return nil, digest, err
	}
	copy(digest[:], hash.Sum(nil))
	encoded, err := aux.MarshalBinary()
	return encoded, digest, err
}

func secp256k1CopyGroup(group curve.Secp256k1) copyGroup[curve.Scalar, curve.Point] {
	return copyGroup[curve.Scalar, curve.Point]{
		zero: group.NewScalar,
		random: func() curve.Scalar {
			return sample.Scalar(rand.Reader, group)
		},
		coordinates: func(players party.IDSlice) map[party.ID]curve.Scalar {
			coordinates := make(map[party.ID]curve.Scalar, len(players))
			for _, player := range players {
				coordinates[player] = player.Scalar(group)
			}
			return coordinates
		},
		weights: func(_, holders party.IDSlice) map[party.ID]curve.Scalar {
			return polynomial.Lagrange(group, holders)
		},
		add:          func(a, b curve.Scalar) curve.Scalar { return group.NewScalar().Set(a).Add(b) },
		multiply:     func(a, b curve.Scalar) curve.Scalar { return group.NewScalar().Set(a).Mul(b) },
		encodeScalar: func(s curve.Scalar) []byte { data, _ := s.MarshalBinary(); return data },
		decodeScalar: func(data []byte) (curve.Scalar, error) {
			scalar := group.NewScalar()
			return scalar, scalar.UnmarshalBinary(data)
		},
		identity:      group.NewPoint,
		baseMultiply:  curve.Scalar.ActOnBase,
		pointAdd:      curve.Point.Add,
		pointMultiply: curve.Scalar.Act,
		pointEqual:    curve.Point.Equal,
		encodePoint: func(point curve.Point) []byte {
			if point.IsIdentity() {
				return []byte{0}
			}
			data, _ := point.MarshalBinary()
			return data
		},
		decodePoint: func(data []byte) (curve.Point, error) {
			point := group.NewPoint()
			if len(data) == 1 && data[0] == 0 {
				return point, nil
			}
			if len(data) != 33 || (data[0] != 2 && data[0] != 3) {
				return nil, errors.New("invalid secp256k1 commitment")
			}
			return point, point.UnmarshalBinary(data)
		},
	}
}

func (n *node) copyFROST(ctx context.Context, x *copyExchange, session *keygenSession, sourceID string) ([]byte, [32]byte, error) {
	return n.transferFROST(ctx, x, session, sourceID, nil, nil)
}

func (n *node) transferFROST(ctx context.Context, x *copyExchange, session *keygenSession, sourceID string, path []uint32, imported []byte) ([]byte, [32]byte, error) {
	var source *copySource
	var secret *ristretto.Scalar
	var digest [32]byte
	vss := frostCopyGroup()
	if sourceID != "" {
		var key *storedFROSTShare
		var err error
		if imported != nil {
			key, err = n.decodeFROSTSigningShare(imported)
		} else {
			key, err = n.loadFROSTSigningShare(ctx, sourceID)
		}
		if err != nil {
			return nil, digest, err
		}
		code := key.chainCode()
		if len(path) != 0 {
			_, derivedCode, err := key.Public.GroupKey.Derive(code, path)
			if err != nil {
				return nil, digest, err
			}
			secretKey, public, err := key.Public.DeriveShare(key.SecretKey, code, path)
			if err != nil {
				return nil, digest, err
			}
			key.Output = keygen.Output{SecretKey: secretKey, Public: public}
			code = derivedCode
		}
		source = &copySource{KeyID: sourceID, Players: key.Players, Threshold: int(key.Public.Threshold), ChainCode: code[:]}
		root := ristretto.NewIdentityElement()
		for _, id := range key.Public.PartyIDs {
			point := key.Public.Shares[id]
			source.Points = append(source.Points, point.Bytes())
			weight, err := id.Lagrange(key.Public.PartyIDs)
			if err != nil {
				return nil, digest, err
			}
			root.Add(root, new(ristretto.Element).ScalarMult(weight, point))
		}
		source.Root = root.Bytes()
		secret = &key.SecretKey.Secret
		defer secret.Set(ristretto.NewScalar())
	}
	copied, err := transferShares(ctx, x, session.key.Threshold, vss, source, secret)
	if err != nil {
		return nil, digest, err
	}
	defer copied.secret.Set(ristretto.NewScalar())
	ids, _ := frostIDsFor(x.players)
	points := make(map[frostparty.ID]*ristretto.Element, len(ids))
	for player, point := range copied.points {
		points[ids[player]] = point
	}
	public, err := eddsa.NewPublic(points, frostparty.Size(session.key.Threshold))
	if err != nil {
		return nil, digest, err
	}
	root, err := vss.decodePoint(copied.source.Root)
	if err != nil || !public.GroupKey.Equal(eddsa.NewPublicKeyFromPoint(root)) || len(copied.source.ChainCode) != 32 {
		return nil, digest, errors.New("copied FROST public key differs from source")
	}
	output := &keygen.Output{
		Public: public, SecretKey: eddsa.NewSecretShare(ids[n.config.PartyID], copied.secret),
	}
	encoded, err := marshalFROSTShareWithChainCode(output, x.players, copied.source.ChainCode)
	return encoded, copied.transcript, err
}

func frostCopyGroup() copyGroup[*ristretto.Scalar, *ristretto.Element] {
	return copyGroup[*ristretto.Scalar, *ristretto.Element]{
		zero: ristretto.NewScalar,
		random: func() *ristretto.Scalar {
			var random [64]byte
			_, _ = rand.Read(random[:])
			scalar, _ := ristretto.NewScalar().SetUniformBytes(random[:])
			clear(random[:])
			return scalar
		},
		coordinates: func(players party.IDSlice) map[party.ID]*ristretto.Scalar {
			ids, _ := frostIDsFor(players)
			coordinates := make(map[party.ID]*ristretto.Scalar, len(ids))
			for player, id := range ids {
				coordinates[player] = id.Scalar()
			}
			return coordinates
		},
		weights: func(players, holders party.IDSlice) map[party.ID]*ristretto.Scalar {
			ids, _ := frostIDsFor(players)
			selected := make(frostparty.IDSlice, len(holders))
			for i, holder := range holders {
				selected[i] = ids[holder]
			}
			weights := make(map[party.ID]*ristretto.Scalar, len(holders))
			for _, holder := range holders {
				weights[holder], _ = ids[holder].Lagrange(selected)
			}
			return weights
		},
		add:          func(a, b *ristretto.Scalar) *ristretto.Scalar { return ristretto.NewScalar().Add(a, b) },
		multiply:     func(a, b *ristretto.Scalar) *ristretto.Scalar { return ristretto.NewScalar().Multiply(a, b) },
		encodeScalar: (*ristretto.Scalar).Bytes,
		decodeScalar: func(data []byte) (*ristretto.Scalar, error) { return ristretto.NewScalar().SetCanonicalBytes(data) },
		identity:     ristretto.NewIdentityElement,
		baseMultiply: func(s *ristretto.Scalar) *ristretto.Element {
			return new(ristretto.Element).ScalarBaseMult(s)
		},
		pointAdd: func(a, b *ristretto.Element) *ristretto.Element { return new(ristretto.Element).Add(a, b) },
		pointMultiply: func(s *ristretto.Scalar, p *ristretto.Element) *ristretto.Element {
			return new(ristretto.Element).ScalarMult(s, p)
		},
		pointEqual:  func(a, b *ristretto.Element) bool { return a.Equal(b) == 1 },
		encodePoint: (*ristretto.Element).Bytes,
		decodePoint: func(data []byte) (*ristretto.Element, error) { return new(ristretto.Element).SetCanonicalBytes(data) },
	}
}
