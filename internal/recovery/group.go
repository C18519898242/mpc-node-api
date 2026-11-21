package recovery

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Internal arithmetic accepts only scalars and points validated at the boundary.
type group struct {
	random                       func() []byte
	scalar                       func([]byte) error
	point                        func([]byte) error
	add, sub, mul                func([]byte, []byte) []byte
	inv                          func([]byte) []byte
	base                         func([]byte) []byte
	pointAdd, pointSub, pointMul func([]byte, []byte) []byte
	wallet                       func([]byte) []byte
	coordinate                   func(string, int) []byte
	identity                     []byte
	one                          []byte
}

func getGroup(algorithm string) (group, error) {
	if algorithm == "ecdsa" {
		c := curve.Secp256k1{}
		s := func(b []byte) curve.Scalar { v := c.NewScalar(); _ = v.UnmarshalBinary(b); return v }
		p := func(b []byte) curve.Point {
			v := c.NewPoint()
			if !bytes.Equal(b, []byte{0}) {
				_ = v.UnmarshalBinary(b)
			}
			return v
		}
		es := func(v curve.Scalar) []byte { b, _ := v.MarshalBinary(); return b }
		ep := func(v curve.Point) []byte {
			if v.IsIdentity() {
				return []byte{0}
			}
			b, _ := v.MarshalBinary()
			return b
		}
		one := make([]byte, 32)
		one[31] = 1
		return group{
			random: func() []byte { return es(sample.Scalar(rand.Reader, c)) },
			scalar: func(b []byte) error {
				if len(b) != 32 {
					return errInvalid
				}
				return c.NewScalar().UnmarshalBinary(b)
			},
			point: func(b []byte) error {
				if bytes.Equal(b, []byte{0}) {
					return nil
				}
				if len(b) != 33 || (b[0] != 2 && b[0] != 3) {
					return errInvalid
				}
				return c.NewPoint().UnmarshalBinary(b)
			},
			add:      func(a, b []byte) []byte { return es(s(a).Add(s(b))) },
			sub:      func(a, b []byte) []byte { return es(s(a).Sub(s(b))) },
			mul:      func(a, b []byte) []byte { return es(s(a).Mul(s(b))) },
			inv:      func(a []byte) []byte { return es(s(a).Invert()) },
			base:     func(a []byte) []byte { return ep(s(a).ActOnBase()) },
			pointAdd: func(a, b []byte) []byte { return ep(p(a).Add(p(b))) },
			pointSub: func(a, b []byte) []byte { return ep(p(a).Sub(p(b))) },
			pointMul: func(a, b []byte) []byte { return ep(s(a).Act(p(b))) },
			wallet: func(a []byte) []byte {
				pub, err := secp256k1.ParsePubKey(a)
				if err != nil {
					return nil
				}
				return pub.SerializeUncompressed()
			},
			coordinate: func(id string, _ int) []byte { return es(party.ID(id).Scalar(c)) },
			identity:   []byte{0}, one: one,
		}, nil
	}
	if algorithm != "frost" {
		return group{}, errors.New("unsupported recovery algorithm")
	}
	s := func(b []byte) *ristretto.Scalar { v, _ := ristretto.NewScalar().SetCanonicalBytes(b); return v }
	p := func(b []byte) *ristretto.Element { v, _ := new(ristretto.Element).SetCanonicalBytes(b); return v }
	one := make([]byte, 32)
	one[0] = 1
	return group{
		random: func() []byte {
			var b [64]byte
			_, _ = rand.Read(b[:])
			v, _ := ristretto.NewScalar().SetUniformBytes(b[:])
			clear(b[:])
			return v.Bytes()
		},
		scalar:   func(b []byte) error { _, err := ristretto.NewScalar().SetCanonicalBytes(b); return err },
		point:    func(b []byte) error { _, err := new(ristretto.Element).SetCanonicalBytes(b); return err },
		add:      func(a, b []byte) []byte { return ristretto.NewScalar().Add(s(a), s(b)).Bytes() },
		sub:      func(a, b []byte) []byte { return ristretto.NewScalar().Subtract(s(a), s(b)).Bytes() },
		mul:      func(a, b []byte) []byte { return ristretto.NewScalar().Multiply(s(a), s(b)).Bytes() },
		inv:      func(a []byte) []byte { return ristretto.NewScalar().Invert(s(a)).Bytes() },
		base:     func(a []byte) []byte { return new(ristretto.Element).ScalarBaseMult(s(a)).Bytes() },
		pointAdd: func(a, b []byte) []byte { return new(ristretto.Element).Add(p(a), p(b)).Bytes() },
		pointSub: func(a, b []byte) []byte { return new(ristretto.Element).Subtract(p(a), p(b)).Bytes() },
		pointMul: func(a, b []byte) []byte { return new(ristretto.Element).ScalarMult(s(a), p(b)).Bytes() },
		wallet:   func(a []byte) []byte { return p(a).BytesEd25519() },
		coordinate: func(_ string, index int) []byte {
			b := make([]byte, 32)
			binary.LittleEndian.PutUint16(b, uint16(index+1))
			return b
		},
		identity: ristretto.NewIdentityElement().Bytes(), one: one,
	}, nil
}

func (g group) weights(at []byte, coordinates [][]byte) [][]byte {
	weights := make([][]byte, len(coordinates))
	for i, x := range coordinates {
		w := bytes.Clone(g.one)
		for j, y := range coordinates {
			if i != j {
				w = g.mul(w, g.mul(g.sub(at, y), g.inv(g.sub(x, y))))
			}
		}
		weights[i] = w
	}
	return weights
}

func (g group) interpolatePoint(at []byte, coordinates, points [][]byte) []byte {
	result := bytes.Clone(g.identity)
	for i, w := range g.weights(at, coordinates) {
		result = g.pointAdd(result, g.pointMul(w, points[i]))
	}
	return result
}
