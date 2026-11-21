package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const proofRounds = 128

type Round struct {
	Scalar     []byte `json:"scalar"`
	Seed       []byte `json:"seed"`
	Ciphertext []byte `json:"ciphertext"`
}

type Proof struct {
	Challenge []byte  `json:"challenge"`
	Rounds    []Round `json:"rounds"`
}

// Basic additive cut-and-choose PVE, with independently sampled masks rather
// than the seed-compressed representation. See docs/emergency-recovery.md.
func prove(g group, key *rsa.PublicKey, secret, public, label []byte) (Proof, error) {
	type pair struct{ scalars, seeds, ciphertexts, points [2][]byte }
	pairs := make([]pair, proofRounds)
	defer func() {
		for _, p := range pairs {
			for j := range 2 {
				clear(p.scalars[j])
				clear(p.seeds[j])
			}
		}
	}()
	h := transcript(key, public, label)
	for i := range pairs {
		p := &pairs[i]
		p.scalars[0] = g.random()
		p.scalars[1] = g.sub(secret, p.scalars[0])
		for j := range 2 {
			p.seeds[j] = make([]byte, 32)
			_, _ = rand.Read(p.seeds[j])
			var err error
			p.ciphertexts[j], err = encrypt(key, p.scalars[j], p.seeds[j], label)
			if err != nil {
				return Proof{}, err
			}
			p.points[j] = g.base(p.scalars[j])
		}
		writePair(h, p.ciphertexts, p.points)
	}
	challenge := h.Sum(nil)[:proofRounds/8]
	proof := Proof{Challenge: challenge, Rounds: make([]Round, proofRounds)}
	for i, p := range pairs {
		j := int((challenge[i/8] >> (i % 8)) & 1)
		proof.Rounds[i] = Round{bytes.Clone(p.scalars[j]), bytes.Clone(p.seeds[j]), p.ciphertexts[1-j]}
	}
	return proof, nil
}

func verify(g group, key *rsa.PublicKey, public, label []byte, proof Proof) error {
	if len(proof.Challenge) != proofRounds/8 || len(proof.Rounds) != proofRounds {
		return errInvalid
	}
	h := transcript(key, public, label)
	for i, r := range proof.Rounds {
		if g.scalar(r.Scalar) != nil || len(r.Seed) != 32 || len(r.Ciphertext) != key.Size() {
			return errInvalid
		}
		opened, err := encrypt(key, r.Scalar, r.Seed, label)
		if err != nil {
			return errInvalid
		}
		j := int((proof.Challenge[i/8] >> (i % 8)) & 1)
		var ciphertexts, points [2][]byte
		ciphertexts[j], ciphertexts[1-j] = opened, r.Ciphertext
		points[j] = g.base(r.Scalar)
		points[1-j] = g.pointSub(public, points[j])
		writePair(h, ciphertexts, points)
	}
	if !bytes.Equal(h.Sum(nil)[:proofRounds/8], proof.Challenge) {
		return errInvalid
	}
	return nil
}

func decrypt(g group, key *rsa.PrivateKey, public, label []byte, proof Proof) ([]byte, error) {
	// Restore soundness guarantees at least one correct unopened ciphertext,
	// not that every unopened ciphertext must be correct.
	for _, r := range proof.Rounds {
		plain, err := rsa.DecryptOAEP(sha256.New(), nil, key, r.Ciphertext, label)
		if err != nil {
			continue
		}
		if g.scalar(plain) != nil {
			clear(plain)
			continue
		}
		secret := g.add(plain, r.Scalar)
		clear(plain)
		if bytes.Equal(g.base(secret), public) {
			return secret, nil
		}
		clear(secret)
	}
	return nil, errInvalid
}

func encrypt(key *rsa.PublicKey, scalar, seed, label []byte) ([]byte, error) {
	// OAEP-SHA256 consumes exactly 32 seed bytes. Fail closed if a future Go
	// implementation changes that contract; protocol round-trip tests cover it.
	reader := bytes.NewReader(seed)
	result, err := rsa.EncryptOAEP(sha256.New(), reader, key, scalar, label)
	if err != nil || reader.Len() != 0 {
		return nil, errInvalid
	}
	return result, nil
}

func transcript(key *rsa.PublicKey, public, label []byte) hash.Hash {
	h := sha256.New()
	writeParts(h, []byte("mpc-node-api/recovery/pve-additive-rsa-oaep-sha256/v1"), key.N.Bytes())
	var exponent [8]byte
	binary.BigEndian.PutUint64(exponent[:], uint64(key.E))
	writeParts(h, exponent[:], public, label)
	return h
}

func writePair(h hash.Hash, ciphertexts, points [2][]byte) {
	for j := range 2 {
		writeParts(h, ciphertexts[j], points[j])
	}
}

func writeParts(h hash.Hash, parts ...[]byte) {
	for _, p := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(p)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(p)
	}
}
