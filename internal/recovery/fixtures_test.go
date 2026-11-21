package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func fixture(t *testing.T, algorithm string, der []byte) (Manifest, [][]byte) {
	t.Helper()
	g, err := getGroup(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	root, slope := g.random(), g.random()
	defer clear(root)
	defer clear(slope)
	m := Manifest{Version: 1, Algorithm: algorithm, ApplicationID: "fixture", KeyID: "test-key", SessionID: "test-session", Threshold: 1, Players: []string{"1", "2", "3"}, PublicKey: g.wallet(g.base(root)), ChainCode: bytes.Repeat([]byte{7}, 32), RecoveryKey: der, Label: []byte("test-label")}
	secrets := make([][]byte, 3)
	for i, id := range m.Players {
		secrets[i] = g.add(root, g.mul(slope, g.coordinate(id, i)))
		m.PublicShares = append(m.PublicShares, g.base(secrets[i]))
		t.Cleanup(func() { clear(secrets[i]) })
	}
	return m, secrets
}

func assertRecoveredScalar(t *testing.T, key RecoveredKey) {
	t.Helper()
	message := []byte("offline recovery signing")
	if key.Algorithm == "ecdsa" {
		private := secp256k1.PrivKeyFromBytes(key.PrivateKey)
		defer private.Zero()
		hash := sha256.Sum256(message)
		public, err := secp256k1.ParsePubKey(key.PublicKey)
		if err != nil || !secpECDSA.Sign(private, hash[:]).Verify(hash[:], public) {
			t.Fatal("recovered ECDSA private key cannot sign")
		}
		return
	}
	var scalar, code [32]byte
	copy(scalar[:], key.PrivateKey)
	copy(code[:], key.ChainCode)
	defer clear(scalar[:])
	derived, _, err := eddsa.DeriveSigningScalar(scalar, code, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(derived[:])
	x, _ := ristretto.NewScalar().SetCanonicalBytes(derived[:])
	root, _ := ristretto.NewScalar().SetCanonicalBytes(scalar[:])
	want, _, err := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(root)).Derive(code, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	public := new(ristretto.Element).ScalarBaseMult(x).BytesEd25519()
	if !bytes.Equal(want.ToEd25519(), public) {
		t.Fatal("recovered FROST derivation changed public key")
	}
	nonce := sha512.Sum512([]byte("test-only random nonce fixture"))
	r, _ := ristretto.NewScalar().SetUniformBytes(nonce[:])
	R := new(ristretto.Element).ScalarBaseMult(r).BytesEd25519()
	h := sha512.New()
	h.Write(R)
	h.Write(public)
	h.Write(message)
	c, _ := ristretto.NewScalar().SetUniformBytes(h.Sum(nil))
	s := ristretto.NewScalar().MultiplyAdd(c, x, r)
	signature := append(R, s.Bytes()...)
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("recovered FROST scalar cannot sign Ed25519")
	}
}
