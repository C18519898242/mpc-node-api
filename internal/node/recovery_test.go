package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/recovery"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestRecoveryFeaturePolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for _, cfg := range []*config.EmergencyRecoveryConfig{nil, {}, {Enabled: false, PublicKeys: [][]byte{der}}} {
		n := newNode(config.Config{EmergencyRecovery: cfg, KeyTransfer: &config.KeyTransferConfig{ExportEnabled: true}})
		n.wrappingKey = key
		for _, algorithm := range []string{"ecdsa", "frost"} {
			w := httptest.NewRecorder()
			n.restHandler().ServeHTTP(w, httptest.NewRequest("POST", "/"+algorithm+"/keys/fixture/recoverydata", nil))
			if w.Code != 403 {
				t.Fatalf("%s recovery default returned %d", algorithm, w.Code)
			}
		}
	}
	n := newNode(config.Config{EmergencyRecovery: &config.EmergencyRecoveryConfig{Enabled: true}})
	if n.configureEmergencyRecovery() == nil {
		t.Fatal("enabled recovery without trusted keys was accepted")
	}
	n.config.EmergencyRecovery.PublicKeys = [][]byte{[]byte("invalid")}
	if n.configureEmergencyRecovery() == nil {
		t.Fatal("invalid recovery RSA key was accepted")
	}
	n.config.EmergencyRecovery.PublicKeys = [][]byte{der}
	if err := n.configureEmergencyRecovery(); err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	body, _ := json.Marshal(map[string]any{"recoveryKey": otherDER})
	r := httptest.NewRequest("POST", "/ecdsa/keys/fixture/recoverydata", bytes.NewReader(body))
	r.Header.Set("MPC-SessionID", "fixture")
	w := httptest.NewRecorder()
	n.restHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("untrusted RSA recipient returned %d", w.Code)
	}
}

func assertRecoveredDerivation(t *testing.T, algorithm string, key recovery.RecoveredKey, expected []byte) {
	t.Helper()
	message := []byte("recovered offline signing")
	if algorithm == "ecdsa" {
		private := secp256k1.PrivKeyFromBytes(key.PrivateKey)
		defer private.Zero()
		chain := bytes.Clone(key.ChainCode)
		for _, index := range []uint32{0, 1} {
			h := hmac.New(sha512.New, chain)
			h.Write(private.PubKey().SerializeCompressed())
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], index)
			h.Write(b[:])
			material := h.Sum(nil)
			var tweak secp256k1.ModNScalar
			if tweak.SetByteSlice(material[:32]) || tweak.IsZero() {
				t.Fatal("invalid BIP32 index")
			}
			private.Key.Add(&tweak)
			tweak.Zero()
			copy(chain, material[32:])
			clear(material)
		}
		hash := sha256.Sum256(message)
		pub, err := secp256k1.ParsePubKey(expected)
		if err != nil || !bytes.Equal(private.PubKey().SerializeUncompressed(), expected) || !secpECDSA.Sign(private, hash[:]).Verify(hash[:], pub) {
			t.Fatal("recovered ECDSA derivation or signing differs from node")
		}
		return
	}
	var root, code [32]byte
	copy(root[:], key.PrivateKey)
	copy(code[:], key.ChainCode)
	defer clear(root[:])
	child, _, err := eddsa.DeriveSigningScalar(root, code, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(child[:])
	x, _ := ristretto.NewScalar().SetCanonicalBytes(child[:])
	defer x.Set(ristretto.NewScalar())
	public := new(ristretto.Element).ScalarBaseMult(x).BytesEd25519()
	if !bytes.Equal(public, expected) {
		t.Fatal("recovered FROST derivation differs from node")
	}
	var random [64]byte
	_, _ = rand.Read(random[:])
	r, _ := ristretto.NewScalar().SetUniformBytes(random[:])
	clear(random[:])
	defer r.Set(ristretto.NewScalar())
	R := new(ristretto.Element).ScalarBaseMult(r).BytesEd25519()
	h := sha512.New()
	h.Write(R)
	h.Write(public)
	h.Write(message)
	c, _ := ristretto.NewScalar().SetUniformBytes(h.Sum(nil))
	s := ristretto.NewScalar().MultiplyAdd(c, x, r)
	if !ed25519.Verify(expected, message, append(R, s.Bytes()...)) {
		t.Fatal("recovered FROST scalar cannot sign offline")
	}
}
