package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"testing"
)

func TestRecoveryRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	for _, algorithm := range []string{"ecdsa", "frost"} {
		t.Run(algorithm, func(t *testing.T) {
			m, secrets := fixture(t, algorithm, der)
			partials := make([]Partial, 3)
			for i := range partials {
				partials[i], err = Generate(m, m.Players[i], secrets[i])
				if err != nil {
					t.Fatal(err)
				}
			}
			// The key has threshold 1: any two original shares must suffice.
			backup, err := Combine(partials[1:], m.PublicKey, &rsaKey.PublicKey, m.Label)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Recover(backup, m.PublicKey, rsaKey, m.Label)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(got.PrivateKey)
			if !bytes.Equal(got.PublicKey, m.PublicKey) || !bytes.Equal(got.ChainCode, m.ChainCode) {
				t.Fatal("recovery changed public key or chain code")
			}
			assertRecoveredScalar(t, got)
			if _, err := Combine(partials[:1], m.PublicKey, &rsaKey.PublicKey, m.Label); err == nil {
				t.Fatal("accepted fewer than threshold+1 shares")
			}
			if _, err := Combine([]Partial{partials[0], partials[0]}, m.PublicKey, &rsaKey.PublicKey, m.Label); err == nil {
				t.Fatal("accepted duplicate shares")
			}
			if err := Validate(backup, m.PublicKey, &rsaKey.PublicKey, []byte("wrong label")); err == nil {
				t.Fatal("accepted wrong label")
			}
			if err := Validate(backup, []byte("wrong public key"), &rsaKey.PublicKey, m.Label); err == nil {
				t.Fatal("accepted wrong public key")
			}
			wrongRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
			if _, err := Recover(backup, m.PublicKey, wrongRSA, m.Label); err == nil {
				t.Fatal("accepted wrong RSA key")
			}
			for _, change := range []func(*Backup){
				func(b *Backup) { b.Partials[0].Proof.Rounds[0].Ciphertext[0] ^= 1 },
				func(b *Backup) { b.Partials[0].Proof.Rounds[0].Scalar[0] ^= 1 },
				func(b *Backup) { b.Partials[0].Proof.Rounds[0].Seed[0] ^= 1 },
				func(b *Backup) { b.Partials[0].Proof.Challenge[0] ^= 1 },
				func(b *Backup) { b.Partials[0].Manifest.ChainCode[0] ^= 1 },
				func(b *Backup) { b.Partials[0].Manifest.SessionID = "another session" },
				func(b *Backup) { b.Partials[0].Manifest.ApplicationID = "another app" },
				func(b *Backup) { b.Partials[0].Manifest.Threshold = 0 },
				func(b *Backup) { b.Partials[0].Proof.Rounds = b.Partials[0].Proof.Rounds[:127] },
			} {
				encoded, _ := json.Marshal(backup)
				var bad Backup
				_ = json.Unmarshal(encoded, &bad)
				change(&bad)
				if err := Validate(bad, m.PublicKey, &rsaKey.PublicKey, m.Label); err == nil {
					t.Fatal("accepted tampered backup")
				}
			}
		})
	}
}

func TestRejectMalformedRecoveryMaterial(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for _, algorithm := range []string{"ecdsa", "frost"} {
		m, secrets := fixture(t, algorithm, der)
		for _, change := range []func(*Manifest){
			func(m *Manifest) { m.Version = 9 },
			func(m *Manifest) { m.Algorithm = "unsupported" },
			func(m *Manifest) { m.Threshold = -1 },
			func(m *Manifest) { m.Threshold = len(m.Players) },
			func(m *Manifest) { m.Players[1] = m.Players[0] },
			func(m *Manifest) { m.Players[0], m.Players[1] = m.Players[1], m.Players[0] },
			func(m *Manifest) { m.PublicShares[0] = []byte{255} },
			func(m *Manifest) { m.PublicShares[2] = m.PublicShares[0] },
			func(m *Manifest) { m.ChainCode = nil },
			func(m *Manifest) { m.RecoveryKey = nil },
			func(m *Manifest) { m.Label = make([]byte, 1025) },
		} {
			encoded, _ := json.Marshal(m)
			var bad Manifest
			_ = json.Unmarshal(encoded, &bad)
			change(&bad)
			if _, err := Generate(bad, m.Players[0], secrets[0]); err == nil {
				t.Fatal("accepted malformed recovery material")
			}
		}
		if _, err := Generate(m, m.Players[0], secrets[1]); err == nil {
			t.Fatal("accepted a secret that differs from the public share")
		}
		if _, err := Generate(m, m.Players[0], []byte{1}); err == nil {
			t.Fatal("accepted a malformed secret scalar")
		}
	}
}
