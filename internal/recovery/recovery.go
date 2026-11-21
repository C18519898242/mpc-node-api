// Package recovery implements project-native, publicly verifiable encrypted
// scalar backups and offline reconstruction. It has no network or database code.
package recovery

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
)

var errInvalid = errors.New("invalid emergency recovery data")

type Manifest struct {
	Version       int      `json:"version"`
	Algorithm     string   `json:"algorithm"`
	ApplicationID string   `json:"applicationID"`
	KeyID         string   `json:"keyID"`
	SessionID     string   `json:"sessionID"`
	Threshold     int      `json:"threshold"`
	Players       []string `json:"players"`
	PublicShares  [][]byte `json:"publicShares"`
	PublicKey     []byte   `json:"publicKey"`
	ChainCode     []byte   `json:"chainCode"`
	RecoveryKey   []byte   `json:"recoveryKey"`
	Label         []byte   `json:"label"`
}

type Partial struct {
	Manifest Manifest `json:"manifest"`
	PartyID  string   `json:"partyID"`
	Proof    Proof    `json:"proof"`
}

type Backup struct {
	Version  int       `json:"version"`
	Partials []Partial `json:"partials"`
}

type RecoveredKey struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyID"`
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
	ChainCode  []byte `json:"chainCode"`
}

func ParsePublicKey(der []byte) (*rsa.PublicKey, error) {
	v, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errInvalid
	}
	k, ok := v.(*rsa.PublicKey)
	if !ok || k.N.BitLen() < 2048 || k.N.BitLen() > 8192 || k.N.Bit(0) != 1 || k.E != 65537 {
		return nil, errInvalid
	}
	return k, nil
}

func Generate(m Manifest, player string, secret []byte) (Partial, error) {
	g, key, _, err := validateManifest(m)
	if err != nil {
		return Partial{}, err
	}
	index := slices.Index(m.Players, player)
	if index < 0 || g.scalar(secret) != nil || !bytes.Equal(g.base(secret), m.PublicShares[index]) {
		return Partial{}, errInvalid
	}
	proof, err := prove(g, key, secret, m.PublicShares[index], proofLabel(m, player))
	return Partial{m, player, proof}, err
}

func Combine(partials []Partial, expected []byte, key *rsa.PublicKey, label []byte) (Backup, error) {
	backup := Backup{Version: 1, Partials: partials}
	if err := Validate(backup, expected, key, label); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func Validate(backup Backup, expected []byte, key *rsa.PublicKey, label []byte) error {
	if backup.Version != 1 || len(backup.Partials) < 2 || len(backup.Partials) > 64 || key == nil || key.N == nil {
		return errInvalid
	}
	m := backup.Partials[0].Manifest
	g, parsed, _, err := validateManifest(m)
	if err != nil {
		return err
	}
	if !bytes.Equal(m.PublicKey, expected) || !bytes.Equal(m.Label, label) || parsed.E != key.E || parsed.N.Cmp(key.N) != 0 || len(backup.Partials) <= m.Threshold {
		return errInvalid
	}
	manifest, _ := json.Marshal(m)
	seen := make(map[string]bool)
	for _, p := range backup.Partials {
		encoded, _ := json.Marshal(p.Manifest)
		index := slices.Index(m.Players, p.PartyID)
		if index < 0 || seen[p.PartyID] || !bytes.Equal(manifest, encoded) {
			return errInvalid
		}
		seen[p.PartyID] = true
		if err := verify(g, key, m.PublicShares[index], proofLabel(m, p.PartyID), p.Proof); err != nil {
			return err
		}
	}
	return nil
}

func Recover(backup Backup, expected []byte, key *rsa.PrivateKey, label []byte) (RecoveredKey, error) {
	if key == nil || key.Validate() != nil {
		return RecoveredKey{}, errInvalid
	}
	if err := Validate(backup, expected, &key.PublicKey, label); err != nil {
		return RecoveredKey{}, err
	}
	m := backup.Partials[0].Manifest
	g, _, coordinates, _ := validateManifest(m)
	selected := make([][]byte, len(backup.Partials))
	for i, p := range backup.Partials {
		selected[i] = coordinates[slices.Index(m.Players, p.PartyID)]
	}
	weights := g.weights(make([]byte, 32), selected)
	secret := make([]byte, 32)
	for i, p := range backup.Partials {
		index := slices.Index(m.Players, p.PartyID)
		share, err := decrypt(g, key, m.PublicShares[index], proofLabel(m, p.PartyID), p.Proof)
		if err != nil {
			clear(secret)
			return RecoveredKey{}, err
		}
		next := g.add(secret, g.mul(weights[i], share))
		clear(secret)
		clear(share)
		secret = next
	}
	if !bytes.Equal(g.wallet(g.base(secret)), expected) {
		clear(secret)
		return RecoveredKey{}, errInvalid
	}
	return RecoveredKey{m.Algorithm, m.KeyID, secret, bytes.Clone(expected), bytes.Clone(m.ChainCode)}, nil
}

func validateManifest(m Manifest) (group, *rsa.PublicKey, [][]byte, error) {
	g, err := getGroup(m.Algorithm)
	if err != nil {
		return g, nil, nil, err
	}
	key, err := ParsePublicKey(m.RecoveryKey)
	if err != nil || m.Version != 1 || len(m.Players) < 2 || len(m.Players) > 64 || len(m.PublicShares) != len(m.Players) || m.Threshold < 1 || m.Threshold >= len(m.Players) || len(m.ChainCode) != 32 || len(m.Label) > 1024 || len(m.KeyID) == 0 || len(m.KeyID) > 128 || len(m.SessionID) == 0 || len(m.SessionID) > 128 || len(m.ApplicationID) > 128 {
		return g, nil, nil, errInvalid
	}
	coordinates := make([][]byte, len(m.Players))
	for i, id := range m.Players {
		if len(id) == 0 || len(id) > 32 || id[0] == 0 || (i > 0 && m.Players[i-1] >= id) || g.point(m.PublicShares[i]) != nil {
			return g, nil, nil, errInvalid
		}
		coordinates[i] = g.coordinate(id, i)
		if bytes.Equal(coordinates[i], make([]byte, 32)) {
			return g, nil, nil, errInvalid
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(coordinates[i], coordinates[j]) {
				return g, nil, nil, errInvalid
			}
		}
	}
	count := m.Threshold + 1
	root := g.interpolatePoint(make([]byte, 32), coordinates[:count], m.PublicShares[:count])
	if bytes.Equal(root, g.identity) || !bytes.Equal(g.wallet(root), m.PublicKey) {
		return g, nil, nil, errInvalid
	}
	for i := count; i < len(m.Players); i++ {
		if !bytes.Equal(g.interpolatePoint(coordinates[i], coordinates[:count], m.PublicShares[:count]), m.PublicShares[i]) {
			return g, nil, nil, errInvalid
		}
	}
	return g, key, coordinates, nil
}

func proofLabel(m Manifest, player string) []byte {
	encoded, _ := json.Marshal(struct {
		Domain   string
		Manifest Manifest
		Player   string
	}{"mpc-node-api/emergency-recovery/v1", m, player})
	digest := sha256.Sum256(encoded)
	return digest[:]
}
