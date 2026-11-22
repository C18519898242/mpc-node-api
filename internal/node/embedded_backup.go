package node

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// Version 1 authenticates the compact JSON encoding of this header as GCM AAD.
// Keep its field order stable for independently implemented backup readers.
type mobileBackupHeader struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"salt"`
}

type mobileShareBackup struct {
	mobileBackupHeader
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// ExportKeyShare exports only this device's root protocol share. The independent
// backup password protects the portable file; neither MK nor presignatures leave.
func (e *Embedded) ExportKeyShare(algorithm, keyID, password string) (encoded string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := mobileCurve(algorithm); err != nil {
		return "", err
	}
	start := time.Now()
	defer func() { e.node.logMPCResult("exportkeyshare", algorithm, "backup", start, err) }()
	if e.closed || e.ctx.Err() != nil {
		return "", errors.New("mobile node is closed")
	}
	if !keyIDPattern.MatchString(keyID) {
		return "", errors.New("invalid mobile backup key ID")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 16 || strings.TrimSpace(password) == "" {
		return "", errors.New("backup password must contain at least 16 characters")
	}
	ctx := context.WithValue(e.ctx, applicationContextKey{}, e.application)
	pending, err := e.store.PendingReshare(ctx, e.application, algorithm, keyID)
	if err != nil || pending {
		return "", errors.New("could not export a key with pending refresh")
	}
	backup, err := e.store.ExportKeyShare(ctx, e.application, algorithm, keyID)
	if err != nil {
		return "", errors.New("could not read local key share")
	}
	defer clear(backup.Share)
	threshold, players, _, err := e.node.transferShareInfo(algorithm, backup.Share)
	if err != nil || threshold != backup.Key.Threshold || !players.Contains(e.node.config.PartyID) {
		return "", errors.New("invalid local key share")
	}
	plain, err := json.Marshal(localKeySharePayload{
		Version: 1, Kind: localKeyShareKind, PartyID: string(e.node.config.PartyID), ApplicationID: e.application, Backup: backup,
	})
	defer clear(plain)
	if err != nil || len(plain) > (1<<18)-28 {
		return "", errors.New("could not encode local key share")
	}
	envelope := mobileShareBackup{mobileBackupHeader: mobileBackupHeader{
		Version: 1, Kind: "mpc-node-api/mobile-key-share-backup", KDF: "PBKDF2-HMAC-SHA256",
		Iterations: 600_000, Cipher: "AES-256-GCM", Salt: make([]byte, 16),
	}}
	if _, err := rand.Read(envelope.Salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, envelope.Salt, envelope.Iterations, 32)
	if err != nil {
		return "", err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	envelope.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(envelope.Nonce); err != nil {
		return "", err
	}
	aad, _ := json.Marshal(envelope.mobileBackupHeader)
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, plain, aad)
	if err := e.ctx.Err(); err != nil {
		return "", err
	}
	data, err := json.Marshal(envelope)
	return string(data), err
}
