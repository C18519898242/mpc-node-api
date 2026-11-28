package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
)

// Version 1 uses PBKDF2-HMAC-SHA256 and AES-256-GCM with a prefixed random nonce.
const (
	masterKeyVersion    = 1
	masterKeyIterations = 600_000
	masterKeySize       = 32
	masterKeySaltSize   = 16
)

const createMasterKeyTable = `CREATE TABLE IF NOT EXISTS node_master_key (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	format_version INTEGER NOT NULL,
	salt BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

type masterKeyRecord struct {
	version    int
	salt       []byte
	ciphertext []byte
}

// LoadOrCreateMasterKey unlocks the node's existing MK or initializes it once.
// An empty password is allowed only while no MK has been provisioned.
func (s *SQLite) LoadOrCreateMasterKey(ctx context.Context, password string) ([]byte, error) {
	record, err := s.readMasterKey(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		if password == "" {
			return nil, nil
		}
		if err := s.createMasterKey(ctx, password); err != nil {
			return nil, err
		}
		record, err = s.readMasterKey(ctx)
	}
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("master password is required for this database")
	}
	if record.version != masterKeyVersion || len(record.salt) != masterKeySaltSize {
		return nil, errors.New("invalid master key format")
	}
	aead, err := masterKeyCipher(password, record.salt)
	if err != nil {
		return nil, err
	}
	if len(record.ciphertext) != masterKeySize+aead.Overhead() {
		return nil, errors.New("invalid master key ciphertext size")
	}
	key, err := aead.Open(nil, nil, record.ciphertext, s.masterKeyAAD())
	if err != nil {
		return nil, errors.New("could not authenticate the encrypted master key")
	}
	return key, nil
}

func (s *SQLite) readMasterKey(ctx context.Context) (masterKeyRecord, error) {
	var record masterKeyRecord
	err := s.db.QueryRowContext(ctx, "SELECT format_version, salt, ciphertext FROM node_master_key WHERE id = 1").
		Scan(&record.version, &record.salt, &record.ciphertext)
	return record, err
}

func (s *SQLite) createMasterKey(ctx context.Context, password string) error {
	salt := make([]byte, masterKeySaltSize)
	rand.Read(salt)
	aead, err := masterKeyCipher(password, salt)
	if err != nil {
		return err
	}
	key := make([]byte, masterKeySize)
	rand.Read(key)
	defer clear(key)
	ciphertext := aead.Seal(nil, nil, key, s.masterKeyAAD())
	// Every caller reads the persisted winner after a concurrent first start.
	_, err = s.db.ExecContext(ctx, s.insertOrIgnore(`INSERT INTO node_master_key (id, format_version, salt, ciphertext)
		VALUES (1, ?, ?, ?)`, "id"), masterKeyVersion, salt, ciphertext)
	return err
}

func (s *SQLite) masterKeyAAD() []byte {
	return []byte("mpc-node-api/master-key/v1\x00" + s.partyID)
}

func masterKeyCipher(password string, salt []byte) (cipher.AEAD, error) {
	kek, err := pbkdf2.Key(sha256.New, password, salt, masterKeyIterations, masterKeySize)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
