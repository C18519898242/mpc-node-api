package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
)

const (
	plaintextShare  = 0
	encryptedShare  = 1
	keySharePurpose = "key"
)

// ShareCipher derives a CEK on demand and borrows the caller's MK for the
// duration of the node. The caller clears the MK after the node stops.
type ShareCipher struct {
	masterKey []byte
	partyID   string
}

func NewShareCipher(masterKey []byte, partyID string) *ShareCipher {
	return &ShareCipher{masterKey: masterKey, partyID: partyID}
}

func (c *ShareCipher) Seal(purpose, appID, algorithm, keyID string, data []byte) ([]byte, error) {
	aead, aad, err := c.cipher(purpose, appID, algorithm, keyID)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, data, aad), nil
}

func (c *ShareCipher) Open(purpose, appID, algorithm, keyID string, data []byte) ([]byte, error) {
	aead, aad, err := c.cipher(purpose, appID, algorithm, keyID)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, data, aad)
}

func (c *ShareCipher) cipher(purpose, appID, algorithm, keyID string) (cipher.AEAD, []byte, error) {
	if len(c.masterKey) != masterKeySize {
		return nil, nil, errors.New("invalid master key size")
	}
	info := fmt.Sprintf("mpc-node-api/share/v1\x00%q\x00%q\x00%q\x00%q\x00%q", c.partyID, purpose, appID, algorithm, keyID)
	cek, err := hkdf.Key(sha256.New, c.masterKey, nil, info, 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(cek)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	return aead, []byte(info), err
}

func resharePurpose(sessionID string) string {
	return "reshare:" + sessionID
}

func presignPurpose(presignatureID string) string {
	return "presign:" + presignatureID
}

func (s *SQLite) sealShare(purpose, appID, algorithm, keyID string, data []byte) ([]byte, int, error) {
	if s.shareCipher == nil {
		if s.mysql {
			return nil, 0, errors.New("mysql share storage requires master key encryption")
		}
		return data, plaintextShare, nil
	}
	sealed, err := s.shareCipher.Seal(purpose, appID, algorithm, keyID, data)
	return sealed, encryptedShare, err
}

func (s *SQLite) openShare(format int, purpose, appID, algorithm, keyID string, data []byte) ([]byte, error) {
	switch {
	case format == plaintextShare && s.shareCipher == nil && !s.mysql:
		return data, nil
	case format == encryptedShare && s.shareCipher != nil:
		return s.shareCipher.Open(purpose, appID, algorithm, keyID, data)
	default:
		clear(data)
		return nil, errors.New("key share storage format does not match encryption configuration")
	}
}

// EnableShareEncryption migrates private shares and presignatures before serving requests.
func (s *SQLite) EnableShareEncryption(ctx context.Context, c *ShareCipher) error {
	if c == nil {
		return errors.New("master key cipher is required")
	}
	if s.mysql {
		for _, table := range []string{"key_shares", "reshare_sessions", "ecdsa_presignatures", "frost_presignatures"} {
			var hasPlaintext bool
			if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE share IS NOT NULL AND share_format = ?)", plaintextShare).
				Scan(&hasPlaintext); err != nil {
				return fmt.Errorf("check %s encryption: %w", table, err)
			}
			if hasPlaintext {
				return fmt.Errorf("mysql table %s contains unencrypted shares; migrate into a clean encrypted database", table)
			}
		}
		s.shareCipher = c
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"key_shares", "reshare_sessions", "ecdsa_presignatures", "frost_presignatures"} {
		if err := encryptStoredShares(ctx, tx, c, table); err != nil {
			return fmt.Errorf("encrypt %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.shareCipher = c
	return nil
}

func encryptStoredShares(ctx context.Context, tx *sql.Tx, c *ShareCipher, table string) error {
	const maxRowID = int64(1<<63 - 1)
	const selectShare = `SELECT rowid, application_id, %s, %s, key_id, share
		FROM %s WHERE share IS NOT NULL AND share_format = ? AND rowid >= ? ORDER BY rowid LIMIT 1`
	query := fmt.Sprintf(selectShare, "algorithm", "session_id", table)
	switch table {
	case "ecdsa_presignatures":
		query = fmt.Sprintf(selectShare, "'ecdsa'", "presignature_id", table)
	case "frost_presignatures":
		query = fmt.Sprintf(selectShare, "'frost'", "presignature_id", table)
	}
	update := "UPDATE " + table + " SET share = ?, share_format = ? WHERE rowid = ?"
	next := -maxRowID - 1
	for {
		var rowID int64
		var appID, algorithm, recordID, keyID string
		var plaintext []byte
		err := tx.QueryRowContext(ctx, query, plaintextShare, next).
			Scan(&rowID, &appID, &algorithm, &recordID, &keyID, &plaintext)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		purpose := keySharePurpose
		if table == "reshare_sessions" {
			purpose = resharePurpose(recordID)
		} else if table == "ecdsa_presignatures" || table == "frost_presignatures" {
			purpose = presignPurpose(recordID)
		}
		sealed, err := c.Seal(purpose, appID, algorithm, keyID, plaintext)
		clear(plaintext)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, update, sealed, encryptedShare, rowID); err != nil {
			return err
		}
		if rowID == maxRowID {
			return nil
		}
		next = rowID + 1
	}
}
