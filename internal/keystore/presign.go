package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

type Presignature struct {
	ID    string
	Share []byte
}

func createPresignTables(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS ecdsa_presign_batches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL UNIQUE,
		key_id TEXT NOT NULL,
		binding BLOB NOT NULL,
		ids TEXT,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS ecdsa_presignatures (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		presignature_id TEXT NOT NULL UNIQUE,
		key_id TEXT NOT NULL,
		share BLOB NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

func (s *SQLite) ReserveECDSAPresign(ctx context.Context, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO ecdsa_presign_batches (session_id, key_id, binding)
		VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, sessionID, keyID, binding[:])
	if err != nil {
		return Conflict, nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Conflict, nil, err
	}
	if count == 1 {
		return Reserved, nil, nil
	}
	var savedBinding []byte
	var savedIDs sql.NullString
	if err := s.db.QueryRowContext(ctx, "SELECT binding, ids FROM ecdsa_presign_batches WHERE session_id = ?", sessionID).
		Scan(&savedBinding, &savedIDs); err != nil {
		return Conflict, nil, err
	}
	if !bytes.Equal(savedBinding, binding[:]) || !savedIDs.Valid {
		return Conflict, nil, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(savedIDs.String), &ids); err != nil {
		return Conflict, nil, err
	}
	return Completed, ids, nil
}

func (s *SQLite) SaveECDSAPresign(ctx context.Context, sessionID string, shares []Presignature) ([]string, error) {
	if len(shares) == 0 {
		return nil, errors.New("empty ECDSA presign batch")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	ids := make([]string, 0, len(shares))
	for _, share := range shares {
		if share.ID == "" || len(share.Share) == 0 {
			return nil, errors.New("invalid ECDSA presign share")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO ecdsa_presignatures (presignature_id, key_id, share)
			SELECT ?, key_id, ? FROM ecdsa_presign_batches WHERE session_id = ? AND ids IS NULL`,
			share.ID, share.Share, sessionID)
		if err != nil {
			return nil, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, errors.New("no pending ECDSA presign batch")
		}
		ids = append(ids, share.ID)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE ecdsa_presign_batches SET ids = ? WHERE session_id = ?", string(encoded), sessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}
