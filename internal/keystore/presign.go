package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type Presignature struct {
	ID    string
	Share []byte
}

// ConsumeECDSAPresign atomically deletes and returns one local share. An empty
// ID selects the oldest available share for the key.
func (s *SQLite) ConsumeECDSAPresign(ctx context.Context, keyID, presignatureID string) (Presignature, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Presignature{}, err
	}
	defer tx.Rollback()

	var share Presignature
	err = tx.QueryRowContext(ctx, `DELETE FROM ecdsa_presignatures WHERE id = (
		SELECT id FROM ecdsa_presignatures WHERE key_id = ? AND (? = '' OR presignature_id = ?)
		ORDER BY id LIMIT 1
	) RETURNING presignature_id, share`, keyID, presignatureID, presignatureID).Scan(&share.ID, &share.Share)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(share.Share)
		return Presignature{}, err
	}
	return share, nil
}

func createPresignTables(tx *sql.Tx) error {
	for _, algorithm := range []string{"ecdsa", "frost"} {
		if err := createPresignTablesFor(tx, algorithm); err != nil {
			return err
		}
	}
	return nil
}

func createPresignTablesFor(tx *sql.Tx, algorithm string) error {
	if _, err := tx.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s_presign_batches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL UNIQUE,
		key_id TEXT NOT NULL,
		binding BLOB NOT NULL,
		ids TEXT,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`, algorithm)); err != nil {
		return err
	}
	_, err := tx.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s_presignatures (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		presignature_id TEXT NOT NULL UNIQUE,
		key_id TEXT NOT NULL,
		share BLOB NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`, algorithm))
	return err
}

func (s *SQLite) ReserveECDSAPresign(ctx context.Context, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	return s.reservePresign(ctx, "ecdsa", sessionID, keyID, binding)
}

func (s *SQLite) ReserveFROSTPresign(ctx context.Context, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	return s.reservePresign(ctx, "frost", sessionID, keyID, binding)
}

func (s *SQLite) reservePresign(ctx context.Context, algorithm, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	result, err := s.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s_presign_batches (session_id, key_id, binding)
		VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, algorithm), sessionID, keyID, binding[:])
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
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT binding, ids FROM %s_presign_batches WHERE session_id = ?", algorithm), sessionID).
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
	return s.savePresign(ctx, "ecdsa", sessionID, shares)
}

func (s *SQLite) SaveFROSTPresign(ctx context.Context, sessionID string, shares []Presignature) ([]string, error) {
	return s.savePresign(ctx, "frost", sessionID, shares)
}

func (s *SQLite) savePresign(ctx context.Context, algorithm, sessionID string, shares []Presignature) ([]string, error) {
	if len(shares) == 0 {
		return nil, errors.New("empty presign batch")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	ids := make([]string, 0, len(shares))
	for _, share := range shares {
		if share.ID == "" || len(share.Share) == 0 {
			return nil, errors.New("invalid presign share")
		}
		result, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s_presignatures (presignature_id, key_id, share)
			SELECT ?, key_id, ? FROM %s_presign_batches WHERE session_id = ? AND ids IS NULL`, algorithm, algorithm),
			share.ID, share.Share, sessionID)
		if err != nil {
			return nil, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, errors.New("no pending presign batch")
		}
		ids = append(ids, share.ID)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s_presign_batches SET ids = ? WHERE session_id = ?", algorithm), string(encoded), sessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}
