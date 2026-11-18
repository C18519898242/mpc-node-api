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

func (s *SQLite) CountPresign(ctx context.Context, keyID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM ecdsa_presignatures WHERE application_id = ? AND key_id = ?) +
		(SELECT COUNT(*) FROM frost_presignatures WHERE application_id = ? AND key_id = ?)
		WHERE EXISTS (
			SELECT 1 FROM key_shares WHERE application_id = ? AND key_id = ? AND share IS NOT NULL
		)`, s.applicationID, keyID, s.applicationID, keyID, s.applicationID, keyID).Scan(&count)
	return count, err
}

func (s *SQLite) DeletePresign(ctx context.Context, keyID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT 1 FROM key_shares WHERE application_id = ? AND key_id = ? AND share IS NOT NULL", s.applicationID, keyID).Scan(&exists); err != nil {
		return err
	}
	for _, algorithm := range []string{"ecdsa", "frost"} {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s_presignatures WHERE application_id = ? AND key_id = ?", algorithm), s.applicationID, keyID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) invalidatePresign(ctx context.Context, tx *sql.Tx, algorithm, keyID string) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s_presignatures WHERE application_id = ? AND key_id = ?", algorithm), s.applicationID, keyID); err != nil {
		return err
	}
	// Keep session reservations while invalidating batch IDs.
	_, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s_presign_batches SET ids = NULL WHERE application_id = ? AND key_id = ?", algorithm), s.applicationID, keyID)
	return err
}

// ConsumeECDSAPresign atomically deletes and returns one local share. An empty
// ID selects the oldest available share for the key.
func (s *SQLite) ConsumeECDSAPresign(ctx context.Context, keyID, presignatureID string) (Presignature, error) {
	return s.consumePresign(ctx, "ecdsa", keyID, presignatureID)
}

// ConsumeFROSTPresign atomically deletes and returns one local FROST share.
func (s *SQLite) ConsumeFROSTPresign(ctx context.Context, keyID, presignatureID string) (Presignature, error) {
	return s.consumePresign(ctx, "frost", keyID, presignatureID)
}

func (s *SQLite) consumePresign(ctx context.Context, algorithm, keyID, presignatureID string) (Presignature, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Presignature{}, err
	}
	defer tx.Rollback()

	var share Presignature
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`DELETE FROM %s_presignatures WHERE id = (
		SELECT id FROM %s_presignatures WHERE application_id = ? AND key_id = ? AND (? = '' OR presignature_id = ?)
		ORDER BY id LIMIT 1
	) RETURNING presignature_id, share`, algorithm, algorithm), s.applicationID, keyID, presignatureID, presignatureID).Scan(&share.ID, &share.Share)
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
	batches := algorithm + "_presign_batches"
	batchSchema := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		application_id TEXT NOT NULL DEFAULT 'default',
		session_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		binding BLOB NOT NULL,
		ids TEXT,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (application_id, session_id)
	)`, batches)
	batchColumns := "id, session_id, key_id, binding, ids, created_at"
	if err := ensureApplicationTable(tx, batches, batchSchema, batchColumns); err != nil {
		return err
	}
	shares := algorithm + "_presignatures"
	shareSchema := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		application_id TEXT NOT NULL DEFAULT 'default',
		presignature_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		share BLOB NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (application_id, presignature_id)
	)`, shares)
	return ensureApplicationTable(tx, shares, shareSchema, "id, presignature_id, key_id, share, created_at")
}

func ensureApplicationTable(tx *sql.Tx, table, schema, columns string) error {
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	return migrateApplicationTable(tx, table, schema, columns, columns)
}

func (s *SQLite) ReserveECDSAPresign(ctx context.Context, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	return s.reservePresign(ctx, "ecdsa", sessionID, keyID, binding)
}

func (s *SQLite) ReserveFROSTPresign(ctx context.Context, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	return s.reservePresign(ctx, "frost", sessionID, keyID, binding)
}

func (s *SQLite) reservePresign(ctx context.Context, algorithm, sessionID, keyID string, binding [32]byte) (Reservation, []string, error) {
	result, err := s.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s_presign_batches (application_id, session_id, key_id, binding)
		VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`, algorithm), s.applicationID, sessionID, keyID, binding[:])
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
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT binding, ids FROM %s_presign_batches WHERE application_id = ? AND session_id = ?", algorithm), s.applicationID, sessionID).
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
		result, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s_presignatures (application_id, presignature_id, key_id, share)
			SELECT application_id, ?, key_id, ? FROM %s_presign_batches WHERE application_id = ? AND session_id = ? AND ids IS NULL`, algorithm, algorithm),
			share.ID, share.Share, s.applicationID, sessionID)
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
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s_presign_batches SET ids = ? WHERE application_id = ? AND session_id = ?", algorithm), string(encoded), s.applicationID, sessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}
