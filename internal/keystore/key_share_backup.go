package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
)

var ErrKeyShareConflict = errors.New("key share backup conflicts with the current record")

type KeyShareBackup struct {
	Key       Key     `json:"key"`
	Share     []byte  `json:"share"`
	CreatedAt *string `json:"createdAt"`
}

func (s *SQLite) ExportKeyShare(ctx context.Context, appID, algorithm, keyID string) (KeyShareBackup, error) {
	backup := KeyShareBackup{Key: Key{Algorithm: algorithm, KeyID: keyID}}
	var format int
	err := s.db.QueryRowContext(ctx, `SELECT session_id, threshold, share, share_format, created_at
		FROM key_shares WHERE application_id = ? AND algorithm = ? AND key_id = ? AND share IS NOT NULL`,
		appID, algorithm, keyID).Scan(&backup.Key.SessionID, &backup.Key.Threshold, &backup.Share, &format, &backup.CreatedAt)
	if err != nil {
		return KeyShareBackup{}, err
	}
	backup.Share, err = s.openShare(format, keySharePurpose, appID, algorithm, keyID, backup.Share)
	return backup, err
}

// RestoreKeyShare permits an identical replay or restoration of a missing local
// share, and rejects overwriting a different generation of the same key.
func (s *SQLite) RestoreKeyShare(ctx context.Context, appID string, backup KeyShareBackup) error {
	key := backup.Key
	if (key.Algorithm != "ecdsa" && key.Algorithm != "frost") || key.KeyID == "" ||
		key.SessionID == "" || key.Threshold < 1 || len(backup.Share) == 0 {
		return errors.New("invalid key share backup")
	}
	record, format, err := s.sealShare(keySharePurpose, appID, key.Algorithm, key.KeyID, backup.Share)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reshare_sessions
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND state = 'prepared')`,
		appID, key.Algorithm, key.KeyID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrKeyShareConflict
	}
	result, err := tx.ExecContext(ctx, s.insertOrIgnore(`INSERT INTO key_shares
		(application_id, algorithm, session_id, key_id, threshold, share, share_format, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "id"),
		appID, key.Algorithm, key.SessionID, key.KeyID, key.Threshold, record, format, backup.CreatedAt)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return tx.Commit()
	}
	var sessionID string
	var threshold, savedFormat int
	var saved []byte
	err = tx.QueryRowContext(ctx, `SELECT session_id, threshold, share, share_format FROM key_shares
		WHERE application_id = ? AND algorithm = ? AND key_id = ?`,
		appID, key.Algorithm, key.KeyID).Scan(&sessionID, &threshold, &saved, &savedFormat)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrKeyShareConflict
	}
	if err != nil {
		return err
	}
	defer clear(saved)
	if sessionID != key.SessionID || threshold != key.Threshold {
		return ErrKeyShareConflict
	}
	if saved != nil {
		plain, err := s.openShare(savedFormat, keySharePurpose, appID, key.Algorithm, key.KeyID, saved)
		if err != nil {
			return err
		}
		defer clear(plain)
		if !bytes.Equal(plain, backup.Share) {
			return ErrKeyShareConflict
		}
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `UPDATE key_shares SET share = ?, share_format = ?
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND share IS NULL`,
		record, format, appID, key.Algorithm, key.KeyID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
