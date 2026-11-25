package keystore

import (
	"context"
	"database/sql"
	"errors"
)

const createWalletBackups = `CREATE TABLE IF NOT EXISTS wallet_backups (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	application_id TEXT NOT NULL,
	session_id TEXT NOT NULL,
	wallet_id TEXT NOT NULL,
	ecdsa_key_id TEXT,
	frost_key_id TEXT,
	manifest BLOB,
	format_version INTEGER,
	backup_key_id TEXT,
	wrapped_key BLOB,
	ciphertext BLOB,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(application_id, session_id),
	UNIQUE(application_id, wallet_id)
)`

type MnemonicBackup struct {
	Version    int
	KeyID      string
	WrappedKey []byte
	Ciphertext []byte
}

// WalletStatus returns Reserved for an unused ID and Conflict for an unfinished
// attempt. Only committed receipts can be retried after a restart.
func (s *SQLite) WalletStatus(ctx context.Context, app, session string) (Reservation, error) {
	var completed bool
	err := s.db.QueryRowContext(ctx, `SELECT manifest IS NOT NULL FROM wallet_backups
		WHERE application_id = ? AND session_id = ?`, app, session).Scan(&completed)
	if errors.Is(err, sql.ErrNoRows) {
		return Reserved, nil
	}
	if completed && err == nil {
		return Completed, nil
	}
	return Conflict, err
}

func (s *SQLite) ReserveWallet(ctx context.Context, app, session, wallet string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO wallet_backups (application_id, session_id, wallet_id)
		VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, app, session, wallet)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

// SaveWallet publishes the two encrypted signing shares and encrypted recovery
// backup together. A failed insert leaves only the original session reservation.
func (s *SQLite) SaveWallet(ctx context.Context, app, session, wallet, ecdsaID, frostID string, manifest []byte, backup MnemonicBackup, ecdsaShare, frostShare []byte) error {
	if s.shareCipher == nil || len(manifest) == 0 || len(ecdsaShare) == 0 || len(frostShare) == 0 ||
		backup.Version != 1 || backup.KeyID == "" || len(backup.WrappedKey) == 0 || len(backup.Ciphertext) < 28 {
		return errors.New("incomplete or unencrypted wallet")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, key := range []struct {
		algorithm, id string
		share         []byte
	}{{"ecdsa", ecdsaID, ecdsaShare}, {"frost", frostID, frostShare}} {
		record, format, err := s.sealShare(keySharePurpose, app, key.algorithm, key.id, key.share)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_shares (application_id, algorithm, session_id, key_id, threshold, share, share_format)
			VALUES (?, ?, ?, ?, 2, ?, ?)`, app, key.algorithm, "wallet."+session, key.id, record, format); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE wallet_backups SET ecdsa_key_id = ?, frost_key_id = ?, manifest = ?,
		format_version = ?, backup_key_id = ?, wrapped_key = ?, ciphertext = ?
		WHERE application_id = ? AND session_id = ? AND wallet_id = ? AND manifest IS NULL`,
		ecdsaID, frostID, manifest, backup.Version, backup.KeyID, backup.WrappedKey, backup.Ciphertext, app, session, wallet)
	if err := requireShareUpdate(result, err); err != nil {
		return err
	}
	return tx.Commit()
}
