package keystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Key struct {
	Algorithm string
	SessionID string
	KeyID     string
	Threshold int
}

type Reservation int

const (
	Reserved Reservation = iota
	Completed
	Conflict
)

type SQLite struct {
	db          *sql.DB
	partyID     string
	shareCipher *ShareCipher
}

const DefaultApplication = "default"

// OpenNodeSQLite opens the database in a node's configured data directory.
func OpenNodeSQLite(dataDir, partyID string) (*SQLite, error) {
	return OpenSQLite(filepath.Join(dataDir, "node.sqlite"), partyID)
}

func OpenSQLite(path, partyID string) (*SQLite, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := initSQLite(db, partyID); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize key database: %w", err)
	}
	return &SQLite{db: db, partyID: partyID}, nil
}

func initSQLite(db *sql.DB, partyID string) error {
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS node_owner (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		party_id TEXT NOT NULL
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO node_owner (id, party_id) VALUES (1, ?) ON CONFLICT DO NOTHING", partyID); err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRow("SELECT party_id FROM node_owner WHERE id = 1").Scan(&owner); err != nil {
		return err
	}
	if owner != partyID {
		return errors.New("key database belongs to a different MPC node")
	}
	if err := migrateKeyShares(tx); err != nil {
		return err
	}
	if err := createPresignTables(tx); err != nil {
		return err
	}
	if err := createReshareTable(tx); err != nil {
		return err
	}
	for _, table := range []string{"key_shares", "reshare_sessions"} {
		var exists bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name = 'share_format')", table).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN share_format INTEGER NOT NULL DEFAULT 0 CHECK (share_format IN (0, 1))"); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(createMasterKeyTable); err != nil {
		return err
	}
	return tx.Commit()
}

const createKeyShares = `CREATE TABLE IF NOT EXISTS key_shares (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	application_id TEXT NOT NULL DEFAULT 'default',
	algorithm TEXT NOT NULL,
	session_id TEXT NOT NULL,
	key_id TEXT NOT NULL,
	threshold INTEGER NOT NULL,
	share BLOB,
	created_at TEXT DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (application_id, algorithm, key_id),
	UNIQUE (application_id, algorithm, session_id)
)`

func migrateKeyShares(tx *sql.Tx) error {
	if _, err := tx.Exec(createKeyShares); err != nil {
		return err
	}
	var legacy bool
	if err := tx.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pragma_table_info('key_shares') WHERE name = 'algorithm' AND pk > 0
	)`).Scan(&legacy); err != nil {
		return err
	}
	idAndTime := "id, algorithm, session_id, key_id, threshold, share, created_at"
	source := idAndTime
	if legacy {
		source = "rowid, algorithm, session_id, key_id, threshold, share, NULL"
	}
	if err := migrateApplicationTable(tx, "key_shares", createKeyShares, idAndTime, source); err != nil {
		return err
	}
	return removeCopyColumns(tx)
}

// Rebuilding replaces legacy uniqueness constraints with application-scoped ones.
func migrateApplicationTable(tx *sql.Tx, table, schema, columns, source string) error {
	var scoped bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name = 'application_id')", table).Scan(&scoped); err != nil || scoped {
		return err
	}
	legacy := table + "_legacy"
	for _, query := range []string{
		"ALTER TABLE " + table + " RENAME TO " + legacy,
		schema,
		"INSERT INTO " + table + " (" + columns + ") SELECT " + source + " FROM " + legacy,
		"DROP TABLE " + legacy,
	} {
		if _, err := tx.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func removeCopyColumns(tx *sql.Tx) error {
	for _, column := range []string{"request_binding", "copy_digest", "copy_candidate"} {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('key_shares')
			WHERE name = ?)`, column).Scan(&exists); err != nil {
			return err
		}
		if exists {
			if _, err := tx.Exec("ALTER TABLE key_shares DROP COLUMN " + column); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reserve records the session before keygen. A row with no share represents an
// attempt that must never restart with the same session ID.
func (s *SQLite) Reserve(ctx context.Context, applicationID string, key Key) (Reservation, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO key_shares (application_id, algorithm, session_id, key_id, threshold)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, applicationID, key.Algorithm, key.SessionID, key.KeyID, key.Threshold)
	if err != nil {
		return Conflict, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Conflict, err
	}
	if count == 1 {
		return Reserved, nil
	}
	var completed bool
	err = s.db.QueryRowContext(ctx, `SELECT share IS NOT NULL FROM key_shares
		WHERE application_id = ? AND algorithm = ? AND session_id = ? AND key_id = ? AND threshold = ?`,
		applicationID, key.Algorithm, key.SessionID, key.KeyID, key.Threshold).Scan(&completed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !completed) {
		return Conflict, nil
	}
	return Completed, err
}

func (s *SQLite) Save(ctx context.Context, applicationID string, key Key, share []byte) error {
	if len(share) == 0 {
		return errors.New("empty key share")
	}
	record, format, err := s.sealShare(keySharePurpose, applicationID, key.Algorithm, key.KeyID, share)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE key_shares SET share = ?, share_format = ?
		WHERE application_id = ? AND algorithm = ? AND session_id = ? AND key_id = ? AND threshold = ? AND share IS NULL`,
		record, format, applicationID, key.Algorithm, key.SessionID, key.KeyID, key.Threshold)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("no pending key share reservation")
	}
	return nil
}

func (s *SQLite) Load(ctx context.Context, applicationID string, algorithm, keyID string) ([]byte, error) {
	var share []byte
	var format int
	err := s.db.QueryRowContext(ctx, `SELECT share, share_format FROM key_shares
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND share IS NOT NULL`, applicationID, algorithm, keyID).Scan(&share, &format)
	if err != nil {
		return nil, err
	}
	return s.openShare(format, keySharePurpose, applicationID, algorithm, keyID, share)
}

func (s *SQLite) DeleteKeyShare(ctx context.Context, applicationID string, keyID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Keep the reservation so replay cannot create another key under this ID.
	result, err := tx.ExecContext(ctx, "UPDATE key_shares SET share = NULL WHERE application_id = ? AND key_id = ? AND share IS NOT NULL", applicationID, keyID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	for _, algorithm := range []string{"ecdsa", "frost"} {
		if err := s.invalidatePresign(ctx, applicationID, tx, algorithm, keyID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE reshare_sessions
		SET state = 'superseded', share = NULL, digest = NULL
		WHERE application_id = ? AND key_id = ? AND state <> 'superseded'`, applicationID, keyID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) Close() error {
	return s.db.Close()
}
