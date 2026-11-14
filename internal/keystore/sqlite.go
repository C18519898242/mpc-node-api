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
	db *sql.DB
}

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
	return &SQLite{db: db}, nil
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
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS key_shares (
		algorithm TEXT NOT NULL,
		session_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		threshold INTEGER NOT NULL,
		share BLOB,
		PRIMARY KEY (algorithm, key_id),
		UNIQUE (algorithm, session_id)
	)`); err != nil {
		return err
	}
	return tx.Commit()
}

// Reserve records the session before keygen. A row with no share represents an
// attempt that must never restart with the same session ID.
func (s *SQLite) Reserve(ctx context.Context, key Key) (Reservation, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO key_shares (algorithm, session_id, key_id, threshold)
		VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`, key.Algorithm, key.SessionID, key.KeyID, key.Threshold)
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
		WHERE algorithm = ? AND session_id = ? AND key_id = ? AND threshold = ?`,
		key.Algorithm, key.SessionID, key.KeyID, key.Threshold).Scan(&completed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !completed) {
		return Conflict, nil
	}
	return Completed, err
}

func (s *SQLite) Save(ctx context.Context, key Key, share []byte) error {
	if len(share) == 0 {
		return errors.New("empty key share")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE key_shares SET share = ?
		WHERE algorithm = ? AND session_id = ? AND key_id = ? AND threshold = ? AND share IS NULL`,
		share, key.Algorithm, key.SessionID, key.KeyID, key.Threshold)
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

func (s *SQLite) Load(ctx context.Context, algorithm, keyID string) ([]byte, error) {
	var share []byte
	err := s.db.QueryRowContext(ctx, `SELECT share FROM key_shares
		WHERE algorithm = ? AND key_id = ? AND share IS NOT NULL`, algorithm, keyID).Scan(&share)
	return share, err
}

func (s *SQLite) Close() error {
	return s.db.Close()
}
