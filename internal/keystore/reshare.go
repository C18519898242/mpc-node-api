package keystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type Reshare struct {
	Algorithm string
	SessionID string
	KeyID     string
}

type ReshareState struct {
	Digest    []byte
	Committed bool
}

func createReshareTable(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS reshare_sessions (
		algorithm TEXT NOT NULL,
		session_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		state TEXT NOT NULL DEFAULT 'started',
		digest BLOB,
		share BLOB,
		PRIMARY KEY (algorithm, session_id)
	)`)
	return err
}

func (s *SQLite) ReserveReshare(ctx context.Context, op Reshare) (Reservation, ReshareState, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO reshare_sessions (algorithm, session_id, key_id)
		SELECT algorithm, ?, key_id FROM key_shares WHERE algorithm = ? AND key_id = ? AND share IS NOT NULL
		ON CONFLICT DO NOTHING`, op.SessionID, op.Algorithm, op.KeyID)
	if err != nil {
		return Conflict, ReshareState{}, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 1 {
		return Reserved, ReshareState{}, err
	}
	state, err := s.LoadReshare(ctx, op)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM key_shares
			WHERE algorithm = ? AND key_id = ? AND share IS NOT NULL)`, op.Algorithm, op.KeyID).Scan(&exists)
		if err == nil && !exists {
			err = sql.ErrNoRows
		}
		return Conflict, ReshareState{}, err
	}
	return Completed, state, err
}

func (s *SQLite) LoadReshare(ctx context.Context, op Reshare) (ReshareState, error) {
	var state ReshareState
	err := s.db.QueryRowContext(ctx, `SELECT digest, state = 'committed' FROM reshare_sessions
		WHERE algorithm = ? AND session_id = ? AND key_id = ? AND state IN ('prepared', 'committed')`,
		op.Algorithm, op.SessionID, op.KeyID).Scan(&state.Digest, &state.Committed)
	return state, err
}

func (s *SQLite) PendingReshare(ctx context.Context, algorithm, keyID string) (bool, error) {
	var pending bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reshare_sessions
		WHERE algorithm = ? AND key_id = ? AND state = 'prepared')`, algorithm, keyID).Scan(&pending)
	return pending, err
}

func (s *SQLite) StageReshare(ctx context.Context, op Reshare, digest [32]byte, share []byte) error {
	if len(share) == 0 {
		return errors.New("empty refreshed share")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE reshare_sessions SET digest = ?, share = ?, state = 'prepared'
		WHERE algorithm = ? AND session_id = ? AND key_id = ? AND state = 'started'`,
		digest[:], share, op.Algorithm, op.SessionID, op.KeyID)
	return requireReshareUpdate(result, err)
}

func (s *SQLite) CommitReshare(ctx context.Context, op Reshare) error {
	var table string
	switch op.Algorithm {
	case "ecdsa":
		table = "ecdsa_presignatures"
	case "frost":
		table = "frost_presignatures"
	default:
		return errors.New("unknown reshare algorithm")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE key_shares SET share = (
		SELECT share FROM reshare_sessions WHERE algorithm = ? AND key_id = ? AND session_id = ? AND state = 'prepared'
	) WHERE algorithm = ? AND key_id = ? AND EXISTS (
		SELECT 1 FROM reshare_sessions WHERE algorithm = ? AND key_id = ? AND session_id = ? AND state = 'prepared'
	)`, op.Algorithm, op.KeyID, op.SessionID, op.Algorithm, op.KeyID, op.Algorithm, op.KeyID, op.SessionID)
	if err := requireReshareUpdate(result, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE key_id = ?", table), op.KeyID); err != nil {
		return err
	}
	// Keep session reservations while invalidating each batch's obsolete IDs.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s_presign_batches SET ids = NULL WHERE key_id = ?", op.Algorithm), op.KeyID); err != nil {
		return err
	}
	// Superseded candidates cannot later replace this generation.
	if _, err := tx.ExecContext(ctx, `UPDATE reshare_sessions SET state = 'superseded', share = NULL, digest = NULL
		WHERE algorithm = ? AND key_id = ? AND session_id <> ? AND state <> 'superseded'`,
		op.Algorithm, op.KeyID, op.SessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE reshare_sessions SET state = 'committed', share = NULL
		WHERE algorithm = ? AND session_id = ? AND key_id = ?`, op.Algorithm, op.SessionID, op.KeyID); err != nil {
		return err
	}
	return tx.Commit()
}

func requireReshareUpdate(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		err = errors.New("invalid reshare state")
	}
	return err
}
