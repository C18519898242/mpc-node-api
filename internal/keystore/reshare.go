package keystore

import (
	"context"
	"database/sql"
	"errors"
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
	const schema = `CREATE TABLE IF NOT EXISTS reshare_sessions (
		application_id TEXT NOT NULL DEFAULT 'default',
		algorithm TEXT NOT NULL,
		session_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		state TEXT NOT NULL DEFAULT 'started',
		digest BLOB,
		share BLOB,
		PRIMARY KEY (application_id, algorithm, session_id)
	)`
	return ensureApplicationTable(tx, "reshare_sessions", schema, "algorithm, session_id, key_id, state, digest, share")
}

func (s *SQLite) ReserveReshare(ctx context.Context, op Reshare) (Reservation, ReshareState, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO reshare_sessions (application_id, algorithm, session_id, key_id)
		SELECT application_id, algorithm, ?, key_id FROM key_shares
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND share IS NOT NULL
		ON CONFLICT DO NOTHING`, op.SessionID, s.applicationID, op.Algorithm, op.KeyID)
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
			WHERE application_id = ? AND algorithm = ? AND key_id = ? AND share IS NOT NULL)`, s.applicationID, op.Algorithm, op.KeyID).Scan(&exists)
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
		WHERE application_id = ? AND algorithm = ? AND session_id = ? AND key_id = ? AND state IN ('prepared', 'committed')`,
		s.applicationID, op.Algorithm, op.SessionID, op.KeyID).Scan(&state.Digest, &state.Committed)
	return state, err
}

func (s *SQLite) PendingReshare(ctx context.Context, algorithm, keyID string) (bool, error) {
	var pending bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reshare_sessions
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND state = 'prepared')`, s.applicationID, algorithm, keyID).Scan(&pending)
	return pending, err
}

func (s *SQLite) StageReshare(ctx context.Context, op Reshare, digest [32]byte, share []byte) error {
	if len(share) == 0 {
		return errors.New("empty refreshed share")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE reshare_sessions SET digest = ?, share = ?, state = 'prepared'
		WHERE application_id = ? AND algorithm = ? AND session_id = ? AND key_id = ? AND state = 'started'`,
		digest[:], share, s.applicationID, op.Algorithm, op.SessionID, op.KeyID)
	return requireShareUpdate(result, err)
}

func (s *SQLite) CommitReshare(ctx context.Context, op Reshare) error {
	if op.Algorithm != "ecdsa" && op.Algorithm != "frost" {
		return errors.New("unknown reshare algorithm")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE key_shares AS k SET share = r.share
		FROM reshare_sessions AS r
		WHERE k.application_id = r.application_id AND k.algorithm = r.algorithm AND k.key_id = r.key_id
		AND r.application_id = ? AND r.algorithm = ? AND r.key_id = ? AND r.session_id = ? AND r.state = 'prepared'`,
		s.applicationID, op.Algorithm, op.KeyID, op.SessionID)
	if err := requireShareUpdate(result, err); err != nil {
		return err
	}
	if err := s.invalidatePresign(ctx, tx, op.Algorithm, op.KeyID); err != nil {
		return err
	}
	// Superseded candidates cannot later replace this generation.
	if _, err := tx.ExecContext(ctx, `UPDATE reshare_sessions SET state = 'superseded', share = NULL, digest = NULL
		WHERE application_id = ? AND algorithm = ? AND key_id = ? AND session_id <> ? AND state <> 'superseded'`,
		s.applicationID, op.Algorithm, op.KeyID, op.SessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE reshare_sessions SET state = 'committed', share = NULL
		WHERE application_id = ? AND algorithm = ? AND session_id = ? AND key_id = ?`, s.applicationID, op.Algorithm, op.SessionID, op.KeyID); err != nil {
		return err
	}
	return tx.Commit()
}

func requireShareUpdate(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		err = errors.New("invalid key share state")
	}
	return err
}
