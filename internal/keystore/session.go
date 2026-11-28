package keystore

import "context"

const createSessionReservations = `CREATE TABLE IF NOT EXISTS session_reservations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	application_id TEXT NOT NULL,
	session_id TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(application_id, session_id)
)`

// ReserveSession keeps only the used ID, independently of in-memory results.
// These rows prevent re-executing expired sessions and must not be TTL-deleted.
func (s *SQLite) ReserveSession(ctx context.Context, app, id string) (bool, error) {
	r, err := s.db.ExecContext(ctx, s.insertOrIgnore(`INSERT INTO session_reservations(application_id,session_id) VALUES(?,?)`, "id"), app, id)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *SQLite) HasSession(ctx context.Context, app, id string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM session_reservations WHERE application_id=? AND session_id=?)`, app, id).Scan(&exists)
	return exists, err
}
