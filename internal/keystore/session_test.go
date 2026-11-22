package keystore

import "testing"

func TestSessionReservationsSurviveReopenAndSeparateApplications(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"a", "b"} {
		fresh, err := s.ReserveSession(t.Context(), app, "ecdsa-sign.once")
		if err != nil || !fresh {
			t.Fatalf("first reserve %s: %v %v", app, fresh, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if fresh, err := s.ReserveSession(t.Context(), "a", "ecdsa-sign.once"); err != nil || fresh {
		t.Fatalf("duplicate after restart: %v %v", fresh, err)
	}
	if used, err := s.HasSession(t.Context(), "a", "ecdsa-sign.once"); err != nil || !used {
		t.Fatalf("reservation missing: %v %v", used, err)
	}
}
