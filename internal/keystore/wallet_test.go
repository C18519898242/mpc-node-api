package keystore

import (
	"database/sql"
	"errors"
	"testing"
)

func TestWalletCommitRollsBackBothShares(t *testing.T) {
	db, err := OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	if err := db.EnableShareEncryption(ctx, NewShareCipher(make([]byte, 32), "1")); err != nil {
		t.Fatal(err)
	}
	const app = "wallet-app"
	if fresh, err := db.ReserveWallet(ctx, app, "attempt", "wallet", nil); err != nil || !fresh {
		t.Fatalf("reserve wallet: %t, %v", fresh, err)
	}
	key := Key{Algorithm: "frost", SessionID: "existing", KeyID: "frost", Threshold: 2}
	if status, err := db.Reserve(ctx, app, key); err != nil || status != Reserved {
		t.Fatalf("reserve conflicting key: %v, %v", status, err)
	}
	backup := MnemonicBackup{Version: 1, KeyID: "fixture", WrappedKey: []byte{1}, Ciphertext: make([]byte, 28)}
	if err := db.SaveWallet(ctx, app, "attempt", "wallet", "ecdsa", "frost", []byte(`{}`), backup, []byte{1}, []byte{2}); err == nil {
		t.Fatal("wallet committed with a conflicting FROST ID")
	}
	if _, err := db.Load(ctx, app, "ecdsa", "ecdsa"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ECDSA share survived wallet rollback: %v", err)
	}
	if status, err := db.WalletStatus(ctx, app, "attempt", nil); err != nil || status != Conflict {
		t.Fatalf("failed wallet was not held as an attempt: %v, %v", status, err)
	}
}

func TestWalletBackupRequestDigestMigration(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := t.Context()
	if err := db.EnableShareEncryption(ctx, NewShareCipher(make([]byte, 32), "1")); err != nil {
		t.Fatal(err)
	}
	const app, session, wallet = "wallet-app", "old-session", "old-wallet"
	if ok, err := db.ReserveWallet(ctx, app, session, wallet, nil); err != nil || !ok {
		t.Fatalf("reserve configured-key wallet: %v, %v", ok, err)
	}
	backup := MnemonicBackup{Version: 1, KeyID: "fixture", WrappedKey: []byte{1}, Ciphertext: make([]byte, 28)}
	if err := db.SaveWallet(ctx, app, session, wallet, "ecdsa", "frost", []byte(`{}`), backup, []byte{1}, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("ALTER TABLE wallet_backups DROP COLUMN backup_request_digest"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNodeSQLite(dir, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if status, err := reopened.WalletStatus(ctx, app, session, nil); err != nil || status != Completed {
		t.Fatalf("legacy wallet replay: %v, %v", status, err)
	}
	if status, err := reopened.WalletStatus(ctx, app, session, make([]byte, 32)); err != nil || status != Conflict {
		t.Fatalf("legacy wallet replay with an uploaded-key digest: %v, %v", status, err)
	}
	if restored, _, err := reopened.LoadWalletBackup(ctx, app, wallet); err != nil || restored.KeyID != backup.KeyID {
		t.Fatalf("legacy wallet backup was not retained: %v", err)
	}
}
