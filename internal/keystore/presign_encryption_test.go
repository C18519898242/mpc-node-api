package keystore

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"
)

func TestPresignEncryptionMigratesAndSurvivesRestart(t *testing.T) {
	for _, algorithm := range []string{"ecdsa", "frost"} {
		t.Run(algorithm, func(t *testing.T) {
			ctx := t.Context()
			dir := t.TempDir()
			app, keyID := "wallet-a", "key"
			db, err := OpenNodeSQLite(dir, "1")
			if err != nil {
				t.Fatal(err)
			}
			key := Key{Algorithm: algorithm, KeyID: keyID, SessionID: "keygen", Threshold: 1}
			if _, err := db.Reserve(ctx, app, key); err != nil {
				t.Fatal(err)
			}
			if err := db.Save(ctx, app, key, []byte("private key fixture")); err != nil {
				t.Fatal(err)
			}
			plain := []byte("sensitive presign nonce fixture")
			if _, _, err := db.reservePresign(ctx, app, algorithm, "legacy", keyID, [32]byte{}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.savePresign(ctx, app, algorithm, "legacy", []Presignature{{ID: "first", Share: plain}, {ID: "second", Share: plain}}); err != nil {
				t.Fatal(err)
			}
			table := algorithm + "_presignatures"
			var created string
			var rowID int64
			if err := db.db.QueryRow("SELECT id,created_at FROM "+table+" WHERE presignature_id='first'").Scan(&rowID, &created); err != nil {
				t.Fatal(err)
			}
			// Recreate the schema shipped before presignature encryption.
			var formatExists bool
			if err := db.db.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name='share_format')", table).Scan(&formatExists); err != nil {
				t.Fatal(err)
			}
			if formatExists {
				if _, err := db.db.Exec("ALTER TABLE " + table + " DROP COLUMN share_format"); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopen := func(encryption bool) *SQLite {
				t.Helper()
				s, err := OpenNodeSQLite(dir, "1")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				if encryption {
					mk, err := s.LoadOrCreateMasterKey(ctx, "presign encryption fixture")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { clear(mk) })
					if err := s.EnableShareEncryption(ctx, NewShareCipher(mk, "1")); err != nil {
						t.Fatal(err)
					}
				}
				return s
			}
			db = reopen(true)
			atRest := func(id string) []byte {
				t.Helper()
				var raw []byte
				var format int
				if err := db.db.QueryRow("SELECT share,share_format FROM "+table+" WHERE presignature_id=?", id).Scan(&raw, &format); err != nil || format != 1 || bytes.Contains(raw, plain) {
					t.Fatalf("presignature was not encrypted: format=%d error=%v", format, err)
				}
				return raw
			}
			first := atRest("first")
			atRest("second")
			decoded, err := db.shareCipher.Open("presign:first", app, algorithm, keyID, first)
			if err != nil || !bytes.Equal(decoded, plain) {
				t.Fatal("presignature CEK did not bind the record identity", err)
			}
			clear(decoded)
			for _, context := range []struct{ purpose, app, algorithm, key string }{
				{"presign:second", app, algorithm, keyID}, {"key", app, algorithm, keyID}, {"presign:first", "wallet-b", algorithm, keyID}, {"presign:first", app, "other", keyID}, {"presign:first", app, algorithm, "other-key"},
			} {
				if data, err := db.shareCipher.Open(context.purpose, context.app, context.algorithm, context.key, first); err == nil {
					clear(data)
					t.Fatal("ciphertext accepted for a different identity or purpose")
				}
			}
			var haveID int64
			var haveCreated string
			if err := db.db.QueryRow("SELECT id,created_at FROM "+table+" WHERE presignature_id='first'").Scan(&haveID, &haveCreated); err != nil || haveID != rowID || haveCreated != created {
				t.Fatal("migration changed presignature metadata", err)
			}
			if _, _, err := db.reservePresign(ctx, app, algorithm, "new", keyID, [32]byte{1}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.savePresign(ctx, app, algorithm, "new", []Presignature{{ID: "third", Share: plain}}); err != nil {
				t.Fatal(err)
			}
			atRest("third")
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = reopen(false)
			if share, err := db.consumePresign(ctx, app, algorithm, keyID, "first"); err == nil || share.Share != nil {
				t.Fatal("read encrypted presignature without MK")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db = reopen(true)
			if !bytes.Equal(first, atRest("first")) {
				t.Fatal("startup encrypted an existing ciphertext twice")
			}
			var wrongMK [32]byte
			wrongMK[0] = 42
			correctCipher := db.shareCipher
			db.shareCipher = NewShareCipher(wrongMK[:], "1")
			if share, err := db.consumePresign(ctx, app, algorithm, keyID, "first"); err == nil || share.Share != nil {
				t.Fatal("wrong MK decrypted a presignature")
			}
			db.shareCipher = correctCipher
			// Failed authentication must roll back the DELETE, preserving the row.
			if !bytes.Equal(first, atRest("first")) {
				t.Fatal("failed decryption deleted the presignature")
			}
			second := atRest("second")
			for _, replacement := range [][]byte{append([]byte{first[0] ^ 1}, first[1:]...), second} {
				if _, err := db.db.Exec("UPDATE "+table+" SET share=? WHERE presignature_id='first'", replacement); err != nil {
					t.Fatal(err)
				}
				if share, err := db.consumePresign(ctx, app, algorithm, keyID, "first"); err == nil || share.Share != nil {
					t.Fatal("accepted tampered or swapped ciphertext")
				}
				var count int
				if err := db.db.QueryRow("SELECT count(*) FROM " + table + " WHERE presignature_id='first'").Scan(&count); err != nil || count != 1 {
					t.Fatal("authentication failure removed the row", err)
				}
			}
			if _, err := db.db.Exec("UPDATE "+table+" SET share=? WHERE presignature_id='first'", first); err != nil {
				t.Fatal(err)
			}
			results := make(chan error, 8)
			for range cap(results) {
				go func() {
					share, err := db.consumePresign(ctx, app, algorithm, keyID, "first")
					if err == nil && !bytes.Equal(share.Share, plain) {
						err = errors.New("incorrect decrypted presignature")
					}
					clear(share.Share)
					results <- err
				}()
			}
			successes := 0
			for range cap(results) {
				err := <-results
				if err == nil {
					successes++
				} else if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal(err)
				}
			}
			if successes != 1 {
				t.Fatalf("consumed encrypted presignature %d times", successes)
			}
			share, err := db.consumePresign(ctx, app, algorithm, keyID, "")
			if err != nil || share.ID != "second" || !bytes.Equal(share.Share, plain) {
				t.Fatal("automatic selection did not decrypt the oldest record", err)
			}
			clear(share.Share)
			if outcome, ids, err := db.reservePresign(ctx, app, algorithm, "legacy", keyID, [32]byte{}); err != nil || outcome != Completed || len(ids) != 2 {
				t.Fatal("migration changed the batch reservation", err)
			}
			if _, err := db.consumePresign(ctx, app, algorithm, keyID, "first"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("batch replay resurrected a consumed presignature")
			}
		})
	}
}
