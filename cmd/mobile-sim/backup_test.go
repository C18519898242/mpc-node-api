package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupFileIsPrivateAndNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share.backup.json")
	encrypted := []byte(`{"ciphertext":"encrypted fixture"}`)
	if err := writeBackupFile(path, encrypted); err != nil {
		t.Fatal(err)
	}
	if err := writeBackupFile(path, []byte("replacement")); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, encrypted) {
		t.Fatal("existing backup was changed", err)
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatal("backup permissions are not private", err)
	}
}

func TestExportRequiresPasswordBeforeOpeningStorage(t *testing.T) {
	t.Setenv("TEST_MOBILE_BACKUP_PASSWORD", "")
	var output bytes.Buffer
	err := run([]string{"exportkeyshare", "-config", "missing-config.json", "-key-id", "key", "-out", filepath.Join(t.TempDir(), "backup.json"), "-backup-password-env", "TEST_MOBILE_BACKUP_PASSWORD"}, &output)
	if err == nil || !strings.Contains(err.Error(), "missing backup password") || output.Len() != 0 {
		t.Fatal("export touched storage or output before validating its password")
	}
}
