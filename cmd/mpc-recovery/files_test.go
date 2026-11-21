package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateOutputNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := writeJSON(path, map[string]string{"privateKey": "fixture"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(path, map[string]string{"privateKey": "other"}); err == nil {
		t.Fatal("overwrote an existing private key file")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing private file changed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows permissions are controlled by the output directory ACL.
	if info.Mode().Perm()&0077 != 0 && os.PathSeparator != '\\' {
		t.Fatal("private output has group or world access")
	}
}

func TestCLIRejectsInvalidInput(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"recover"}, {"validate", "-in", "one", "-in", "two", "-public-key", "pub", "-rsa-key", "rsa"}} {
		if err := run(args, new(bytes.Buffer)); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	for _, input := range []string{`{"unknown":true}`, `{} {}`, `not json`} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		var target struct{}
		if err := readJSON(path, &target); err == nil {
			t.Fatal("accepted malformed JSON")
		}
	}
}
