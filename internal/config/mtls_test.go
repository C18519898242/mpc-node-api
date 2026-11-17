package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMPCNetworkRequiresTLS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	base := `{"partyId":"1","restAddr":"127.0.0.1:8081","mpcAddr":"0.0.0.0:9081",
		"dataDir":"data","peers":{"2":"192.0.2.2:9082"}`
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(base + "}")
	if _, err := Load(path); err == nil {
		t.Fatal("plaintext MPC allowed outside loopback")
	}
	write(base + `,"mpcTLS":{"caFile":"ca.crt","certFile":"node.crt","keyFile":"node.key"}}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MPCTLS.KeyFile != filepath.Join(dir, "node.key") || cfg.MPCTLS.CAFile != filepath.Join(dir, "ca.crt") ||
		cfg.MPCTLS.CertFile != filepath.Join(dir, "node.crt") {
		t.Fatal("certificate paths are not relative to the config")
	}
}
