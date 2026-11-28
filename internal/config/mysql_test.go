package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestDatabaseConfigValidation(t *testing.T) {
	const base = `{"partyId":"1","restAddr":"127.0.0.1:8081","mpcAddr":"127.0.0.1:9081","peers":{"2":"127.0.0.1:9082"}`
	const mk = `,"encryptorMasterPasswordEnv":"MPC_NODE_1_MASTER_PASSWORD"`
	for _, tc := range []struct {
		name  string
		extra string
		valid bool
	}{
		{"mysql fields without dataDir", mk + `,"database":{"driver":"mysql","addr":"127.0.0.1:3306","user":"root","passwordEnv":"DB_PASS","dbName":"mpc_node_1","tlsMode":"preferred"}`, true},
		{"mysql docker dns", mk + `,"database":{"driver":"mysql","addr":"mysql:3306","user":"mpc","passwordEnv":"DB_PASS","dbName":"mpc_node_1","tlsMode":"true","caFile":"ca.crt"}`, true},
		{"mysql dsnEnv", mk + `,"database":{"driver":"mysql","dsnEnv":"MYSQL_DSN"}`, true},
		{"mysql requires encryptorMasterPasswordEnv", `,"database":{"driver":"mysql","dsnEnv":"MYSQL_DSN"}`, false},
		{"sqlite requires dataDir", ``, false},
		{"mysql fields rejected for sqlite", `,"dataDir":"data","database":{"driver":"sqlite","addr":"127.0.0.1:3306"}`, false},
		{"unsupported driver", `,"dataDir":"data","database":{"driver":"postgres","dsnEnv":"PG_DSN"}`, false},
		{"dsnEnv conflicts with structured fields", mk + `,"database":{"driver":"mysql","dsnEnv":"MYSQL_DSN","addr":"127.0.0.1:3306"}`, false},
		{"invalid dbName", mk + `,"database":{"driver":"mysql","addr":"127.0.0.1:3306","user":"root","dbName":"bad-db"}`, false},
		{"unspecified addr", mk + `,"database":{"driver":"mysql","addr":"0.0.0.0:3306","user":"root","dbName":"mpc_node_1"}`, false},
		{"bad tlsMode", mk + `,"database":{"driver":"mysql","addr":"127.0.0.1:3306","user":"root","dbName":"mpc_node_1","tlsMode":"verify"}`, false},
		{"caFile conflicts with false tlsMode", mk + `,"database":{"driver":"mysql","addr":"127.0.0.1:3306","user":"root","dbName":"mpc_node_1","tlsMode":"false","caFile":"ca.crt"}`, false},
		{"caFile conflicts with preferred tlsMode", mk + `,"database":{"driver":"mysql","addr":"127.0.0.1:3306","user":"root","dbName":"mpc_node_1","tlsMode":"preferred","caFile":"ca.crt"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "node.json")
			if err := os.WriteFile(path, []byte(base+tc.extra+"}"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("Load() error = %v, want valid=%v", err, tc.valid)
			}
			if tc.valid && cfg.Database != nil && cfg.Database.CAFile != "" && cfg.Database.CAFile != filepath.Join(dir, "ca.crt") {
				t.Fatalf("CAFile = %q, want relative resolution", cfg.Database.CAFile)
			}
		})
	}

	embeddedPath := filepath.Join(t.TempDir(), "embedded.json")
	if err := os.WriteFile(embeddedPath, []byte(`{"partyId":"1","peers":{"2":"127.0.0.1:9082"},"mpcTLS":{"caFile":"ca.crt","certFile":"node.crt","keyFile":"node.key"},"encryptorMasterPasswordEnv":"MK","database":{"driver":"mysql","dsnEnv":"MYSQL_DSN"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEmbedded(embeddedPath); err == nil {
		t.Fatal("LoadEmbedded accepted mysql storage")
	}

	embeddedCfg := Config{
		PartyID:  "1",
		DataDir:  t.TempDir(),
		Peers:    map[party.ID]string{"2": "127.0.0.1:9082"},
		MPCTLS:   &MPCTLSConfig{CAFile: "ca.crt", CertFile: "node.crt", KeyFile: "node.key"},
		Database: &DatabaseConfig{Driver: "mysql", DSNEnv: "MYSQL_DSN"},
	}
	if err := ValidateEmbedded(embeddedCfg); err == nil {
		t.Fatal("ValidateEmbedded accepted mysql storage")
	}
}
