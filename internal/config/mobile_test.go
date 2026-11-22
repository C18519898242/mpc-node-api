package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestMobilePeerConfigurationRequiresApplicationAndTLS(t *testing.T) {
	base := Config{PartyID: "2", RESTAddr: "127.0.0.1:8182", MPCAddr: "127.0.0.1:9182", DataDir: "data", Peers: map[party.ID]string{"3": "127.0.0.1:9183"}, MobilePeers: map[party.ID]string{"1": "mobile"}, MPCTLS: &MPCTLSConfig{CAFile: "ca.crt", CertFile: "node.crt", KeyFile: "node.key"}, RESTAuth: &RESTAuthConfig{APIKeys: []APIKey{{ApplicationID: "mobile"}}}}
	for _, test := range []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{"valid", func(*Config) {}, true},
		{"no TLS", func(c *Config) { c.MPCTLS = nil }, false},
		{"no auth", func(c *Config) { c.RESTAuth = nil }, false},
		{"wrong application", func(c *Config) { c.MobilePeers["1"] = "other" }, false},
		{"duplicate peer", func(c *Config) { c.Peers["1"] = "127.0.0.1:9181" }, false},
		{"self as mobile", func(c *Config) { c.MobilePeers["2"] = "mobile" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, _ := json.Marshal(base)
			var cfg Config
			_ = json.Unmarshal(encoded, &cfg)
			test.change(&cfg)
			encoded, _ = json.Marshal(cfg)
			file := filepath.Join(t.TempDir(), "node.json")
			if err := os.WriteFile(file, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(file)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestEmbeddedConfigurationHasNoListeners(t *testing.T) {
	cfg := Config{PartyID: "1", DataDir: t.TempDir(), Peers: map[party.ID]string{"2": "127.0.0.1:9182", "3": "127.0.0.1:9183"}, MPCTLS: &MPCTLSConfig{CAFile: "ca", CertFile: "cert", KeyFile: "key"}}
	if err := ValidateEmbedded(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RESTAddr = "127.0.0.1:8181"
	if err := ValidateEmbedded(cfg); err == nil {
		t.Fatal("embedded node accepted a listening address")
	}
	cfg.RESTAddr = ""
	cfg.MPCTLS = nil
	if err := ValidateEmbedded(cfg); err == nil {
		t.Fatal("embedded node accepted plaintext transport")
	}
}
