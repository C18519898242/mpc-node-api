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

func TestContainerNetworkConfig(t *testing.T) {
	const tls = `,"mpcTLS":{"caFile":"ca.crt","certFile":"node.crt","keyFile":"node.key"}`
	const optIn = `,"allowNonLoopbackREST":true`
	const auth = `,"restAuth":{"apiKeys":[{"applicationID":"default","sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`
	for _, test := range []struct {
		name, rest, peers, options string
		valid                      bool
	}{
		{"authenticated container", "0.0.0.0:8080", `{"2":"node-2:9000","3":"node-3:9000"}`, tls + optIn + auth, true},
		{"require REST opt-in", "0.0.0.0:8080", `{"2":"192.0.2.2:9000"}`, tls + auth, false},
		{"require REST auth", "0.0.0.0:8080", `{"2":"192.0.2.2:9000"}`, tls + optIn, false},
		{"require API key", "0.0.0.0:8080", `{"2":"192.0.2.2:9000"}`, tls + optIn + `,"restAuth":{"apiKeys":[]}`, false},
		{"require peer TLS for DNS", "127.0.0.1:8080", `{"2":"node-2:9000"}`, "", false},
		{"reject duplicate peer address", "127.0.0.1:8080", `{"2":"node-2:9000","3":"NODE-2:09000"}`, tls, false},
		{"reject peer URL", "127.0.0.1:8080", `{"2":"node-2/path:9000"}`, tls, false},
		{"reject zero peer port", "127.0.0.1:8080", `{"2":"node-2:0"}`, tls, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "node.json")
			data := `{"partyId":"1","restAddr":"` + test.rest + `","mpcAddr":"127.0.0.1:9000","dataDir":"data","peers":` + test.peers + test.options + `}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestRESTCertificateConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	base := `{"partyId":"1","restAddr":"127.0.0.1:8081","mpcAddr":"127.0.0.1:9081",
		"dataDir":"data","peers":{"2":"127.0.0.1:9082"},"restTLS":`
	write := func(tls string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(base+tls+"}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"certFile":"rest.crt"}`)
	if _, err := Load(path); err == nil {
		t.Fatal("REST TLS accepted a missing keyFile")
	}
	write(`{"certFile":"rest.crt","keyFile":"rest.key"}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RESTTLS == nil || cfg.RESTTLS.CertFile != filepath.Join(dir, "rest.crt") || cfg.RESTTLS.KeyFile != filepath.Join(dir, "rest.key") {
		t.Fatal("REST certificate paths are not relative to the config")
	}
	const decryptionAuth = `,"restAuth":{"apiKeys":[{"applicationID":"default","sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","rsaDecryption":true}]}`
	write(`null` + decryptionAuth)
	if _, err := Load(path); err == nil {
		t.Fatal("RSA decryption credential was accepted without REST TLS")
	}
	write(`{"certFile":"rest.crt","keyFile":"rest.key"}` + decryptionAuth)
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
