package mobile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestChainPathJSON(t *testing.T) {
	for raw, want := range map[string][]uint32{"": nil, "null": nil, "[]": nil, "[0,1,2147483647]": {0, 1, 2147483647}} {
		got, err := parseChainPath(raw)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("path %q: got %v, error %v", raw, got, err)
		}
	}
	client := new(Client)
	for _, raw := range []string{"bad", "{}", `"m/0/1"`, "[null]", "[0,null]", "[-1]", "[1.5]", "[true]", "[2147483648]", "[4294967296]"} {
		if _, err := parseChainPath(raw); err == nil {
			t.Fatalf("accepted invalid path %q", raw)
		}
		// Invalid input must fail before touching the embedded node or its shares.
		if _, err := client.SignWithPath("frost", "key", nil, raw); err == nil {
			t.Fatal("online signing accepted an invalid path")
		}
		if _, err := client.SignWithPresignatureAndPath("frost", "key", "id", nil, raw); err == nil {
			t.Fatal("presign signing accepted an invalid path")
		}
	}
}

func TestNewRequiresPrivateStorageAndSecureConfiguration(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "certs")
	if err := peertls.GenerateDevDirectory(certDir, party.IDSlice{"1", "2"}); err != nil {
		t.Fatal(err)
	}
	validMap := map[string]any{
		"partyId":       "1",
		"applicationID": "mobile-app",
		"peers":         map[string]string{"2": "127.0.0.1:9182"},
		"serverAPIKeys": map[string]string{"2": "server-key-2"},
		"mpcTLS": map[string]string{
			"caFile":   filepath.Join(certDir, "ca.crt"),
			"certFile": filepath.Join(certDir, "node-1", "node.crt"),
			"keyFile":  filepath.Join(certDir, "node-1", "node.key"),
		},
	}
	validJSON, err := json.Marshal(validMap)
	if err != nil {
		t.Fatal(err)
	}
	mysqlMap := make(map[string]any, len(validMap)+1)
	for k, v := range validMap {
		mysqlMap[k] = v
	}
	mysqlMap["database"] = map[string]any{
		"driver":      "mysql",
		"addr":        "127.0.0.1:3306",
		"user":        "root",
		"passwordEnv": "DB_PASS",
		"dbName":      "mpc_node_1",
	}
	mysqlJSON, err := json.Marshal(mysqlMap)
	if err != nil {
		t.Fatal(err)
	}

	for _, cfg := range []string{`not JSON`, `{}`, `{"partyId":"1","peers":{"2":"127.0.0.1:9182"}}`, string(mysqlJSON)} {
		if client, err := New(cfg, t.TempDir(), "password"); err == nil {
			client.Close()
			t.Fatalf("accepted insecure or mysql mobile configuration: %s", cfg)
		}
	}

	dataDir := t.TempDir()
	client, err := New(string(validJSON), dataDir, "mobile-password")
	if err != nil {
		t.Fatalf("valid mobile configuration failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "node.sqlite")); err != nil {
		t.Fatalf("expected SQLite database for mobile node: %v", err)
	}
}
