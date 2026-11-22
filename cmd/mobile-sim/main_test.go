package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandRejectsInvalidInputsBeforeOpeningStorage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"export"}, {"keygen", "-algorithm", "rsa"},
		{"keygen", "-threshold", "0"}, {"keygen", "-threshold", "-1"},
		{"sign", "-algorithm", "frost"},
		{"sign", "-key-id", "key", "extra"},
		{"sign", "-key-id", "key", "-threshold", "2"},
		{"presiggen"}, {"presiggen", "-key-id", "key", "-count", "0"},
		{"presiggen", "-key-id", "key", "-count", "9"},
		{"signwithpresig", "-key-id", "key"},
		{"signwithpresig", "-key-id", "key", "-presignature-id", "invalid"},
		{"sign", "-key-id", "key", "-chain-path", "not-json"},
		{"sign", "-key-id", "key", "-chain-path", "{}"},
		{"sign", "-key-id", "key", "-chain-path", "[null]"},
		{"sign", "-key-id", "key", "-chain-path", "[0,null]"},
		{"sign", "-key-id", "key", "-chain-path", "[-1]"},
		{"sign", "-key-id", "key", "-chain-path", "[2147483648]"},
		{"sign", "-key-id", "key", "-chain-path", "[4294967296]"},
		{"presiggen", "-key-id", "key", "-chain-path", "[0,1]"},
	} {
		if _, err := parseCommand(args); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
}

func TestSigningCommandsAcceptChainPaths(t *testing.T) {
	for _, mode := range []string{"sign", "signwithpresig"} {
		for _, path := range []string{"[]", "null", "[0,1,2147483647]"} {
			args := []string{mode, "-algorithm", "frost", "-key-id", "key", "-chain-path", path}
			if mode == "signwithpresig" {
				args = append(args, "-presignature-id", strings.Repeat("A", 43))
			}
			if _, err := parseCommand(args); err != nil {
				t.Fatalf("valid mobile chain path rejected: %v, %v", args, err)
			}
		}
	}
}

func TestPresignCommands(t *testing.T) {
	for _, args := range [][]string{
		{"presiggen", "-algorithm", "frost", "-key-id", "key", "-count", "2"},
		{"signwithpresig", "-algorithm", "ecdsa", "-key-id", "key", "-presignature-id", strings.Repeat("A", 43), "-message", "你好"},
	} {
		cmd, err := parseCommand(args)
		if err != nil || cmd.mode != args[0] || cmd.keyID != "key" {
			t.Fatalf("mobile presign command rejected: %v, %v", args, err)
		}
	}
}

func TestCommandPreservesRawMessageAndKeygenOptions(t *testing.T) {
	cmd, err := parseCommand([]string{"sign", "-config", "phone.json", "-algorithm", "ecdsa", "-key-id", "key", "-message", "你好"})
	if err != nil || cmd.message != "你好" || cmd.keyID != "key" || cmd.configPath != "phone.json" || cmd.algorithm != "ecdsa" {
		t.Fatalf("unexpected parsed command: %+v, %v", cmd, err)
	}
	cmd, err = parseCommand([]string{"keygen", "-algorithm", "frost", "-threshold", "2"})
	if err != nil || cmd.threshold != 2 || cmd.keyID != "" {
		t.Fatalf("optional generated key ID: %+v, %v", cmd, err)
	}
}

func TestSettingsResolveFilesAndReadSecretsOnlyFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phone.json")
	fixture := `{"partyId":"1","dataDir":"phone-db","peers":{"2":"127.0.0.1:9182","3":"127.0.0.1:9183"},"mpcTLS":{"caFile":"ca.crt","certFile":"phone.crt","keyFile":"phone.key"},"applicationID":"mobile-demo","encryptorMasterPasswordEnv":"TEST_MOBILE_PASSWORD","serverAPIKeyEnvs":{"2":"TEST_MOBILE_API_2","3":"TEST_MOBILE_API_3"}}`
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_MOBILE_PASSWORD", "phone-password-secret")
	t.Setenv("TEST_MOBILE_API_2", "server-two-secret")
	t.Setenv("TEST_MOBILE_API_3", "server-three-secret")
	settings, err := loadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	var resolved struct {
		DataDir string `json:"dataDir"`
		MPCTLS  struct {
			CAFile string `json:"caFile"`
		} `json:"mpcTLS"`
		ApplicationID string            `json:"applicationID"`
		ServerAPIKeys map[string]string `json:"serverAPIKeys"`
	}
	if err := json.Unmarshal([]byte(settings.configJSON), &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.DataDir != filepath.Join(dir, "phone-db") || resolved.MPCTLS.CAFile != filepath.Join(dir, "ca.crt") || resolved.ApplicationID != "mobile-demo" || resolved.ServerAPIKeys["2"] != "server-two-secret" || settings.password != "phone-password-secret" {
		t.Fatal("paths or environment credentials were not passed to embedded config")
	}
	if strings.Contains(settings.configJSON, "phone-password-secret") {
		t.Fatal("master password must not be serialized")
	}
	t.Setenv("TEST_MOBILE_API_3", "")
	if _, err := loadSettings(path); err == nil || strings.Contains(err.Error(), "server-two-secret") || strings.Contains(err.Error(), "phone-password-secret") {
		t.Fatal("missing credential was accepted or error exposed credentials")
	}
	fixture = strings.Replace(fixture, `"3":"TEST_MOBILE_API_3"`, `"4":"TEST_MOBILE_API_3"`, 1)
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_MOBILE_API_3", "server-three-secret")
	if _, err := loadSettings(path); err == nil {
		t.Fatal("credential mapping must match outbound peer IDs")
	}
}
