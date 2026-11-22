package mobile

import (
	"slices"
	"testing"
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
	for _, cfg := range []string{`not JSON`, `{}`, `{"partyId":"1","peers":{"2":"127.0.0.1:9182"}}`} {
		if client, err := New(cfg, t.TempDir(), "password"); err == nil {
			client.Close()
			t.Fatal("accepted insecure mobile configuration")
		}
	}
}
