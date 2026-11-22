package mobile

import "testing"

func TestNewRequiresPrivateStorageAndSecureConfiguration(t *testing.T) {
	for _, cfg := range []string{`not JSON`, `{}`, `{"partyId":"1","peers":{"2":"127.0.0.1:9182"}}`} {
		if client, err := New(cfg, t.TempDir(), "password"); err == nil {
			client.Close()
			t.Fatal("accepted insecure mobile configuration")
		}
	}
}
