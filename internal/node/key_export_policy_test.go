package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

func TestKeyExportDisabledByDefault(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"wrappingKey": der})
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{
		`{}`,
		`{"keyTransfer":{}}`,
		`{"keyTransfer":{"wrappingPrivateKeyFile":"configured-local-key.pem"}}`,
		fmt.Sprintf(`{"keyTransfer":{"exportEnabled":false,"exportWrappingKeys":[%q]}}`,
			base64.StdEncoding.EncodeToString(der)),
	} {
		var cfg config.Config
		if err := json.Unmarshal([]byte(document), &cfg); err != nil {
			t.Fatal(err)
		}
		n := newNode(cfg)
		n.wrappingKey = key
		n.client.Transport = noBackupPeerTransport{}
		if n.allowWrappingKey(&key.PublicKey) {
			t.Fatalf("configured RSA key bypassed the disabled export feature: %s", document)
		}
		for _, algorithm := range []string{"ecdsa", "frost"} {
			for _, operation := range []string{"exportkey", "exportkeyshare"} {
				path := "/" + algorithm + "/keys/fixture/" + operation
				r := httptest.NewRequest("POST", path, bytes.NewReader(body))
				w := httptest.NewRecorder()
				// No store is installed. The feature gate must run before
				// reading a key or initiating an MPC session.
				n.restHandler().ServeHTTP(w, r)
				if w.Code != 403 {
					t.Fatalf("%s with %s returned %d, want 403", path, document, w.Code)
				}
			}
		}
	}
}
