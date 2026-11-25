package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
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

func TestKeyExportRejectsUnlistedWrappingKey(t *testing.T) {
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
	n := newNode(config.Config{
		PartyID: "1", Peers: map[party.ID]string{"2": "peer"},
		KeyTransfer: &config.KeyTransferConfig{ExportEnabled: true},
	})
	n.wrappingKey = key
	db, err := keystore.OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	n.keys = db
	const session = "export-fixture"
	routingID := mpcRoutingID(session)
	for _, algorithm := range []string{"ecdsa", "frost"} {
		for _, operation := range []string{"exportkey", "exportkeyshare"} {
			t.Run(algorithm+"/"+operation, func(t *testing.T) {
				call := func() int {
					path := "/" + algorithm + "/keys/fixture/" + operation + "?mpc_routing_id=" + routingID
					r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
					r.Header.Set("MPC-SessionID", session)
					r.Header.Set("MPC-RoutingID", routingID)
					r.Header.Add("MPC-Players", "1")
					r.Header.Add("MPC-Players", "2")
					w := httptest.NewRecorder()
					n.restHandler().ServeHTTP(w, r)
					return w.Code
				}
				n.config.KeyTransfer.ExportWrappingKeys = nil
				if status := call(); status != http.StatusForbidden {
					t.Errorf("unlisted node wrapping key returned HTTP %d, want 403", status)
				}
				n.config.KeyTransfer.ExportWrappingKeys = [][]byte{der}
				if status := call(); status != http.StatusNotFound {
					t.Errorf("listed wrapping key with missing key ID returned HTTP %d, want 404", status)
				}
			})
		}
	}
}
