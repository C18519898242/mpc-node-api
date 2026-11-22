package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestEmbeddedMobileCreateReopenAndSign(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "certs")
	if err := peertls.GenerateDevDirectory(certDir, []party.ID{"1", "2", "3"}); err != nil {
		t.Fatal(err)
	}
	files := func(id string) *config.MPCTLSConfig {
		return &config.MPCTLSConfig{CAFile: filepath.Join(certDir, "ca.crt"), CertFile: filepath.Join(certDir, "node-"+id, "node.crt"), KeyFile: filepath.Join(certDir, "node-"+id, "node.key")}
	}
	const app = "mobile-test"
	for _, algorithm := range []string{"frost", "ecdsa"} {
		t.Run(algorithm, func(t *testing.T) {
			servers := make(map[party.ID]*httptest.Server)
			nodes := make(map[party.ID]*node)
			credentials := make(map[party.ID]string)
			for _, id := range []party.ID{"2", "3"} {
				other := party.ID("2")
				if id == "2" {
					other = "3"
				}
				credential := "fixture-key-" + string(id)
				credentials[id] = credential
				digest := sha256.Sum256([]byte(credential))
				foreign := sha256.Sum256([]byte("foreign-key"))
				cfg := config.Config{PartyID: id, DataDir: t.TempDir(), Peers: map[party.ID]string{other: "127.0.0.1:1"}, MobilePeers: map[party.ID]string{"1": app}, MPCTLS: files(string(id)), RESTAuth: &config.RESTAuthConfig{APIKeys: []config.APIKey{{ApplicationID: app, SHA256: base64.StdEncoding.EncodeToString(digest[:])}, {ApplicationID: "foreign", SHA256: base64.StdEncoding.EncodeToString(foreign[:])}}}}
				n := newNode(cfg)
				n.workerContext = t.Context()
				if err := n.configureRESTAuth(); err != nil {
					t.Fatal(err)
				}
				db, err := keystore.OpenNodeSQLite(cfg.DataDir, string(id))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				mk, err := db.LoadOrCreateMasterKey(t.Context(), "backend fixture password")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { clear(mk) })
				if err := db.EnableShareEncryption(t.Context(), keystore.NewShareCipher(mk, string(id))); err != nil {
					t.Fatal(err)
				}
				n.keys = db
				tlsConfig, err := n.configurePeerTLS()
				if err != nil {
					t.Fatal(err)
				}
				s := httptest.NewUnstartedServer(n.peerHandler())
				s.TLS = tlsConfig
				s.StartTLS()
				t.Cleanup(s.Close)
				servers[id], nodes[id] = s, n
			}
			for _, n := range nodes {
				for peer := range n.config.Peers {
					n.config.Peers[peer] = servers[peer].Listener.Addr().String()
				}
			}
			cfg := config.Config{PartyID: "1", DataDir: t.TempDir(), Peers: map[party.ID]string{}, MPCTLS: files("1")}
			for id, s := range servers {
				cfg.Peers[id] = s.Listener.Addr().String()
			}
			if _, err := NewEmbedded(cfg, app, "", credentials); err == nil {
				t.Fatal("mobile node accepted an empty master password")
			}
			if _, err := NewEmbedded(cfg, app, "password", nil); err == nil {
				t.Fatal("mobile node accepted missing backend credentials")
			}
			client, err := NewEmbedded(cfg, app, "mobile fixture password", credentials)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			keyID := "mobile-" + algorithm
			created, err := client.CreateKey(algorithm, 2, keyID)
			if err != nil {
				t.Fatal(err)
			}
			var key struct {
				KeyID     string
				PublicKey []byte
			}
			if json.Unmarshal([]byte(created), &key) != nil || key.KeyID != keyID || len(key.PublicKey) == 0 {
				t.Fatal("invalid mobile key creation response")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			client, err = NewEmbedded(cfg, app, "mobile fixture password", credentials)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			signed, err := client.Sign(algorithm, keyID, []byte("mobile restart signing"))
			if err != nil {
				t.Fatal(err)
			}
			var signature struct {
				PublicKey []byte
				Signature []byte
			}
			if json.Unmarshal([]byte(signed), &signature) != nil || !bytes.Equal(signature.PublicKey, key.PublicKey) || len(signature.Signature) == 0 {
				t.Fatal("mobile restart changed public key")
			}
			ctx := context.WithValue(t.Context(), applicationContextKey{}, app)
			for _, n := range nodes {
				var pub []byte
				if algorithm == "frost" {
					pub, err = n.loadFROSTPublicKey(ctx, keyID, nil)
				} else {
					pub, err = n.loadECDSAPublicKey(ctx, keyID, nil)
				}
				if err != nil || !bytes.Equal(pub, key.PublicKey) {
					t.Fatal("mobile and server public keys differ")
				}
			}
			db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "node.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var format, count int
			if err := db.QueryRow("SELECT share_format FROM key_shares WHERE application_id=? AND algorithm=? AND key_id=?", app, algorithm, keyID).Scan(&format); err != nil || format != 1 {
				t.Fatal("mobile share was not encrypted", err)
			}
			if err := db.QueryRow("SELECT count(*) FROM node_master_key").Scan(&count); err != nil || count != 1 {
				t.Fatal("mobile MK was not persisted", err)
			}
			// A device certificate does not authorize a different application's API key.
			for _, path := range []string{"/internal/mobile/poll", "/internal/mobile/frost/keys", "/applications/foreign/internal/mpc/frost.fixture"} {
				r, _ := http.NewRequest("POST", servers["2"].URL+path, bytes.NewReader([]byte(`{}`)))
				r.Header.Set("Authorization", "APIKEY foreign-key")
				response, err := client.node.peerClients["2"].Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				want := 403
				if path[0:13] == "/applications" {
					want = 404
				}
				if response.StatusCode != want {
					t.Fatalf("%s: got %d, want %d", path, response.StatusCode, want)
				}
			}
			if wrong, err := NewEmbedded(cfg, app, "wrong password", credentials); err == nil {
				wrong.Close()
				t.Fatal("mobile database accepted wrong master password")
			}
			// Closing during an in-flight operation must cancel its workers and
			// polling before the MK is cleared or SQLite is closed.
			blocked := &blockedMobileSignTransport{base: client.node.peerClients["3"].Transport, arrived: make(chan struct{})}
			client.node.peerClients["3"].Transport = blocked
			signDone := make(chan error, 1)
			go func() { _, err := client.Sign(algorithm, keyID, []byte("interrupted signing")); signDone <- err }()
			select {
			case <-blocked.arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("mobile signing did not start")
			}
			closed := make(chan error, 1)
			go func() { closed <- client.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("close did not cancel the mobile operation")
			}
			if err := <-signDone; err == nil {
				t.Fatal("interrupted mobile operation succeeded")
			}
			if _, err := client.Sign(algorithm, keyID, []byte("after close")); err == nil {
				t.Fatal("closed embedded client signed")
			}
		})
	}
}

type blockedMobileSignTransport struct {
	base    http.RoundTripper
	arrived chan struct{}
	once    sync.Once
}

func (b *blockedMobileSignTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/sign") {
		b.once.Do(func() { close(b.arrived) })
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	return b.base.RoundTrip(r)
}
func (b *blockedMobileSignTransport) CloseIdleConnections() {
	if c, ok := b.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
