package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestServeRESTTLS(t *testing.T) {
	const fixtureConfig = "MPC_TEST_REST_TLS_CONFIG"
	if path := os.Getenv(fixtureConfig); path != "" {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal(Serve(cfg))
	}

	dir := t.TempDir()
	if err := peertls.GenerateDevDirectory(filepath.Join(dir, "tls"), party.IDSlice{"1", "2"}); err != nil {
		t.Fatal(err)
	}
	var addresses [3]string
	var ports [3]net.Listener
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		ports[i], addresses[i] = listener, listener.Addr().String()
	}
	const apiKey = "listener-fixture"
	digest := sha256.Sum256([]byte(apiKey))
	cfg := config.Config{
		PartyID: "1", RESTAddr: addresses[0], MPCAddr: addresses[1], DataDir: "data",
		Peers:                      map[party.ID]string{"2": addresses[2]},
		EncryptorMasterPasswordEnv: "MPC_TEST_REST_TLS_PASSWORD",
		MPCTLS: &config.MPCTLSConfig{
			CAFile: "tls/ca.crt", CertFile: "tls/node-1/node.crt", KeyFile: "tls/node-1/node.key",
		},
		RESTTLS: &config.RESTTLSConfig{CertFile: "tls/node-1/node.crt", KeyFile: "tls/node-1/node.key"},
		RESTAuth: &config.RESTAuthConfig{APIKeys: []config.APIKey{{
			ApplicationID: "default", SHA256: base64.StdEncoding.EncodeToString(digest[:]), RSADecryption: true,
		}}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, program, "-test.run=^TestServeRESTTLS$")
	child.Env = append(os.Environ(), fixtureConfig+"="+path, cfg.EncryptorMasterPasswordEnv+"=test password", "GODEBUG=tls10server=1")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	_ = ports[0].Close()
	_ = ports[1].Close()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	})

	ca, err := os.ReadFile(filepath.Join(dir, "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("failed to load test CA")
	}
	tlsConfig := &tls.Config{
		RootCAs: roots, ServerName: peertls.Name("1"), MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	base := "https://" + cfg.RESTAddr
	var response *http.Response
	for ctx.Err() == nil {
		response, err = client.Get(base + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil || response == nil {
		t.Fatalf("HTTPS health check failed: %v", err)
	}
	var health struct{ Status string }
	err = json.NewDecoder(response.Body).Decode(&health)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || health.Status != "ok" || err != nil {
		t.Fatalf("invalid health check response: HTTP %d, %v", response.StatusCode, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "APIKEY "+apiKey)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request returned HTTP %d", response.StatusCode)
	}
	legacy := tlsConfig.Clone()
	legacy.MinVersion, legacy.MaxVersion = tls.VersionTLS11, tls.VersionTLS11
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cfg.RESTAddr, legacy)
	if err == nil {
		_ = connection.Close()
		t.Fatal("REST listener accepted TLS 1.1")
	}
	if !strings.Contains(err.Error(), "protocol version not supported") {
		t.Fatalf("unexpected TLS 1.1 failure: %v", err)
	}
}
