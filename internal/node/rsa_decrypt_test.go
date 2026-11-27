package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

const rsaDecryptToken = "rsa-decrypt-fixture"
const rsaOtherToken = "same-application-fixture"

func rsaTestRESTAuth() *config.RESTAuthConfig {
	digest := func(token string) string {
		sum := sha256.Sum256([]byte(token))
		return base64.StdEncoding.EncodeToString(sum[:])
	}
	return &config.RESTAuthConfig{APIKeys: []config.APIKey{
		{ApplicationID: defaultApplication, SHA256: digest(rsaDecryptToken), RSADecryption: true},
		{ApplicationID: defaultApplication, SHA256: digest(rsaOtherToken)},
	}}
}

func TestRSADecryptSharesCombine(t *testing.T) {
	players, nodes := rsaTestNodes(t, rsaTestRESTAuth())
	var rest [3]*httptest.Server
	for i, n := range nodes {
		rest[i] = httptest.NewTLSServer(n.restHandler())
		t.Cleanup(rest[i].Close)
	}
	type reply struct {
		status int
		header http.Header
		body   []byte
		err    error
	}
	call := func(i int, path, usage string, body []byte) reply {
		const session = "rsa-decrypt-fixture"
		routingID := mpcRoutingID(session)
		if path == "/rsa/keys" {
			path += "?mpc_routing_id=" + routingID
			body, _ = json.Marshal(map[string]any{"keyID": "decrypt-fixture", "bits": 2048, "threshold": 1, "usage": usage})
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rest[i].URL+path, bytes.NewReader(body))
		if err != nil {
			return reply{err: err}
		}
		req.Header.Set("Authorization", "APIKEY "+rsaDecryptToken)
		if usage != "" {
			req.Header.Set("MPC-SessionID", session)
			req.Header.Set("MPC-RoutingID", routingID)
			for _, player := range players {
				req.Header.Add("MPC-Players", string(player))
			}
		}
		res, err := rest[i].Client().Do(req)
		if err != nil {
			return reply{err: err}
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return reply{status: res.StatusCode, header: res.Header, body: data, err: err}
	}
	assertStatus := func(result reply, status int) {
		t.Helper()
		if result.err != nil || result.status != status {
			t.Fatalf("request returned %d, want %d (%v, %s)", result.status, status, result.err, result.body)
		}
	}
	results := make(chan reply, len(rest))
	for i := range rest {
		go func() { results <- call(i, "/rsa/keys", "decrypt", nil) }()
	}
	for range rest {
		result := <-results
		assertStatus(result, http.StatusOK)
		var generated generateKeyResponse
		if err := json.Unmarshal(result.body, &generated); err != nil || generated.KeyID != "decrypt-fixture" {
			t.Fatalf("invalid keygen response: %s", result.body)
		}
	}
	stored, err := nodes[0].keys.Load(t.Context(), defaultApplication, "rsa", "decrypt-fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored)
	var legacy struct{ Share []byte }
	if err := json.Unmarshal(stored, &legacy); err != nil || len(legacy.Share) != 0 {
		t.Fatal("an older signing-only binary could load the decryption key as a signing key")
	}
	assertStatus(call(0, "/rsa/keys", "sign", nil), http.StatusConflict)
	// Make the next replay validate the persisted key after a restart.
	nodes[0].mu.Lock()
	nodes[0].sessions = make(map[sessionKey]*keygenSession)
	nodes[0].mu.Unlock()
	assertStatus(call(0, "/rsa/keys", "sign", nil), http.StatusConflict)
	assertStatus(call(0, "/rsa/keys", "decrypt", nil), http.StatusOK)

	const keyPath = "/rsa/keys/decrypt-fixture/"
	result := call(0, keyPath+"publickey", "", []byte(`{}`))
	assertStatus(result, http.StatusOK)
	var metadata struct {
		PublicKey       []byte
		Players         uint
		RequiredSigners uint
	}
	if err := json.Unmarshal(result.body, &metadata); err != nil || metadata.Players != 3 || metadata.RequiredSigners != 2 {
		t.Fatalf("invalid public key response: %s", result.body)
	}
	parsed, err := x509.ParsePKIXPublicKey(metadata.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected an RSA public key")
	}
	message, label := []byte("threshold decryption fixture"), []byte("OAEP test label")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, message, label)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string][]byte{"ciphertext": ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	signRequest, _ := json.Marshal(map[string][]byte{"messageHash": digest[:]})
	assertStatus(call(0, keyPath+"sign", "", signRequest), http.StatusForbidden)
	canonical := base64.StdEncoding.EncodeToString(ciphertext)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lastDigit := len(canonical) - 3 // a 2048-bit ciphertext requires two pad characters
	padBits := strings.IndexByte(alphabet, canonical[lastDigit]) + 1
	nonCanonical := canonical[:lastDigit] + string(alphabet[padBits]) + canonical[lastDigit+1:]
	for _, invalid := range [][]byte{
		[]byte(`{"ciphertext":"` + nonCanonical + `"}`),
		[]byte(`{"ciphertext":"` + canonical + `\n"}`),
		[]byte(`{"ciphertext":"AA=="}`),
		[]byte(`{"ciphertext":"` + canonical + `","label":""}`),
	} {
		assertStatus(call(0, keyPath+"decrypt", "", invalid), http.StatusBadRequest)
	}
	parts := make([]thresholdrsa.DecryptionShare, 0, 2)
	for _, i := range []int{0, 2} {
		result := call(i, keyPath+"decrypt", "", body)
		assertStatus(result, http.StatusOK)
		var response struct {
			PartialDecryption []byte
		}
		var envelope struct {
			Format, KeyID                string
			PublicKey, Ciphertext, Share []byte
			Players, Threshold           uint
		}
		var part thresholdrsa.DecryptionShare
		if result.header.Get("Cache-Control") != "no-store" || json.Unmarshal(result.body, &response) != nil ||
			json.Unmarshal(response.PartialDecryption, &envelope) != nil || envelope.Format != "circl-rsa-oaep-sha256-v1" ||
			envelope.KeyID != "decrypt-fixture" || envelope.Threshold != 2 || envelope.Players != 3 ||
			!bytes.Equal(envelope.PublicKey, metadata.PublicKey) || !bytes.Equal(envelope.Ciphertext, ciphertext) ||
			part.UnmarshalBinary(envelope.Share) != nil || part.Index != uint(i+1) {
			t.Fatalf("invalid partial decryption response from node %d", i+1)
		}
		parts = append(parts, part)
	}
	plaintext, err := thresholdrsa.CombineDecryptionSharesOAEP(key, 3, 2, parts, ciphertext, label)
	if err != nil || !bytes.Equal(plaintext, message) {
		t.Fatalf("could not recover plaintext: %v", err)
	}
}

func TestRSADecryptionRequiresCredentialPermissionAndTLS(t *testing.T) {
	for _, tc := range []struct {
		name, scheme, token string
		configureAuth       bool
		want                int
	}{
		{"authentication disabled", "https", rsaDecryptToken, false, http.StatusForbidden},
		{"credential missing", "https", "", true, http.StatusUnauthorized},
		{"credential from same application", "https", rsaOtherToken, true, http.StatusForbidden},
		{"TLS missing", "http", rsaDecryptToken, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "node-2:9000"}, MPCTLS: &config.MPCTLSConfig{}}
			if tc.configureAuth {
				cfg.RESTAuth = rsaTestRESTAuth()
			}
			n := newNode(cfg)
			n.shareCipher = keystore.NewShareCipher(make([]byte, 32), "1")
			if err := n.configureRESTAuth(); err != nil {
				t.Fatal(err)
			}
			handler := n.restHandler()
			const session = "auth-fixture"
			routingID := mpcRoutingID(session)
			for _, operation := range []struct{ path, body string }{
				{"/rsa/keys?mpc_routing_id=" + routingID, `{"bits":2048,"threshold":1,"usage":"decrypt"}`},
				{"/rsa/keys/fixture/decrypt", `{"ciphertext":"AA=="}`},
			} {
				r := httptest.NewRequest(http.MethodPost, tc.scheme+"://node.example"+operation.path, strings.NewReader(operation.body))
				r.Header.Set("MPC-SessionID", session)
				r.Header.Set("MPC-RoutingID", routingID)
				r.Header.Add("MPC-Players", "1")
				r.Header.Add("MPC-Players", "2")
				r.Header.Set("X-Forwarded-Proto", "https")
				if tc.token != "" {
					r.Header.Set("Authorization", "APIKEY "+tc.token)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Errorf("%s returned %d, want %d (%s)", operation.path, w.Code, tc.want, w.Body.String())
				}
			}
		})
	}
}
