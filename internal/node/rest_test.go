package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

func TestNodeInfo(t *testing.T) {
	handler := newNode(config.Config{}).restHandler()
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/version", `{"version":"1"}`},
		{"/info/protocols", `{
			"ecdsa":{"name":"cmp","curve":"secp256k1","version":1},
			"frost":{"name":"frost","curve":"ed25519","version":1}
		}`},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s returned %d with content type %q", tc.path, w.Code, w.Header().Get("Content-Type"))
		}
		var actual, expected any
		if json.Unmarshal(w.Body.Bytes(), &actual) != nil || json.Unmarshal([]byte(tc.want), &expected) != nil ||
			!reflect.DeepEqual(actual, expected) {
			t.Errorf("%s returned %s, want %s", tc.path, w.Body.String(), tc.want)
		}
	}
}

func TestSchnorrRoutesNotRegistered(t *testing.T) {
	handler := newNode(config.Config{}).restHandler()
	for _, path := range []string{"/schnorr/keys/key/reshare", "/schnorr/keys/key/keycopy"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("%s returned %d, want 404", path, response.Code)
		}
	}
}

func TestKeygenRejectsInvalidSessionID(t *testing.T) {
	node := newNode(config.Config{DataDir: t.TempDir()})
	request := httptest.NewRequest(http.MethodPost, "/v1/keygen", strings.NewReader(`{"sessionId":"../bad"}`))
	response := httptest.NewRecorder()
	node.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
