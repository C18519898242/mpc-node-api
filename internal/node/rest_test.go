package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

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
