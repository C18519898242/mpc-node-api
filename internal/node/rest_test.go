package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

func TestKeygenRejectsInvalidSessionID(t *testing.T) {
	node := newNode(config.Config{DataDir: t.TempDir()})
	request := httptest.NewRequest(http.MethodPost, "/v1/keygen", strings.NewReader(`{"sessionId":"../bad"}`))
	response := httptest.NewRecorder()
	node.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
