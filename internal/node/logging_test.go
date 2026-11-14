package node

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type failingLogStore struct{ shareStore }

func (failingLogStore) Load(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("sensitive-storage-error")
}

func TestSignLogsOnlyOperationMetadata(t *testing.T) {
	var logs bytes.Buffer
	n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "node2"}})
	n.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	n.keys = failingLogStore{}
	const sessionID = "sensitive-session"
	routingID := mpcRoutingID(sessionID)
	request := httptest.NewRequest(http.MethodPost, "/frost/keys/sensitive-key/sign?mpc_routing_id="+routingID,
		strings.NewReader(`{"message":"c2Vuc2l0aXZlLW1lc3NhZ2U="}`))
	request.Header.Set("MPC-SessionID", sessionID)
	request.Header.Set("MPC-RoutingID", routingID)
	request.Header.Set("Authorization", "sensitive-authorization")
	request.Header.Add("MPC-Players", "1")
	request.Header.Add("MPC-Players", "2")
	response := httptest.NewRecorder()
	n.restHandler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	assertSafeLogs(t, logs.String(), `"operation":"sign"`, `"algorithm":"frost"`, `"status":500`, `"duration_ms":`)
}

func TestSignProtocolFailureDoesNotLogPeerError(t *testing.T) {
	var logs bytes.Buffer
	n := newNode(config.Config{PartyID: "1"})
	n.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	session := n.beginSign("frost-sign.sensitive-session", [32]byte{}, func(context.Context, *keygenSession) ([]byte, error) {
		return nil, errors.New("sensitive-peer-error")
	})
	<-session.done
	assertSafeLogs(t, logs.String(), `"operation":"sign"`, `"algorithm":"frost"`, `"result":"failed"`)
}

func assertSafeLogs(t *testing.T, logs string, fields ...string) {
	t.Helper()
	if strings.Contains(logs, "sensitive-") || strings.Contains(logs, "c2Vuc2l0aXZlLW1lc3NhZ2U=") {
		t.Fatal("sensitive request or protocol data appeared in logs")
	}
	for _, field := range fields {
		if !strings.Contains(logs, field) {
			t.Errorf("log missing %s: %s", field, logs)
		}
	}
}
