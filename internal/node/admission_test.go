package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestSessionAdmissionDoesNotConsumeReservations(t *testing.T) {
	transport := localPeerTransport{}
	nodes := make([]*node, 2)
	for i := range nodes {
		id, peer := party.ID(fmt.Sprint(i+1)), party.ID(fmt.Sprint(2-i))
		n := newNode(config.Config{PartyID: id, Peers: map[party.ID]string{peer: string(peer)}, DataDir: t.TempDir()})
		db, err := keystore.OpenNodeSQLite(n.config.DataDir, string(id))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		n.keys, n.client.Transport = db, transport
		nodes[i], transport[string(id)] = n, n.peerHandler()
	}
	call := func(n *node, path, sid string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path+"?mpc_routing_id="+mpcRoutingID(sid), bytes.NewReader(body)).WithContext(t.Context())
		r.Header.Set("MPC-SessionID", sid)
		r.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
		r.Header.Add("MPC-Players", "1")
		r.Header.Add("MPC-Players", "2")
		w := httptest.NewRecorder()
		n.restHandler().ServeHTTP(w, r)
		return w
	}
	results := make(chan *httptest.ResponseRecorder, len(nodes))
	for _, n := range nodes {
		go func() {
			results <- call(n, "/frost/keys", "source", []byte(`{"curve":"ed25519","threshold":1,"keyID":"source-key"}`))
		}()
	}
	for range nodes {
		if got := <-results; got.Code != http.StatusOK {
			t.Fatalf("source keygen: %d %s", got.Code, got.Body.String())
		}
	}
	n := nodes[0]
	for i := 0; i < maxAppActiveSessions; i++ {
		n.sessions[sessionKey{defaultApplication, fmt.Sprintf("busy-%d", i)}] = &keygenSession{}
	}
	t.Run("keycopy", func(t *testing.T) {
		got := call(n, "/frost/keys/_/keycopy", "copy-full", []byte(`{"curve":"ed25519","threshold":1,"keyID":"copy-key"}`))
		if got.Code != http.StatusServiceUnavailable {
			t.Fatalf("keycopy: %d %s", got.Code, got.Body.String())
		}
		reservation, err := n.keys.Reserve(t.Context(), defaultApplication, keystore.Key{Algorithm: "frost", SessionID: "copy.copy-full", KeyID: "copy-key", Threshold: 1})
		if err != nil || reservation != keystore.Reserved {
			t.Fatalf("capacity rejection consumed keycopy reservation: %v, %v", reservation, err)
		}
	})
	t.Run("reshare", func(t *testing.T) {
		got := call(n, "/frost/keys/source-key/reshare", "reshare-full", nil)
		if got.Code != http.StatusServiceUnavailable {
			t.Fatalf("reshare: %d %s", got.Code, got.Body.String())
		}
		reservation, _, err := n.keys.ReserveReshare(t.Context(), defaultApplication, keystore.Reshare{Algorithm: "frost", SessionID: "reshare-full", KeyID: "source-key"})
		if err != nil || reservation != keystore.Reserved {
			t.Fatalf("capacity rejection consumed reshare reservation: %v, %v", reservation, err)
		}
	})
	t.Run("import", func(t *testing.T) {
		wrapping, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		n.wrappingKey = wrapping
		share, err := n.keys.Load(t.Context(), defaultApplication, "frost", "source-key")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(share)
		payload, err := json.Marshal(keyTransferPayload{Version: 1, Algorithm: "frost", KeyID: "source-key", ExportID: make([]byte, 32), Share: share})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(payload)
		wrapped, err := wrapKeyShare(&wrapping.PublicKey, payload)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(struct {
			KeyID           string          `json:"keyID"`
			Threshold       int             `json:"threshold"`
			WrappedKeyShare wrappedKeyShare `json:"wrappedKeyShare"`
		}{"import-key", 1, wrapped})
		if err != nil {
			t.Fatal(err)
		}
		got := call(n, "/frost/keys/importkey", "import-full", body)
		if got.Code != http.StatusServiceUnavailable {
			t.Fatalf("import: %d %s", got.Code, got.Body.String())
		}
		reservation, err := n.keys.Reserve(t.Context(), defaultApplication, keystore.Key{Algorithm: "frost", SessionID: "import.import-full", KeyID: "import-key", Threshold: 1})
		if err != nil || reservation != keystore.Reserved {
			t.Fatalf("capacity rejection consumed import reservation: %v, %v", reservation, err)
		}
	})
	t.Run("prepared and committed reshare bypass capacity", func(t *testing.T) {
		op := keystore.Reshare{Algorithm: "frost", SessionID: "resume-prepared", KeyID: "source-key"}
		if reservation, _, err := n.keys.ReserveReshare(t.Context(), defaultApplication, op); err != nil || reservation != keystore.Reserved {
			t.Fatalf("prepare reservation: %v, %v", reservation, err)
		}
		share, err := n.keys.Load(t.Context(), defaultApplication, "frost", "source-key")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(share)
		if err := n.keys.StageReshare(t.Context(), defaultApplication, op, [32]byte{1}, share); err != nil {
			t.Fatal(err)
		}
		reservation, state, session, err := n.beginReshare(t.Context(), op)
		if err != nil || reservation != keystore.Completed || state.Committed || len(state.Digest) != 32 || session != nil {
			t.Fatalf("prepared recovery at capacity: %v, %+v, %v, %v", reservation, state, session, err)
		}
		if err := n.keys.CommitReshare(t.Context(), defaultApplication, op); err != nil {
			t.Fatal(err)
		}
		reservation, state, session, err = n.beginReshare(t.Context(), op)
		if err != nil || reservation != keystore.Completed || !state.Committed || session != nil {
			t.Fatalf("committed recovery at capacity: %v, %+v, %v, %v", reservation, state, session, err)
		}
	})
}
