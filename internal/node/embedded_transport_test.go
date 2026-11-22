package node

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type mobileResponseTransport func(*http.Request) (*http.Response, error)

func (f mobileResponseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMobileRejectsMalformedOrMisroutedPollMessages(t *testing.T) {
	for _, body := range []string{
		`not JSON`,
		`{"sequence":0,"message":{"From":"2","To":"1"}}`,
		`{"sequence":2,"message":{"From":"2","To":"1"}}`,
		`{"sequence":1,"message":{"From":"3","To":"1"}}`,
		`{"sequence":1,"message":{"From":"2","To":"3"}}`,
	} {
		n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "127.0.0.1:9182"}})
		n.peerClients = map[party.ID]*http.Client{"2": {Transport: mobileResponseTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}}
		e := &Embedded{node: n, application: "mobile", credentials: map[party.ID]string{"2": "fixture"}}
		if err := e.pollPeer(t.Context(), "2", "frost.fixture"); err == nil {
			t.Fatal("accepted malformed or misrouted poll message")
		}
	}
}
