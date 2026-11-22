package node

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestPeerRetryDelayBounds(t *testing.T) {
	if got := nextPeerRetryDelay(0); got != peerRetryInitial {
		t.Fatalf("nextPeerRetryDelay(0) = %s, want %s", got, peerRetryInitial)
	}
	delay := peerRetryInitial
	for _, want := range []time.Duration{200, 400, 800, 1600, 2000, 2000} {
		delay = nextPeerRetryDelay(delay)
		if delay != want*time.Millisecond {
			t.Fatalf("next delay = %s, want %s", delay, want*time.Millisecond)
		}
	}
	for i := 0; i < 20; i++ {
		delay = nextPeerRetryDelay(delay)
	}
	if delay != peerRetryMax {
		t.Fatalf("delay after growth = %s, want cap %s", delay, peerRetryMax)
	}
	low, high := peerRetryMax*4/5, peerRetryMax*6/5
	for i := 0; i < 100; i++ {
		jittered := jitterPeerRetryDelay(peerRetryMax)
		if jittered < low || jittered > high {
			t.Fatalf("jittered delay = %s, want within [%s, %s]", jittered, low, high)
		}
	}
}

type peerRetryTransport func(*http.Request) (*http.Response, error)

func (f peerRetryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func peerRetryNode(transport peerRetryTransport) *node {
	n := newNode(config.Config{PartyID: "1", Peers: map[party.ID]string{"2": "peer.invalid:9182"}})
	n.client = &http.Client{Transport: transport}
	return n
}

func peerRetryResponse(code int) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
}

func TestDeliverMessageRetriesTemporaryResponses(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			attempts := 0
			var firstAttempt time.Time
			var firstDeadline time.Time
			n := peerRetryNode(func(r *http.Request) (*http.Response, error) {
				attempts++
				if r.Method != http.MethodPost || r.URL.Path != "/internal/mpc/test" {
					t.Fatalf("unexpected delivery request: %s %s", r.Method, r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "message" {
					t.Fatalf("delivery body = %q, %v", body, err)
				}
				deadline, ok := r.Context().Deadline()
				if remaining := time.Until(deadline); !ok || remaining <= 0 || remaining > 30*time.Second {
					t.Fatalf("request has no valid 30s retry deadline: %v, %v", deadline, ok)
				}
				if attempts == 1 {
					firstAttempt = time.Now()
					firstDeadline = deadline
					if remaining := time.Until(deadline); remaining < 29*time.Second {
						t.Fatalf("retry budget is unexpectedly short: %s", remaining)
					}
					return peerRetryResponse(code), nil
				}
				if !deadline.Equal(firstDeadline) {
					t.Fatalf("retry reset delivery budget: %v, want %v", deadline, firstDeadline)
				}
				if elapsed := time.Since(firstAttempt); elapsed < 80*time.Millisecond {
					t.Fatalf("retried too quickly: %s", elapsed)
				}
				return peerRetryResponse(http.StatusNoContent), nil
			})
			if err := n.deliverMessage(context.Background(), "2", "/internal/mpc/test", []byte("message")); err != nil {
				t.Fatal(err)
			}
			if attempts != 2 {
				t.Fatalf("attempts = %d, want 2", attempts)
			}
		})
	}
}

func TestDeliverMessageDoesNotRetryPermanentFailures(t *testing.T) {
	certificateErr := &tls.CertificateVerificationError{Err: errors.New("untrusted peer")}
	for _, tc := range []struct {
		name string
		code int
		err  error
	}{
		{name: "forbidden", code: http.StatusForbidden},
		{name: "conflict", code: http.StatusConflict},
		{name: "server error", code: http.StatusInternalServerError},
		{name: "certificate verification", err: certificateErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			n := peerRetryNode(func(*http.Request) (*http.Response, error) {
				attempts++
				if tc.err != nil {
					return nil, tc.err
				}
				return peerRetryResponse(tc.code), nil
			})
			err := n.deliverMessage(context.Background(), "2", "/internal/mpc/test", nil)
			if err == nil || attempts != 1 {
				t.Fatalf("delivery = %v after %d attempts, want error after 1", err, attempts)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("delivery error lost certificate failure: %v", err)
			}
		})
	}
}

func TestDeliverMessageStopsOnParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	n := peerRetryNode(func(*http.Request) (*http.Response, error) {
		attempts++
		cancel()
		return peerRetryResponse(http.StatusNotFound), nil
	})
	defer cancel()
	started := time.Now()
	err := n.deliverMessage(ctx, "2", "/internal/mpc/test", nil)
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("delivery = %v after %d attempts, want canceled after 1", err, attempts)
	}
	if elapsed := time.Since(started); elapsed >= 80*time.Millisecond {
		t.Fatalf("cancellation waited for retry delay: %s", elapsed)
	}
}

func TestDeliverMessageHonorsEarlierParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	attempts := 0
	n := peerRetryNode(func(r *http.Request) (*http.Response, error) {
		attempts++
		if deadline, ok := r.Context().Deadline(); !ok || !deadline.Equal(wantDeadline) {
			t.Fatalf("request deadline = %v, %v, want parent deadline %v", deadline, ok, wantDeadline)
		}
		return peerRetryResponse(http.StatusServiceUnavailable), nil
	})
	err := n.deliverMessage(ctx, "2", "/internal/mpc/test", nil)
	if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 {
		t.Fatalf("delivery = %v after %d attempts, want deadline exceeded after 1", err, attempts)
	}
}

func TestDeliverMessageDoesNotStartAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	n := peerRetryNode(func(*http.Request) (*http.Response, error) {
		attempts++
		return peerRetryResponse(http.StatusNoContent), nil
	})
	err := n.deliverMessage(ctx, "2", "/internal/mpc/test", nil)
	if !errors.Is(err, context.Canceled) || attempts != 0 {
		t.Fatalf("delivery = %v after %d attempts, want canceled without attempting", err, attempts)
	}
}
