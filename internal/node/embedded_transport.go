package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func (e *Embedded) coordinate(path, route, sid string, body []byte, pollRoutes ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(e.ctx, keygenTimeout+5*time.Second)
	defer cancel()
	e.node.workerContext = ctx
	type result struct {
		data []byte
		err  error
	}
	responses := make(chan result, len(e.node.config.Peers)+1)
	pollErrors := make(chan error, 1)
	pollCtx, stopPolls := context.WithCancel(ctx)
	var polls sync.WaitGroup
	if len(pollRoutes) == 0 {
		pollRoutes = []string{route}
	}
	for peer := range e.node.config.Peers {
		for _, pollRoute := range pollRoutes {
			polls.Add(1)
			go func() {
				defer polls.Done()
				if err := e.pollPeer(pollCtx, peer, pollRoute); err != nil && pollCtx.Err() == nil {
					select {
					case pollErrors <- err:
					default:
					}
				}
			}()
		}
		go func() {
			data, err := e.remoteCall(ctx, peer, "/internal/mobile"+path, sid, body, false)
			responses <- result{data, err}
		}()
	}
	go func() { data, err := e.localCall(ctx, path, sid, body); responses <- result{data, err} }()
	var agreed []byte
	var failure error
	for remaining := len(e.node.config.Peers) + 1; remaining > 0; {
		select {
		case response := <-responses:
			remaining--
			if response.err != nil && failure == nil {
				failure = response.err
				cancel()
			}
			if response.err == nil {
				if agreed == nil {
					agreed = response.data
				} else if !bytes.Equal(bytes.TrimSpace(agreed), bytes.TrimSpace(response.data)) && failure == nil {
					failure = errors.New("mobile MPC participants returned different results")
					cancel()
				}
			}
		case err := <-pollErrors:
			if failure == nil {
				failure = err
				cancel()
			}
		}
	}
	stopPolls()
	polls.Wait()
	return agreed, failure
}

func (e *Embedded) setSessionHeaders(r *http.Request, sid string) {
	if sid == "" {
		return
	}
	r.Header.Set("MPC-SessionID", sid)
	r.Header.Set("MPC-RoutingID", mpcRoutingID(sid))
	query := r.URL.Query()
	query.Set("mpc_routing_id", mpcRoutingID(sid))
	r.URL.RawQuery = query.Encode()
	for _, id := range e.node.configuredPlayers() {
		r.Header.Add("MPC-Players", string(id))
	}
}

func (e *Embedded) remoteCall(ctx context.Context, peer party.ID, path, sid string, body []byte, poll bool) ([]byte, error) {
	endpoint := url.URL{Scheme: "https", Host: e.node.config.Peers[peer], Path: path}
	r, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "APIKEY "+e.credentials[peer])
	r.Header.Set("Content-Type", "application/json")
	e.setSessionHeaders(r, sid)
	client := *e.node.peerClients[peer]
	if !poll {
		client.Timeout = keygenTimeout + 5*time.Second
	}
	response, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("mobile backend %s request failed", peer)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("invalid mobile backend response size")
	}
	if poll && (response.StatusCode == 404 || response.StatusCode == 204) {
		return nil, nil
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("mobile backend %s rejected request (HTTP %d)", peer, response.StatusCode)
	}
	return data, nil
}

func (e *Embedded) pollPeer(ctx context.Context, peer party.ID, route string) error {
	var ack uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, _ := json.Marshal(struct {
			SessionID string `json:"sessionID"`
			Ack       uint64 `json:"ack"`
		}{route, ack})
		data, err := e.remoteCall(ctx, peer, "/internal/mobile/poll", "", body, true)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		var delivery mobileDelivery
		var message protocol.Message
		if json.Unmarshal(data, &delivery) != nil || delivery.Sequence == 0 || (delivery.Sequence != ack && delivery.Sequence != ack+1) || json.Unmarshal(delivery.Message, &message) != nil || message.From != peer || !message.IsFor(e.node.config.PartyID) {
			return errors.New("invalid polled MPC message")
		}
		if delivery.Sequence == ack {
			continue
		}
		r, _ := http.NewRequestWithContext(ctx, "POST", "http://embedded", nil)
		w := newEmbeddedResponse()
		e.node.acceptMessage(w, withApplication(r, e.application), route, &message)
		if w.code == 204 {
			ack = delivery.Sequence
		} else if w.code == 404 || w.code == 503 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		} else {
			return errors.New("local node rejected polled MPC message")
		}
	}
}
