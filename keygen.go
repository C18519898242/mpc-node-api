package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const keygenTimeout = 3 * time.Minute

var sessionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type node struct {
	config   nodeConfig
	client   *http.Client
	mu       sync.Mutex
	sessions map[string]*keygenSession
}

type keygenSession struct {
	incoming chan *protocol.Message
	status   keygenStatus
}

type keygenStatus struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	PublicKey string `json:"publicKey,omitempty"`
}

func newNode(config nodeConfig) *node {
	return &node{
		config:   config,
		client:   &http.Client{Timeout: 2 * time.Second},
		sessions: make(map[string]*keygenSession),
	}
}

func (n *node) restHandler() http.Handler {
	mux := healthMux()
	mux.HandleFunc("POST /v1/keygen", n.startKeygen)
	mux.HandleFunc("GET /v1/sessions/{sessionId}", n.getKeygen)
	return mux
}

func (n *node) startKeygen(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SessionID string `json:"sessionId"`
	}
	if decodeJSON(w, r, &request, 4096) != nil || !sessionIDPattern.MatchString(request.SessionID) {
		http.Error(w, "invalid keygen request or sessionId", http.StatusBadRequest)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.keygenStatus(request.SessionID)
	switch {
	case err == nil:
		writeStatus(w, http.StatusOK, status)
	case !errors.Is(err, os.ErrNotExist):
		log.Printf("node %s: read keygen result: %v", n.config.PartyID, err)
		http.Error(w, "could not read keygen result", http.StatusInternalServerError)
	default:
		if err := n.recordKeygenAttempt(request.SessionID); err != nil {
			log.Printf("node %s: record keygen attempt: %v", n.config.PartyID, err)
			http.Error(w, "could not record keygen attempt", http.StatusInternalServerError)
			return
		}
		session := &keygenSession{
			incoming: make(chan *protocol.Message, 32),
			status:   keygenStatus{SessionID: request.SessionID, State: "running"},
		}
		n.sessions[request.SessionID] = session
		go n.runKeygen(request.SessionID, session)
		writeStatus(w, http.StatusAccepted, session.status)
	}
}

func (n *node) getKeygen(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	if !sessionIDPattern.MatchString(id) {
		http.Error(w, "invalid sessionId", http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	status, err := n.keygenStatus(id)
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not read keygen result", http.StatusInternalServerError)
	default:
		writeStatus(w, http.StatusOK, status)
	}
}

// keygenStatus is called with n.mu held.
func (n *node) keygenStatus(id string) (keygenStatus, error) {
	if session, ok := n.sessions[id]; ok {
		return session.status, nil
	}
	data, err := os.ReadFile(n.sharePath(id))
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(n.sharePath(id) + ".started"); markerErr == nil {
			return keygenStatus{SessionID: id, State: "failed"}, nil
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return keygenStatus{}, markerErr
		}
	}
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	config := cmp.EmptyConfig(curve.Secp256k1{})
	if err := config.UnmarshalBinary(data); err != nil {
		return keygenStatus{}, err
	}
	if config.ID != n.config.PartyID {
		return keygenStatus{}, errors.New("stored share belongs to a different node")
	}
	return completedStatus(id, config)
}

func (n *node) runKeygen(id string, session *keygenSession) {
	ctx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
	defer cancel()

	status, err := n.executeKeygen(ctx, id, session.incoming)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		log.Printf("node %s: keygen %s failed: %v", n.config.PartyID, id, err)
		session.status.State = "failed"
		return
	}
	session.status = status
}

func (n *node) executeKeygen(ctx context.Context, id string, incoming <-chan *protocol.Message) (keygenStatus, error) {
	parties := []party.ID{n.config.PartyID}
	for peer := range n.config.Peers {
		parties = append(parties, peer)
	}
	// CMP's threshold is the number of shares that cannot sign. Use 2 for 3-of-3.
	start := cmp.Keygen(curve.Secp256k1{}, n.config.PartyID, parties, 2, nil)
	handler, err := protocol.NewMultiHandler(start, []byte(id))
	if err != nil {
		return keygenStatus{}, err
	}
	outgoing := handler.Listen()
	for {
		select {
		case <-ctx.Done():
			return keygenStatus{}, ctx.Err()
		case message := <-incoming:
			handler.Accept(message)
		case message, open := <-outgoing:
			if !open {
				result, err := handler.Result()
				if err != nil {
					return keygenStatus{}, err
				}
				return n.saveShare(id, result.(*cmp.Config))
			}
			if err := n.sendMessage(ctx, id, message); err != nil {
				return keygenStatus{}, err
			}
		}
	}
}

func (n *node) sharePath(id string) string {
	return filepath.Join(n.config.DataDir, "cmp-"+id+".share")
}

func (n *node) recordKeygenAttempt(id string) error {
	file, err := os.OpenFile(n.sharePath(id)+".started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return file.Close()
}

func (n *node) saveShare(id string, config *cmp.Config) (keygenStatus, error) {
	status, err := completedStatus(id, config)
	if err != nil {
		return keygenStatus{}, err
	}
	data, err := config.MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	file, err := os.CreateTemp(n.config.DataDir, ".share-*")
	if err != nil {
		return keygenStatus{}, err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return keygenStatus{}, err
	}
	return status, os.Rename(file.Name(), n.sharePath(id))
}

func completedStatus(id string, config *cmp.Config) (keygenStatus, error) {
	publicKey, err := config.PublicPoint().MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	return keygenStatus{SessionID: id, State: "succeeded", PublicKey: hex.EncodeToString(publicKey)}, nil
}

func writeStatus(w http.ResponseWriter, code int, status keygenStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(status)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any, limit int64) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return fmt.Errorf("expected a single JSON value")
	}
	return nil
}
