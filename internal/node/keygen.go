package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const keygenTimeout = 3 * time.Minute

type sessionKey struct {
	applicationID string
	sessionID     string
}

type keygenSession struct {
	incoming       chan *protocol.Message
	copyIncoming   chan *protocol.Message
	copySourceID   string
	copyDigest     *[32]byte
	status         keygenStatus
	done           chan struct{}
	key            keystore.Key
	signBinding    [32]byte
	signature      []byte
	presignInboxes []chan *protocol.Message
	presignIDs     []string
	players        party.IDSlice
}

type keygenStatus struct {
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	PublicKey string `json:"publicKey,omitempty"`
}

func (n *node) beginKeygen(ctx context.Context, id string) (status keygenStatus, started bool, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	status, err = n.lookupKeygen(ctx, id)
	if err == nil {
		return status, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return keygenStatus{}, false, err
	}
	if err := n.recordKeygenAttempt(applicationID(ctx), id); err != nil {
		return keygenStatus{}, false, fmt.Errorf("%w: %w", errRecordKeygenAttempt, err)
	}
	session := &keygenSession{
		incoming: make(chan *protocol.Message, 32),
		status:   keygenStatus{SessionID: id, State: "running"},
	}
	n.sessions[sessionKey{applicationID(ctx), id}] = session
	go n.runKeygen(context.WithoutCancel(ctx), id, session)
	return session.status, true, nil
}

var errRecordKeygenAttempt = errors.New("record keygen attempt")

func (n *node) getKeygenStatus(ctx context.Context, id string) (keygenStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lookupKeygen(ctx, id)
}

// lookupKeygen requires n.mu to be held.
func (n *node) lookupKeygen(ctx context.Context, id string) (keygenStatus, error) {
	if session, ok := n.sessions[sessionKey{applicationID(ctx), id}]; ok {
		return session.status, nil
	}
	return n.loadKeygenStatus(applicationID(ctx), id)
}

func (n *node) runKeygen(ctx context.Context, id string, session *keygenSession) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, keygenTimeout)
	defer cancel()

	share, err := n.executeKeygen(ctx, id, []byte(id), 2, n.configuredPlayers(), session.incoming)
	var status keygenStatus
	stage := "protocol"
	if err == nil {
		stage = "storage"
		status, err = n.saveShare(applicationID(ctx), id, share)
	}
	n.logMPCResult("keygen", "ecdsa", stage, start, err)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		session.status.State = "failed"
		return
	}
	session.status = status
}

func (n *node) configuredPlayers() party.IDSlice {
	parties := []party.ID{n.config.PartyID}
	for peer := range n.config.Peers {
		parties = append(parties, peer)
	}
	for peer := range n.config.MobilePeers {
		parties = append(parties, peer)
	}
	return party.NewIDSlice(parties)
}

func (n *node) executeKeygen(ctx context.Context, id string, protocolID []byte, threshold int, parties party.IDSlice, incoming <-chan *protocol.Message) (*cmp.Config, error) {
	start := cmp.Keygen(curve.Secp256k1{}, n.config.PartyID, parties, threshold, nil)
	result, err := n.runCMP(ctx, id, protocolID, start, incoming, parties)
	if err != nil {
		return nil, err
	}
	return result.(*cmp.Config), nil
}

func (n *node) runCMP(ctx context.Context, id string, protocolID []byte, start protocol.StartFunc, incoming <-chan *protocol.Message, participants party.IDSlice) (any, error) {
	handler, err := protocol.NewMultiHandler(start, applicationBinding(applicationID(ctx), protocolID))
	if err != nil {
		return nil, err
	}
	outgoing := handler.Listen()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case message := <-incoming:
			handler.Accept(message)
		case message, open := <-outgoing:
			if !open {
				return handler.Result()
			}
			if err := n.sendMessage(ctx, id, message, participants); err != nil {
				return nil, err
			}
		}
	}
}
