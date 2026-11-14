package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const frostSessionPrefix = "frost."

func (n *node) frostPublicKey(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var request struct {
		ChainPath []uint32 `json:"chainPath"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil {
		http.Error(w, "invalid public key request", http.StatusBadRequest)
		return
	}
	if len(request.ChainPath) != 0 {
		http.Error(w, "FROST public key lookup supports the root key only", http.StatusBadRequest)
		return
	}

	point, err := n.loadFROSTPublicKey(r.Context(), keyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		log.Printf("node %s: FROST public key lookup for %s: %v", n.config.PartyID, keyID, err)
		http.Error(w, "could not read FROST public key", http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Curve     string `json:"curve"`
			PublicKey []byte `json:"publicKey"`
		}{"ed25519", point})
	}
}

func (n *node) loadFROSTPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	data, err := n.keys.Load(ctx, "frost", keyID)
	if err != nil {
		return nil, err
	}
	defer clear(data)

	// Read the group key from the stored keygen output without decoding the secret share.
	var share struct {
		Public struct {
			GroupKey *eddsa.PublicKey `json:"groupkey"`
		}
	}
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, err
	}
	if share.Public.GroupKey == nil {
		return nil, errors.New("stored FROST share is missing its group key")
	}
	return share.Public.GroupKey.ToEd25519(), nil
}

func (n *node) generateFROSTKey(w http.ResponseWriter, r *http.Request) {
	n.generateKey(w, r, frostSessionPrefix, "ed25519", n.generateFROSTShare)
}

func (n *node) generateFROSTShare(ctx context.Context, id string, session *keygenSession) ([]byte, error) {
	share, err := n.executeFROSTKeygen(ctx, id, session)
	if err != nil {
		return nil, err
	}
	return json.Marshal(share)
}

func (n *node) executeFROSTKeygen(ctx context.Context, id string, session *keygenSession) (*keygen.Output, error) {
	roster := []party.ID{n.config.PartyID}
	for peer := range n.config.Peers {
		roster = append(roster, peer)
	}
	slices.Sort(roster)
	// FROST uses nonzero integer IDs. Every node maps the same sorted roster to 1..N.
	ids := make(map[party.ID]frostparty.ID, len(roster))
	frostIDs := make(frostparty.IDSlice, len(roster))
	for i, peer := range roster {
		frostIDs[i] = frostparty.ID(i + 1)
		ids[peer] = frostIDs[i]
	}
	self := ids[n.config.PartyID]
	// The library's DKG messages do not contain a session ID.
	binding := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%d:%q", id, session.key.KeyID, session.key.Threshold, roster))
	state, output, err := frost.NewKeygenState(self, frostIDs, frostparty.Size(session.key.Threshold), 0)
	if err != nil {
		return nil, err
	}
	type messageKey struct {
		from frostparty.ID
		kind messages.MessageType
	}
	seen := make(map[messageKey][32]byte)
	for {
		outgoing := state.ProcessAll()
		for _, message := range outgoing {
			payload, err := message.MarshalBinary()
			if err != nil {
				return nil, err
			}
			envelope := &protocol.Message{SSID: binding[:], From: n.config.PartyID, Data: payload}
			if !message.IsBroadcast() {
				envelope.To = roster[int(message.To)-1]
			}
			if err := n.sendMessage(ctx, id, envelope, nil); err != nil {
				return nil, err
			}
		}
		if len(outgoing) > 0 {
			// Advancing a round can make previously queued messages ready to process.
			continue
		}
		select {
		case <-state.Done():
			if err := state.Err(); err != nil {
				return nil, err
			}
			return output, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope := <-session.incoming:
			if !bytes.Equal(envelope.SSID, binding[:]) {
				return nil, fmt.Errorf("FROST session parameters disagree")
			}
			message, err := decodeFROSTKeygenMessage(envelope.Data)
			if err != nil {
				return nil, err
			}
			if ids[envelope.From] != message.From || ids[envelope.To] != message.To {
				return nil, fmt.Errorf("FROST message identity does not match envelope")
			}
			key := messageKey{message.From, message.Type}
			digest := sha256.Sum256(envelope.Data)
			if previous, exists := seen[key]; exists {
				if previous != digest {
					return nil, fmt.Errorf("conflicting FROST message")
				}
				continue
			}
			seen[key] = digest
			if err := state.HandleMessage(message); err != nil {
				return nil, err
			}
		}
	}
}

func decodeFROSTKeygenMessage(payload []byte) (*messages.Message, error) {
	// The library's Message.UnmarshalBinary can return nil for invalid bodies.
	var message messages.Message
	if err := message.Header.UnmarshalBinary(payload); err != nil {
		return nil, err
	}
	body := payload[message.Header.Size():]
	switch message.Type {
	case messages.MessageTypeKeyGen1:
		message.KeyGen1 = new(messages.KeyGen1)
		return &message, message.KeyGen1.UnmarshalBinary(body)
	case messages.MessageTypeKeyGen2:
		message.KeyGen2 = new(messages.KeyGen2)
		return &message, message.KeyGen2.UnmarshalBinary(body)
	default:
		return nil, fmt.Errorf("unexpected FROST keygen message type %d", message.Type)
	}
}
