package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	froststate "github.com/taurusgroup/frost-ed25519/pkg/state"
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
	if eddsa.ValidatePath(request.ChainPath) != nil {
		http.Error(w, "invalid FROST derivation path", http.StatusBadRequest)
		return
	}

	point, err := n.loadFROSTPublicKey(r.Context(), keyID, request.ChainPath)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not read FROST public key", http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Curve     string `json:"curve"`
			PublicKey []byte `json:"publicKey"`
		}{"ed25519", point})
	}
}

func (n *node) loadFROSTPublicKey(ctx context.Context, keyID string, path []uint32) ([]byte, error) {
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
	if len(path) != 0 {
		root := share.Public.GroupKey
		child, _, err := root.Derive(root.DefaultChainCode(), path)
		if err != nil {
			return nil, err
		}
		return child.ToEd25519(), nil
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

func (n *node) frostRoster() ([]party.ID, map[party.ID]frostparty.ID, frostparty.IDSlice) {
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
	return roster, ids, frostIDs
}

func (n *node) executeFROSTKeygen(ctx context.Context, id string, session *keygenSession) (*keygen.Output, error) {
	roster, ids, frostIDs := n.frostRoster()
	// The library's DKG messages do not contain a session ID.
	binding := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%d:%q", id, session.key.KeyID, session.key.Threshold, roster))
	state, output, err := frost.NewKeygenState(ids[n.config.PartyID], frostIDs, frostparty.Size(session.key.Threshold), 0)
	if err != nil {
		return nil, err
	}
	if err := n.runFROST(ctx, id, session, binding, state, roster, ids, nil, false); err != nil {
		return nil, err
	}
	return output, nil
}

func (n *node) runFROST(ctx context.Context, id string, session *keygenSession, binding [32]byte, state *froststate.State, roster []party.ID, ids map[party.ID]frostparty.ID, signers party.IDSlice, signing bool) error {
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
				return err
			}
			envelope := &protocol.Message{SSID: binding[:], From: n.config.PartyID, Data: payload}
			if !message.IsBroadcast() {
				envelope.To = roster[int(message.To)-1]
			}
			if err := n.sendMessage(ctx, id, envelope, signers); err != nil {
				return err
			}
		}
		if len(outgoing) > 0 {
			// Advancing a round can make previously queued messages ready to process.
			continue
		}
		select {
		case <-state.Done():
			return state.Err()
		case <-ctx.Done():
			return ctx.Err()
		case envelope := <-session.incoming:
			if !bytes.Equal(envelope.SSID, binding[:]) {
				return fmt.Errorf("FROST session parameters disagree")
			}
			message, err := decodeFROSTMessage(envelope.Data, signing)
			if err != nil {
				return err
			}
			if ids[envelope.From] != message.From || ids[envelope.To] != message.To {
				return fmt.Errorf("FROST message identity does not match envelope")
			}
			key := messageKey{message.From, message.Type}
			digest := sha256.Sum256(envelope.Data)
			if previous, exists := seen[key]; exists {
				if previous != digest {
					return fmt.Errorf("conflicting FROST message")
				}
				continue
			}
			seen[key] = digest
			if err := state.HandleMessage(message); err != nil {
				return err
			}
		}
	}
}

func decodeFROSTMessage(payload []byte, signing bool) (*messages.Message, error) {
	// The library's Message.UnmarshalBinary can return nil for invalid bodies.
	var message messages.Message
	if err := message.Header.UnmarshalBinary(payload); err != nil {
		return nil, err
	}
	body := payload[message.Header.Size():]
	if signing {
		switch message.Type {
		case messages.MessageTypeSign1:
			message.Sign1 = new(messages.Sign1)
			return &message, message.Sign1.UnmarshalBinary(body)
		case messages.MessageTypeSign2:
			message.Sign2 = new(messages.Sign2)
			return &message, message.Sign2.UnmarshalBinary(body)
		default:
			return nil, fmt.Errorf("unexpected FROST signing message type %d", message.Type)
		}
	}
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
