package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	rsaSessionPrefix = "rsa."
	rsaReadyMessage  = "rsa-keygen/ready"
	rsaShareMessage  = "rsa-keygen/share"
	rsaKeygenTimeout = 15 * time.Minute
	rsaUsageSign     = "sign"
	rsaUsageDecrypt  = "decrypt"
)

type rsaKeygenParams struct {
	bits  int
	usage string
}

type storedRSAKeyShare struct {
	Players            party.IDSlice `json:"players"`
	PublicKey          []byte        `json:"publicKey"`
	Share              []byte        `json:"share,omitempty"`
	Usage              string        `json:"usage,omitempty"`
	DecryptionKeyShare []byte        `json:"decryptionKeyShare,omitempty"`
}

func rsaKeyUsage(usage string) string {
	switch usage {
	case "", rsaUsageSign:
		return rsaUsageSign
	case rsaUsageDecrypt:
		return rsaUsageDecrypt
	default:
		return ""
	}
}

func (n *node) rsaEnabled() bool {
	return n.config.MPCTLS != nil && n.shareCipher != nil
}

func (n *node) generateRSAKey(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() {
		http.Error(w, "RSA keygen requires MPC mTLS and encrypted storage", http.StatusForbidden)
		return
	}
	sid := r.Header.Get("MPC-SessionID")
	if !memorySessionPattern.MatchString(sid) {
		http.Error(w, "invalid MPC-SessionID", http.StatusBadRequest)
		return
	}
	players := n.signingPlayers(w, r, sid)
	if players == nil {
		return
	}
	for _, player := range players {
		if player != n.config.PartyID && n.config.Peers[player] == "" {
			http.Error(w, "RSA keygen requires static MPC peers", http.StatusBadRequest)
			return
		}
	}
	var request struct {
		Bits      int    `json:"bits"`
		Threshold int    `json:"threshold"`
		KeyID     string `json:"keyID"`
		Usage     string `json:"usage"`
	}
	if decodeJSON(w, r, &request, 4096) != nil || (request.Bits != 2048 && request.Bits != 3072 && request.Bits != 4096) ||
		request.Threshold < 1 || request.Threshold >= len(players) || (request.KeyID != "" && !keyIDPattern.MatchString(request.KeyID)) {
		http.Error(w, "invalid RSA keygen parameters", http.StatusBadRequest)
		return
	}
	usage := rsaKeyUsage(request.Usage)
	if usage == "" {
		http.Error(w, "invalid RSA key usage", http.StatusBadRequest)
		return
	}
	if usage == rsaUsageDecrypt && !rsaDecryptionAllowed(r) {
		http.Error(w, "RSA decryption requires an authorized API key and HTTPS", http.StatusForbidden)
		return
	}
	key := keystore.Key{Algorithm: "rsa", SessionID: sid, KeyID: request.KeyID, Threshold: request.Threshold}
	// Safe-prime generation can take longer than an elliptic-curve keygen session.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(rsaKeygenTimeout + 5*time.Second))
	n.serveStoredKeygen(w, r, key, "RSA", players, rsaKeygenParams{bits: request.Bits, usage: usage}, n.generateRSAKeyShare)
}

func (n *node) generateRSAKeyShare(ctx context.Context, route string, session *keygenSession) ([]byte, error) {
	self, dealer := n.config.PartyID, session.players[0]
	transcript := fmt.Appendf(nil, "%s:%s:%d:%d:%q", route, session.key.KeyID, session.key.Threshold, session.rsaParams.bits, session.players)
	// Keep the original signing transcript so existing signing nodes can participate.
	if session.rsaParams.usage == rsaUsageDecrypt {
		transcript = append(transcript, ":decrypt"...)
	}
	binding := sha256.Sum256(applicationBinding(applicationID(ctx), transcript))
	if self != dealer {
		ready := &protocol.Message{SSID: binding[:], From: self, To: dealer, Protocol: rsaReadyMessage}
		if err := n.sendMessage(ctx, route, ready, session.players); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case message := <-session.incoming:
			if message.From == dealer && message.To == self && message.Protocol == rsaShareMessage && bytes.Equal(message.SSID, binding[:]) &&
				validRSAKeyShare(message.Data, self, session.players, session.key.Threshold, session.rsaParams) {
				return message.Data, nil
			}
			clear(message.Data)
			return nil, errors.New("invalid share from RSA dealer")
		}
	}

	// Wait for the full roster to agree on the request before creating a key.
	ready := make(map[party.ID]bool, len(session.players)-1)
	for len(ready) < len(session.players)-1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case message := <-session.incoming:
			if message.To != self || message.Protocol != rsaReadyMessage || !bytes.Equal(message.SSID, binding[:]) || len(message.Data) != 0 {
				clear(message.Data)
				return nil, errors.New("RSA keygen participants disagree on the request")
			}
			ready[message.From] = true
		}
	}
	return n.dealRSAKey(ctx, route, session, binding)
}

func (n *node) dealRSAKey(ctx context.Context, route string, session *keygenSession, binding [32]byte) ([]byte, error) {
	random := rsaKeygenRandom{ctx}
	private, err := thresholdrsa.GenerateKey(random, session.rsaParams.bits)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	shares, err := thresholdrsa.Deal(random, uint(len(session.players)), uint(session.key.Threshold+1), private, false)
	if err != nil {
		return nil, err
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, err
	}
	encode := func(share *thresholdrsa.KeyShare) ([]byte, error) {
		data, err := share.MarshalBinary()
		if err != nil {
			return nil, err
		}
		defer clear(data)
		stored := storedRSAKeyShare{Players: session.players, PublicKey: public, Usage: session.rsaParams.usage}
		// Older binaries only load share, so they cannot use decryption keys for signing.
		if stored.Usage == rsaUsageDecrypt {
			stored.DecryptionKeyShare = data
		} else {
			stored.Share = data
		}
		return json.Marshal(stored)
	}
	for i, peer := range session.players[1:] {
		payload, err := encode(&shares[i+1])
		if err != nil {
			return nil, err
		}
		message := &protocol.Message{SSID: binding[:], From: n.config.PartyID, To: peer, Protocol: rsaShareMessage, Data: payload}
		err = n.sendMessage(ctx, route, message, session.players)
		clear(payload)
		if err != nil {
			return nil, err
		}
	}
	return encode(&shares[0])
}

func validRSAKeyShare(data []byte, self party.ID, players party.IDSlice, threshold int, params rsaKeygenParams) bool {
	key, err := decodeStoredRSAKeyShare(data, self)
	return err == nil && key.usage == params.usage && slices.Equal(key.players, players) &&
		key.publicKey.N.BitLen() == params.bits && key.share.Threshold == uint(threshold+1)
}

type rsaKeyData struct {
	players   party.IDSlice
	publicDER []byte
	publicKey *rsa.PublicKey
	share     thresholdrsa.KeyShare
	usage     string
}

func decodeStoredRSAKeyShare(data []byte, self party.ID) (*rsaKeyData, error) {
	var stored storedRSAKeyShare
	err := json.Unmarshal(data, &stored)
	defer clear(stored.Share)
	defer clear(stored.DecryptionKeyShare)
	if err != nil {
		return nil, errors.New("invalid RSA key share record")
	}
	usage := rsaKeyUsage(stored.Usage)
	if usage == "" {
		return nil, errors.New("invalid stored RSA key usage")
	}
	encodedShare := stored.Share
	if usage == rsaUsageDecrypt {
		if len(stored.Share) != 0 {
			return nil, errors.New("invalid stored RSA decryption share")
		}
		encodedShare = stored.DecryptionKeyShare
	} else if len(stored.DecryptionKeyShare) != 0 {
		return nil, errors.New("invalid stored RSA signing share")
	}
	public, err := x509.ParsePKIXPublicKey(stored.PublicKey)
	key, ok := public.(*rsa.PublicKey)
	if err != nil || !ok || key.N.Bit(0) != 1 || key.E != 65537 {
		return nil, errors.New("invalid stored RSA public key")
	}
	switch key.N.BitLen() {
	case 2048, 3072, 4096:
	default:
		return nil, errors.New("invalid stored RSA key size")
	}
	var share thresholdrsa.KeyShare
	index := slices.Index(stored.Players, self)
	if index < 0 || share.UnmarshalBinary(encodedShare) != nil || share.Index != uint(index+1) ||
		share.Players != uint(len(stored.Players)) || share.Threshold < 2 || share.Threshold > share.Players {
		return nil, errors.New("invalid stored RSA share metadata")
	}
	return &rsaKeyData{players: stored.Players, publicDER: stored.PublicKey, publicKey: key, share: share, usage: usage}, nil
}

// CIRCL's safe-prime search reads randomness for each candidate.
type rsaKeygenRandom struct{ ctx context.Context }

func (r rsaKeygenRandom) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return rand.Reader.Read(data)
}
