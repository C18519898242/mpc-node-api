package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	rsaPSSSignPrefix   = "rsa-pss-sign."
	rsaPSSReadyMessage = "rsa-pss/ready"
	rsaPSSSaltMessage  = "rsa-pss/salt"
	rsaPSSAbortMessage = "rsa-pss/abort"
	rsaPSSFormat       = "circl-rsa-pss-sha256-v1"
	rsaPSSHashSHA256   = "SHA256"
)

type rsaPSSEnvelope struct {
	Format       string        `json:"format"`
	SessionID    string        `json:"sessionID"`
	KeyID        string        `json:"keyID"`
	HashFunction string        `json:"hash"`
	PublicKey    []byte        `json:"publicKey"`
	Players      uint          `json:"players"`
	Threshold    uint          `json:"threshold"`
	PlayerIndex  uint          `json:"playerIndex"`
	Signers      party.IDSlice `json:"signers"`
	Digest       []byte        `json:"digest"`
	Salt         []byte        `json:"salt"`
	Share        []byte        `json:"share"`
}

func (n *node) signRSAPSS(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() || !n.authenticatedRESTTLS(r) {
		http.Error(w, "RSA-PSS signing requires MPC mTLS, encrypted storage, an API key and HTTPS", http.StatusForbidden)
		return
	}
	keyID := r.PathValue("keyID")
	sessionID := r.Header.Get("MPC-SessionID")
	var request struct {
		Hash        string `json:"hash"`
		MessageHash []byte `json:"messageHash"`
	}
	if !keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sessionID) ||
		decodeJSON(w, r, &request, 4096) != nil || request.Hash != rsaPSSHashSHA256 || len(request.MessageHash) != sha256.Size {
		http.Error(w, "invalid RSA-PSS signing request", http.StatusBadRequest)
		return
	}
	signers := n.signingPlayers(w, r, sessionID)
	if signers == nil {
		return
	}
	for _, player := range signers {
		if player != n.config.PartyID && n.config.Peers[player] == "" {
			http.Error(w, "RSA-PSS signing requires static MPC peers", http.StatusBadRequest)
			return
		}
	}
	release := n.lockKeyOperation(w, applicationID(r.Context()), "rsa", keyID, false)
	if release == nil {
		return
	}
	defer release()

	data := n.readRSAKey(w, r, keyID)
	if data == nil {
		return
	}
	if data.usage != rsaUsageSign {
		http.Error(w, "RSA key does not permit signing", http.StatusForbidden)
		return
	}
	if uint(len(signers)) < data.share.Threshold {
		http.Error(w, "signing players do not satisfy the key threshold", http.StatusBadRequest)
		return
	}
	for _, player := range signers {
		if !data.players.Contains(player) {
			http.Error(w, "signing players do not match key holders", http.StatusBadRequest)
			return
		}
	}

	id := rsaPSSSignPrefix + sessionID
	bindingMessage := append([]byte(request.Hash+"\x00"), request.MessageHash...)
	n.serveSignature(w, r, id, keyID, signers, nil, bindingMessage, "RSA-PSS", "partial",
		func(ctx context.Context, session *keygenSession, _ bool) ([]byte, error) {
			salt, err := n.exchangeRSAPSSSalt(ctx, id, session, sessionID, keyID, request.Hash, request.MessageHash, signers, data.publicDER)
			if err != nil {
				return nil, err
			}
			padder := &thresholdrsa.PSSPadder{
				Rand: bytes.NewReader(salt),
				Opts: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
			}
			padded, err := padder.Pad(data.publicKey, crypto.SHA256, request.MessageHash)
			if err != nil {
				return nil, err
			}
			part, err := data.share.Sign(rand.Reader, data.publicKey, padded, false)
			if err != nil {
				return nil, err
			}
			encoded, err := part.MarshalBinary()
			if err != nil {
				return nil, err
			}
			defer clear(encoded)
			envelope, err := json.Marshal(rsaPSSEnvelope{
				Format:       rsaPSSFormat,
				SessionID:    sessionID,
				KeyID:        keyID,
				HashFunction: request.Hash,
				PublicKey:    data.publicDER,
				Players:      data.share.Players,
				Threshold:    data.share.Threshold,
				PlayerIndex:  data.share.Index,
				Signers:      signers,
				Digest:       request.MessageHash,
				Salt:         salt,
				Share:        encoded,
			})
			if err != nil {
				return nil, err
			}
			defer clear(envelope)
			return json.Marshal(struct {
				PartialSignature []byte `json:"partialSignature"`
			}{envelope})
		})
}

func (n *node) exchangeRSAPSSSalt(ctx context.Context, route string, session *keygenSession, sessionID, keyID, hashName string, digest []byte, signers party.IDSlice, publicDER []byte) ([]byte, error) {
	transcript, err := json.Marshal(struct {
		SessionID    string
		KeyID        string
		Hash         string
		Digest       []byte
		Signers      party.IDSlice
		PublicKeyDER []byte
	}{sessionID, keyID, hashName, digest, signers, publicDER})
	if err != nil {
		return nil, err
	}
	ssid := sha256.Sum256(applicationBinding(applicationID(ctx), transcript))
	self, dealer := n.config.PartyID, signers[0]
	if self != dealer {
		ready := &protocol.Message{SSID: ssid[:], From: self, To: dealer, Protocol: rsaPSSReadyMessage}
		if err := n.sendMessage(ctx, route, ready, signers); err != nil {
			return nil, err
		}
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case message := <-session.incoming:
				if message.From != dealer || message.To != self || !bytes.Equal(message.SSID, ssid[:]) {
					clear(message.Data)
					return nil, errors.New("invalid salt from RSA-PSS coordinator")
				}
				if message.Protocol == rsaPSSAbortMessage {
					clear(message.Data)
					return nil, errors.New("RSA-PSS signing participants disagree on the request")
				}
				if message.Protocol != rsaPSSSaltMessage || len(message.Data) != sha256.Size {
					clear(message.Data)
					return nil, errors.New("invalid salt from RSA-PSS coordinator")
				}
				return bytes.Clone(message.Data), nil
			}
		}
	}

	ready := make(map[party.ID]bool, len(signers)-1)
	seenSSIDs := make(map[party.ID][]byte, len(signers)-1)
	failAndAbort := func(extra *protocol.Message) {
		if extra != nil && signers.Contains(extra.From) && extra.From != self && len(extra.SSID) == sha256.Size {
			if _, exists := seenSSIDs[extra.From]; !exists {
				seenSSIDs[extra.From] = bytes.Clone(extra.SSID)
			}
		}
		n.abortRSAPSSSession(ctx, route, session, self, signers, seenSSIDs)
	}
	for len(ready) < len(signers)-1 {
		select {
		case <-ctx.Done():
			failAndAbort(nil)
			return nil, ctx.Err()
		case message := <-session.incoming:
			if message.To != self || message.Protocol != rsaPSSReadyMessage || !bytes.Equal(message.SSID, ssid[:]) ||
				len(message.Data) != 0 || !signers.Contains(message.From) || message.From == self {
				clear(message.Data)
				failAndAbort(message)
				return nil, errors.New("RSA-PSS signing participants disagree on the request")
			}
			// Idempotent ready retries from an already-ready peer must not abort the session.
			if ready[message.From] {
				continue
			}
			ready[message.From] = true
			seenSSIDs[message.From] = ssid[:]
		}
	}

	salt := make([]byte, sha256.Size)
	if _, err := rand.Read(salt); err != nil {
		failAndAbort(nil)
		return nil, err
	}
	for _, peer := range signers[1:] {
		message := &protocol.Message{SSID: ssid[:], From: self, To: peer, Protocol: rsaPSSSaltMessage, Data: salt}
		if err := n.sendMessage(ctx, route, message, signers); err != nil {
			clear(salt)
			failAndAbort(nil)
			return nil, err
		}
		delete(seenSSIDs, peer)
	}
	return salt, nil
}

func (n *node) abortRSAPSSSession(ctx context.Context, route string, session *keygenSession, self party.ID, signers party.IDSlice, seenSSIDs map[party.ID][]byte) {
	n.mu.Lock()
	session.status.State = "failed"
	for draining := true; draining; {
		select {
		case message := <-session.incoming:
			if signers.Contains(message.From) && message.From != self && len(message.SSID) == sha256.Size {
				if _, exists := seenSSIDs[message.From]; !exists {
					seenSSIDs[message.From] = bytes.Clone(message.SSID)
				}
			}
			clear(message.Data)
		default:
			draining = false
		}
	}
	n.mu.Unlock()
	if len(seenSSIDs) == 0 {
		return
	}
	abortCtx, cancel := context.WithTimeout(n.operationContext(ctx), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for peer, peerSSID := range seenSSIDs {
		wg.Add(1)
		go func(peer party.ID, peerSSID []byte) {
			defer wg.Done()
			_ = n.sendMessage(abortCtx, route, &protocol.Message{
				SSID: peerSSID, From: self, To: peer, Protocol: rsaPSSAbortMessage,
			}, signers)
		}(peer, peerSSID)
	}
	wg.Wait()
}
