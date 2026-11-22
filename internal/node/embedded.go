package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Embedded owns an outbound-only node. Operations are serialized so one mobile
// session can be canceled and drained before another borrows its decrypted MK.
type Embedded struct {
	mu          sync.Mutex
	node        *node
	store       *keystore.SQLite
	masterKey   []byte
	application string
	credentials map[party.ID]string
	ctx         context.Context
	cancel      context.CancelFunc
	closed      bool
}

func NewEmbedded(cfg config.Config, app, password string, credentials map[party.ID]string) (*Embedded, error) {
	if err := config.ValidateEmbedded(cfg); err != nil {
		return nil, err
	}
	if !applicationIDPattern.MatchString(app) || password == "" || len(credentials) != len(cfg.Peers) {
		return nil, errors.New("embedded node requires an application, master password and peer credentials")
	}
	for peer := range cfg.Peers {
		if credentials[peer] == "" {
			return nil, errors.New("missing backend credential")
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}
	n := newNode(cfg)
	n.embedded = true
	if _, err := n.configurePeerTLS(); err != nil {
		return nil, err
	}
	db, err := keystore.OpenNodeSQLite(cfg.DataDir, string(cfg.PartyID))
	if err != nil {
		closeEmbeddedClients(n)
		return nil, err
	}
	mk, err := db.LoadOrCreateMasterKey(context.Background(), password)
	if err != nil {
		db.Close()
		closeEmbeddedClients(n)
		return nil, err
	}
	n.shareCipher = keystore.NewShareCipher(mk, string(cfg.PartyID))
	if err := db.EnableShareEncryption(context.Background(), n.shareCipher); err != nil {
		db.Close()
		clear(mk)
		closeEmbeddedClients(n)
		return nil, err
	}
	n.keys = db
	ctx, cancel := context.WithCancel(context.Background())
	keys := make(map[party.ID]string, len(credentials))
	for id, key := range credentials {
		keys[id] = key
	}
	return &Embedded{node: n, store: db, masterKey: mk, application: app, credentials: keys, ctx: ctx, cancel: cancel}, nil
}

func closeEmbeddedClients(n *node) {
	for _, c := range n.peerClients {
		c.CloseIdleConnections()
	}
}

func (e *Embedded) Close() error {
	e.cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	closeEmbeddedClients(e.node)
	err := e.store.Close()
	clear(e.masterKey)
	clear(e.credentials)
	return err
}

type mobileKeyResult struct {
	KeyID          string `json:"keyID"`
	PresignatureID string `json:"presignatureId,omitempty"`
	Curve          string `json:"curve"`
	PublicKey      []byte `json:"publicKey"`
	Signature      []byte `json:"signature,omitempty"`
}

func (e *Embedded) CreateKey(algorithm string, threshold int, keyID string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	curve, err := mobileCurve(algorithm)
	if err != nil {
		return "", err
	}
	if e.closed || e.ctx.Err() != nil {
		return "", errors.New("mobile node is closed")
	}
	if threshold < 1 || threshold >= len(e.node.configuredPlayers()) || (keyID != "" && !keyIDPattern.MatchString(keyID)) {
		return "", errors.New("invalid mobile key parameters")
	}
	body, _ := json.Marshal(generateKeyRequest{Threshold: threshold, Curve: curve, KeyID: keyID})
	sid := newMobileSession()
	response, err := e.coordinate("/"+algorithm+"/keys", algorithm+"."+sid, sid, body)
	if err != nil {
		return "", err
	}
	var created generateKeyResponse
	if json.Unmarshal(response, &created) != nil || !keyIDPattern.MatchString(created.KeyID) {
		return "", errors.New("invalid mobile key response")
	}
	public, err := e.publicKey(algorithm, created.KeyID, nil)
	if err != nil {
		return "", err
	}
	result, _ := json.Marshal(mobileKeyResult{KeyID: created.KeyID, Curve: curve, PublicKey: public})
	return string(result), nil
}

// Sign signs the original message. ECDSA uses SHA256(message); FROST signs the
// original bytes. An omitted path signs the root key.
func (e *Embedded) Sign(algorithm, keyID string, message []byte) (string, error) {
	return e.SignWithPath(algorithm, keyID, message, nil)
}

func (e *Embedded) SignWithPath(algorithm, keyID string, message []byte, chainPath []uint32) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	curve, err := mobileCurve(algorithm)
	if err != nil {
		return "", err
	}
	if e.closed || e.ctx.Err() != nil {
		return "", errors.New("mobile node is closed")
	}
	if !keyIDPattern.MatchString(keyID) || len(message) > 2048 {
		return "", errors.New("invalid mobile signing parameters")
	}
	public, err := e.publicKey(algorithm, keyID, chainPath)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{"message": append([]byte{}, message...), "chainPath": chainPath})
	digest := sha256.Sum256(message)
	if algorithm == "ecdsa" {
		body, _ = json.Marshal(ecdsaSignRequest{MessageHash: digest[:], ChainPath: chainPath})
	}
	sid := newMobileSession()
	response, err := e.coordinate("/"+algorithm+"/keys/"+keyID+"/sign", algorithm+"-sign."+sid, sid, body)
	if err != nil {
		return "", err
	}
	var signed struct{ Signature []byte }
	if json.Unmarshal(response, &signed) != nil {
		return "", errors.New("invalid mobile signature response")
	}
	if algorithm == "frost" {
		if !ed25519.Verify(public, message, signed.Signature) {
			return "", errors.New("mobile signature did not verify")
		}
	} else {
		point, err := secp256k1.ParsePubKey(public)
		if err != nil {
			return "", err
		}
		signature, err := secpECDSA.ParseDERSignature(signed.Signature)
		if err != nil || !signature.Verify(digest[:], point) {
			return "", errors.New("mobile signature did not verify")
		}
	}
	result, _ := json.Marshal(mobileKeyResult{KeyID: keyID, Curve: curve, PublicKey: public, Signature: signed.Signature})
	return string(result), nil
}

func (e *Embedded) publicKey(algorithm, keyID string, chainPath []uint32) ([]byte, error) {
	body, _ := json.Marshal(struct {
		ChainPath []uint32 `json:"chainPath"`
	}{chainPath})
	data, err := e.localCall(e.ctx, "/"+algorithm+"/keys/"+keyID+"/publickey", "", body)
	if err != nil {
		return nil, err
	}
	var result struct{ PublicKey []byte }
	if json.Unmarshal(data, &result) != nil || len(result.PublicKey) == 0 {
		return nil, errors.New("invalid stored mobile public key")
	}
	return result.PublicKey, nil
}

func mobileCurve(algorithm string) (string, error) {
	switch algorithm {
	case "ecdsa":
		return "secp256k1", nil
	case "frost":
		return "ed25519", nil
	}
	return "", errors.New("mobile algorithm must be ecdsa or frost")
}

func newMobileSession() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type embeddedResponse struct {
	body    bytes.Buffer
	headers http.Header
	code    int
}

func newEmbeddedResponse() *embeddedResponse    { return &embeddedResponse{headers: make(http.Header)} }
func (r *embeddedResponse) Header() http.Header { return r.headers }
func (r *embeddedResponse) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}
func (r *embeddedResponse) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.body.Write(b)
}

func (e *Embedded) localCall(ctx context.Context, path, sid string, body []byte) ([]byte, error) {
	r, err := http.NewRequestWithContext(ctx, "POST", "http://embedded"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	e.setSessionHeaders(r, sid)
	w := newEmbeddedResponse()
	e.node.restHandler().ServeHTTP(w, withApplication(r, e.application))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if w.code != 200 {
		return nil, fmt.Errorf("local mobile operation failed (HTTP %d)", w.code)
	}
	return w.body.Bytes(), nil
}
