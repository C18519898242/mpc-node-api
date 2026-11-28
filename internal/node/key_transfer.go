package node

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type keyTransferPayload struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyID"`
	ExportID  []byte `json:"exportID"`
	Share     []byte `json:"share"`
}

type keyTransferParameters struct {
	Route         string
	KeyID         string
	SourceID      string
	Threshold     int
	Players       party.IDSlice
	Path          []uint32
	ExportID      []byte
	ImportBinding []byte `json:",omitempty"`
	// Imports reserve their key only after admission, while n.mu is held.
	reserve func() bool
}

func parseKeyTransferRoute(route string) (string, string, bool) {
	prefix, sid, ok := strings.Cut(route, ".")
	algorithm, operation, found := strings.Cut(prefix, "-")
	if algorithm == "rsa" {
		return algorithm, operation, ok && (operation == "import" || operation == "export") && memorySessionPattern.MatchString(sid)
	}
	return algorithm, operation, ok && found && (algorithm == "ecdsa" || algorithm == "frost") &&
		(operation == "export" || operation == "import" || operation == "recovery") && memorySessionPattern.MatchString(sid)
}

func (n *node) allowWrappingKey(key *rsa.PublicKey) bool {
	if n.config.KeyTransfer == nil || !n.config.KeyTransfer.ExportEnabled {
		return false
	}
	der, _ := x509.MarshalPKIXPublicKey(key)
	for _, allowed := range n.config.KeyTransfer.ExportWrappingKeys {
		if bytes.Equal(allowed, der) {
			return true
		}
	}
	return false
}

func (n *node) exportKey(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n.config.KeyTransfer == nil || !n.config.KeyTransfer.ExportEnabled {
			http.Error(w, "key export is disabled", http.StatusForbidden)
			return
		}
		keyID := r.PathValue("keyID")
		sid := r.Header.Get("MPC-SessionID")
		var request struct {
			ChainPath   []uint32 `json:"chainPath"`
			WrappingKey []byte   `json:"wrappingKey"`
		}
		if !keyIDPattern.MatchString(keyID) || keyID == "_" || !memorySessionPattern.MatchString(sid) ||
			decodeJSON(w, r, &request, 16384) != nil || eddsa.ValidatePath(request.ChainPath) != nil {
			http.Error(w, "invalid key export request", http.StatusBadRequest)
			return
		}
		wrappingKey, err := parseWrappingKey(request.WrappingKey)
		if err != nil {
			http.Error(w, "invalid RSA wrapping key", http.StatusBadRequest)
			return
		}
		if !n.allowWrappingKey(wrappingKey) {
			http.Error(w, "wrapping key is not allowed for export", http.StatusForbidden)
			return
		}
		players := n.signingPlayers(w, r, sid)
		if players == nil {
			return
		}
		release := n.lockSigningKey(w, r, algorithm, keyID)
		if release == nil {
			return
		}
		defer release()
		share, err := n.keys.Load(r.Context(), applicationID(r.Context()), algorithm, keyID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "could not load export key", http.StatusInternalServerError)
			return
		}
		defer clear(share)
		threshold, holders, _, err := n.transferShareInfo(algorithm, share)
		if err != nil {
			http.Error(w, "invalid stored export key", http.StatusInternalServerError)
			return
		}
		if len(players) <= threshold || !allPlayersIn(players, holders) {
			http.Error(w, "export players do not satisfy the key threshold", http.StatusBadRequest)
			return
		}
		params := keyTransferParameters{
			Route: algorithm + "-export." + sid, KeyID: keyID, SourceID: keyID,
			Threshold: threshold, Players: players, Path: request.ChainPath,
		}
		n.serveKeyTransfer(w, r, params, request.WrappingKey,
			func(ctx context.Context, exchange *copyExchange, session *keygenSession) ([]byte, error) {
				copyKey := n.transferECDSA
				if algorithm == "frost" {
					copyKey = n.transferFROST
				}
				candidate, exportID, err := copyKey(ctx, exchange, session, keyID, request.ChainPath, nil)
				defer clear(candidate)
				if err != nil {
					return nil, err
				}
				payload, err := json.Marshal(keyTransferPayload{1, algorithm, keyID, exportID[:], candidate})
				if err != nil {
					return nil, err
				}
				defer clear(payload)
				wrapped, err := wrapKeyShare(wrappingKey, payload)
				if err != nil {
					return nil, err
				}
				return json.Marshal(wrapped)
			})
	}
}

func (n *node) importKey(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n.wrappingKey == nil {
			http.Error(w, "key import requires a configured wrapping private key", http.StatusForbidden)
			return
		}
		sid := r.Header.Get("MPC-SessionID")
		var request struct {
			KeyID           string          `json:"keyID"`
			Threshold       int             `json:"threshold"`
			WrappedKeyShare wrappedKeyShare `json:"wrappedKeyShare"`
		}
		if !memorySessionPattern.MatchString(sid) || decodeJSON(w, r, &request, 1<<19) != nil ||
			(request.KeyID != "" && !keyIDPattern.MatchString(request.KeyID)) {
			http.Error(w, "invalid key import request", http.StatusBadRequest)
			return
		}
		players := n.signingPlayers(w, r, sid)
		if players == nil {
			return
		}
		if request.Threshold < 1 || request.Threshold >= len(players) {
			http.Error(w, "invalid import threshold", http.StatusBadRequest)
			return
		}
		data, err := unwrapKeyShare(n.wrappingKey, request.WrappedKeyShare)
		if err != nil {
			http.Error(w, "could not authenticate imported key share", http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload keyTransferPayload
		if json.Unmarshal(data, &payload) != nil || payload.Version != 1 || payload.Algorithm != algorithm ||
			len(payload.ExportID) != sha256.Size || !keyIDPattern.MatchString(payload.KeyID) {
			http.Error(w, "invalid imported key payload", http.StatusBadRequest)
			return
		}
		defer clear(payload.Share)
		threshold, holders, identity, err := n.transferShareInfo(algorithm, payload.Share)
		if err != nil || len(players) <= threshold || !allPlayersIn(players, holders) {
			http.Error(w, "imported share does not match this node or player group", http.StatusBadRequest)
			return
		}
		if request.KeyID == "" {
			digest := sha256.Sum256([]byte(algorithm + "-import." + sid))
			request.KeyID = base64.RawURLEncoding.EncodeToString(digest[:21])
		}
		release := n.lockKeyOperation(w, applicationID(r.Context()), algorithm, request.KeyID, true)
		if release == nil {
			return
		}
		defer release()
		key := keystore.Key{Algorithm: algorithm, SessionID: "import." + sid, KeyID: request.KeyID, Threshold: request.Threshold}
		params := keyTransferParameters{
			Route: algorithm + "-import." + sid, KeyID: key.KeyID, SourceID: payload.KeyID,
			Threshold: key.Threshold, Players: players, ExportID: payload.ExportID,
		}
		params.reserve = func() bool {
			reserved, err := n.keys.Reserve(r.Context(), applicationID(r.Context()), key)
			if err != nil {
				http.Error(w, "could not reserve imported key", http.StatusInternalServerError)
				return false
			}
			if reserved == keystore.Conflict {
				http.Error(w, "import session or key ID already used", http.StatusConflict)
				return false
			}
			if reserved == keystore.Completed {
				saved, err := n.keys.Load(r.Context(), applicationID(r.Context()), algorithm, key.KeyID)
				defer clear(saved)
				if err != nil {
					http.Error(w, "could not load completed import", http.StatusInternalServerError)
					return false
				}
				t, roster, previous, err := n.transferShareInfo(algorithm, saved)
				if err != nil || t != key.Threshold || !slices.Equal(roster, players) || !bytes.Equal(identity, previous) {
					http.Error(w, "completed import does not match the request", http.StatusConflict)
					return false
				}
				writeImportedKey(w, key.KeyID)
				return false
			}
			return true
		}
		n.serveKeyTransfer(w, r, params, nil,
			func(ctx context.Context, exchange *copyExchange, session *keygenSession) ([]byte, error) {
				copyKey := n.transferECDSA
				if algorithm == "frost" {
					copyKey = n.transferFROST
				}
				candidate, _, err := copyKey(ctx, exchange, session, payload.KeyID, nil, payload.Share)
				defer clear(candidate)
				if err != nil {
					return nil, err
				}
				if err := n.keys.Save(ctx, applicationID(ctx), key, candidate); err != nil {
					return nil, err
				}
				return json.Marshal(generateKeyResponse{KeyID: key.KeyID})
			})
	}
}

func writeImportedKey(w http.ResponseWriter, keyID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(generateKeyResponse{KeyID: keyID})
}

func allPlayersIn(selected, roster party.IDSlice) bool {
	for _, player := range selected {
		if !roster.Contains(player) {
			return false
		}
	}
	return true
}

// transferShareInfo validates node ownership before exporting or importing.
func (n *node) transferShareInfo(algorithm string, data []byte) (threshold int, players party.IDSlice, identity []byte, err error) {
	// Native library decoders can panic on malformed nested public data.
	defer func() {
		if recover() != nil {
			threshold, players, identity, err = 0, nil, nil, errors.New("invalid serialized key share")
		}
	}()
	if algorithm == "ecdsa" {
		key, err := n.decodeCMPShare(data)
		if err != nil {
			return 0, nil, nil, err
		}
		defer key.ECDSA.Set(key.Group.NewScalar())
		root, err := key.PublicPoint().MarshalBinary()
		if err != nil || len(key.ChainKey) != 32 {
			return 0, nil, nil, errors.New("invalid ECDSA share metadata")
		}
		return key.Threshold, key.PartyIDs(), append(root, key.ChainKey...), nil
	}
	key, err := n.decodeFROSTSigningShare(data)
	if err != nil {
		return 0, nil, nil, err
	}
	defer key.SecretKey.Secret.Set(ristretto.NewScalar())
	code := key.chainCode()
	return int(key.Public.Threshold), key.Players, append(key.Public.GroupKey.ToEd25519(), code[:]...), nil
}

type keyTransferOperation func(context.Context, *copyExchange, *keygenSession) ([]byte, error)

func (n *node) serveKeyTransfer(w http.ResponseWriter, r *http.Request, params keyTransferParameters, localBinding []byte, run keyTransferOperation) {
	parameters, _ := json.Marshal(params)
	binding := sha256.Sum256(applicationBinding(applicationID(r.Context()), parameters))
	localHash := sha256.Sum256(append(binding[:32:32], localBinding...))
	lookup := sessionKey{applicationID(r.Context()), params.Route}
	n.mu.Lock()
	n.pruneSessionsLocked(time.Now())
	session := n.sessions[lookup]
	if session != nil && session.signBinding != localHash {
		n.mu.Unlock()
		http.Error(w, "key transfer session already used with different parameters", http.StatusConflict)
		return
	}
	if session == nil && n.checkSessionCapacityLocked(lookup.applicationID) != nil {
		n.mu.Unlock()
		http.Error(w, "too many concurrent MPC sessions", http.StatusServiceUnavailable)
		return
	}
	if params.reserve != nil && !params.reserve() {
		n.mu.Unlock()
		return
	}
	if session == nil {
		algorithm, _, _ := parseKeyTransferRoute(params.Route)
		session = &keygenSession{
			key:     keystore.Key{Algorithm: algorithm, KeyID: params.KeyID, Threshold: params.Threshold},
			players: params.Players, incoming: make(chan *protocol.Message, 32),
			copyIncoming: make(chan *protocol.Message, 3*len(params.Players)),
			signBinding:  localHash, done: make(chan struct{}), status: keygenStatus{State: "running"},
		}
		n.sessions[lookup] = session
		go n.runKeyTransfer(context.WithoutCancel(r.Context()), lookup, session, binding, run)
	}
	n.mu.Unlock()
	// Keep the source key and import payload alive until the detached worker exits.
	<-session.done
	if session.status.State != "succeeded" {
		http.Error(w, "key transfer failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(session.signature)
}

func (n *node) runKeyTransfer(ctx context.Context, lookup sessionKey, session *keygenSession, binding [32]byte, run keyTransferOperation) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, keygenTimeout)
	defer cancel()
	exchange := &copyExchange{
		node: n, route: lookup.sessionID, binding: binding, players: session.players, incoming: session.copyIncoming,
		received: map[string]map[party.ID][]byte{copySourceRound: {}, copyCommitRound: {}, copyShareRound: {}},
	}
	result, err := run(ctx, exchange, session)
	algorithm, operation, _ := parseKeyTransferRoute(lookup.sessionID)
	n.logMPCResult(operation, algorithm, "protocol", start, err)
	n.mu.Lock()
	session.signature, session.status.State = result, "succeeded"
	if err != nil {
		session.status.State = "failed"
	}
	n.finishSessionLocked(session)
	close(session.done)
	n.mu.Unlock()
}
