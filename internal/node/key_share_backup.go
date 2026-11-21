package node

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

const localKeyShareKind = "local-key-share"

type localKeySharePayload struct {
	Version       int                     `json:"version"`
	Kind          string                  `json:"kind"`
	PartyID       string                  `json:"partyID"`
	ApplicationID string                  `json:"applicationID"`
	Backup        keystore.KeyShareBackup `json:"backup"`
}

func (n *node) exportLocalKeyShare(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keyID := r.PathValue("keyID")
		var request struct {
			WrappingKey []byte `json:"wrappingKey"`
		}
		if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 16384) != nil {
			http.Error(w, "invalid local share export request", http.StatusBadRequest)
			return
		}
		key, err := parseWrappingKey(request.WrappingKey)
		if err != nil {
			http.Error(w, "invalid RSA wrapping key", http.StatusBadRequest)
			return
		}
		if !n.allowWrappingKey(key) {
			http.Error(w, "wrapping key is not allowed for export", http.StatusForbidden)
			return
		}
		appID := applicationID(r.Context())
		release := n.lockSigningKey(w, r, algorithm, keyID)
		if release == nil {
			return
		}
		defer release()
		backup, err := n.keys.ExportKeyShare(r.Context(), appID, algorithm, keyID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "could not read local key share", http.StatusInternalServerError)
			return
		}
		defer clear(backup.Share)
		payload, err := json.Marshal(localKeySharePayload{
			Version: 1, Kind: localKeyShareKind, PartyID: string(n.config.PartyID), ApplicationID: appID, Backup: backup,
		})
		defer clear(payload)
		if err != nil || len(payload) > (1<<18)-28 {
			http.Error(w, "could not encode local key share", http.StatusInternalServerError)
			return
		}
		wrapped, err := wrapKeyShare(key, payload)
		if err != nil {
			http.Error(w, "could not wrap local key share", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wrapped)
	}
}

func (n *node) importLocalKeyShare(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n.wrappingKey == nil {
			http.Error(w, "local share import requires a configured wrapping private key", http.StatusForbidden)
			return
		}
		var request struct {
			WrappedKeyShare wrappedKeyShare `json:"wrappedKeyShare"`
		}
		if decodeJSON(w, r, &request, 1<<19) != nil {
			http.Error(w, "invalid local share import request", http.StatusBadRequest)
			return
		}
		data, err := unwrapKeyShare(n.wrappingKey, request.WrappedKeyShare)
		if err != nil {
			http.Error(w, "could not authenticate local share backup", http.StatusBadRequest)
			return
		}
		defer clear(data)
		var payload localKeySharePayload
		defer func() { clear(payload.Backup.Share) }()
		if json.Unmarshal(data, &payload) != nil {
			http.Error(w, "invalid local share backup", http.StatusBadRequest)
			return
		}
		if payload.ApplicationID != applicationID(r.Context()) {
			http.Error(w, "local share backup belongs to a different application", http.StatusForbidden)
			return
		}
		key := payload.Backup.Key
		if payload.Version != 1 || payload.Kind != localKeyShareKind || payload.PartyID != string(n.config.PartyID) ||
			key.Algorithm != algorithm || !keyIDPattern.MatchString(key.KeyID) ||
			key.SessionID == "" || len(key.SessionID) > 160 {
			http.Error(w, "local share backup does not match this node", http.StatusBadRequest)
			return
		}
		threshold, players, _, err := n.transferShareInfo(algorithm, payload.Backup.Share)
		if err != nil || threshold != key.Threshold || threshold < 1 || !players.Contains(n.config.PartyID) {
			http.Error(w, "invalid local key share data", http.StatusBadRequest)
			return
		}
		release := n.lockKeyOperation(w, payload.ApplicationID, algorithm, key.KeyID, true)
		if release == nil {
			return
		}
		defer release()
		err = n.keys.RestoreKeyShare(r.Context(), payload.ApplicationID, payload.Backup)
		switch {
		case errors.Is(err, keystore.ErrKeyShareConflict):
			http.Error(w, "local backup conflicts with the current key share", http.StatusConflict)
		case err != nil:
			http.Error(w, "could not restore local key share", http.StatusInternalServerError)
		default:
			writeImportedKey(w, key.KeyID)
		}
	}
}
