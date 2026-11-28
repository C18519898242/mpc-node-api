package node

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

func (n *node) rsaPublicKey(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() {
		http.Error(w, "RSA requires MPC mTLS and encrypted storage", http.StatusForbidden)
		return
	}
	keyID := r.PathValue("keyID")
	if !keyIDPattern.MatchString(keyID) {
		http.Error(w, "invalid RSA public key request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		if err := decodeJSON(w, r, &struct{}{}, 4096); err != nil && err != io.EOF {
			http.Error(w, "invalid RSA public key request", http.StatusBadRequest)
			return
		}
	}
	data := n.readRSAKey(w, r, keyID)
	if data == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		_ = json.NewEncoder(w).Encode(struct {
			PublicKey []byte `json:"publicKey"`
		}{data.publicDER})
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		PublicKey       []byte `json:"publicKey"`
		Players         uint   `json:"players"`
		RequiredSigners uint   `json:"requiredSigners"`
	}{data.publicDER, data.share.Players, data.share.Threshold})
}

func (n *node) signRSA(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() {
		http.Error(w, "RSA requires MPC mTLS and encrypted storage", http.StatusForbidden)
		return
	}
	keyID := r.PathValue("keyID")
	var request struct {
		MessageHash []byte `json:"messageHash"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil || len(request.MessageHash) != sha256.Size {
		http.Error(w, "invalid RSA signing request", http.StatusBadRequest)
		return
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
	// Both the modulus and the share come from the authenticated local record.
	padded, err := (thresholdrsa.PKCS1v15Padder{}).Pad(data.publicKey, crypto.SHA256, request.MessageHash)
	if err != nil {
		http.Error(w, "could not encode RSA digest", http.StatusInternalServerError)
		return
	}
	part, err := data.share.Sign(rand.Reader, data.publicKey, padded, false)
	if err != nil {
		http.Error(w, "could not sign RSA digest", http.StatusInternalServerError)
		return
	}
	encoded, err := part.MarshalBinary()
	if err != nil {
		http.Error(w, "could not encode RSA signature share", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		PartialSignature []byte `json:"partialSignature"`
	}{encoded})
}

func (n *node) readRSAKey(w http.ResponseWriter, r *http.Request, keyID string) *rsaKeyData {
	raw, err := n.keys.Load(r.Context(), applicationID(r.Context()), "rsa", keyID)
	defer clear(raw)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return nil
	}
	if err == nil {
		data, decodeErr := decodeStoredRSAKeyShare(raw, n.config.PartyID)
		if decodeErr == nil {
			return data
		}
	}
	http.Error(w, "could not read RSA key", http.StatusInternalServerError)
	return nil
}
