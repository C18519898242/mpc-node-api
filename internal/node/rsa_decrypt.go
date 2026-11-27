package node

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
)

const rsaDecryptionFormat = "circl-rsa-oaep-sha256-v1"
const rsaMaxCiphertextBytes = 4096 / 8

type rsaDecryptionEnvelope struct {
	Format     string `json:"format"`
	KeyID      string `json:"keyID"`
	PublicKey  []byte `json:"publicKey"`
	Players    uint   `json:"players"`
	Threshold  uint   `json:"threshold"`
	Ciphertext []byte `json:"ciphertext"`
	Share      []byte `json:"share"`
}

func (n *node) decryptRSA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !n.rsaEnabled() || !rsaDecryptionAllowed(r) {
		http.Error(w, "RSA decryption requires MPC mTLS, encrypted storage, an authorized API key and HTTPS", http.StatusForbidden)
		return
	}
	keyID := r.PathValue("keyID")
	var request struct {
		Ciphertext string `json:"ciphertext"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil ||
		request.Ciphertext == "" || len(request.Ciphertext) > base64.StdEncoding.EncodedLen(rsaMaxCiphertextBytes) {
		http.Error(w, "invalid RSA ciphertext", http.StatusBadRequest)
		return
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(request.Ciphertext)
	if err != nil || len(ciphertext) > rsaMaxCiphertextBytes || base64.StdEncoding.EncodeToString(ciphertext) != request.Ciphertext {
		http.Error(w, "invalid RSA ciphertext", http.StatusBadRequest)
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
	if data.usage != rsaUsageDecrypt {
		http.Error(w, "RSA key does not permit decryption", http.StatusForbidden)
		return
	}
	if len(ciphertext) != data.publicKey.Size() {
		http.Error(w, "invalid RSA ciphertext", http.StatusBadRequest)
		return
	}
	decrypter, err := thresholdrsa.NewOAEPDecrypter(data.publicKey, &data.share)
	if err != nil {
		http.Error(w, "could not prepare RSA key for decryption", http.StatusInternalServerError)
		return
	}
	part, err := decrypter.DecryptShare(ciphertext)
	if err != nil {
		http.Error(w, "invalid RSA ciphertext", http.StatusBadRequest)
		return
	}
	encoded, err := part.MarshalBinary()
	if err != nil {
		http.Error(w, "could not encode RSA decryption share", http.StatusInternalServerError)
		return
	}
	defer clear(encoded)
	envelope, err := json.Marshal(rsaDecryptionEnvelope{
		Format: rsaDecryptionFormat, KeyID: keyID, PublicKey: data.publicDER,
		Players: data.share.Players, Threshold: data.share.Threshold, Ciphertext: ciphertext, Share: encoded,
	})
	if err != nil {
		http.Error(w, "could not encode RSA decryption response", http.StatusInternalServerError)
		return
	}
	defer clear(envelope)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		PartialDecryption []byte `json:"partialDecryption"`
	}{envelope})
}
