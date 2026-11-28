package node

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
)

func (n *node) exportRSAKey(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() || !n.authenticatedRESTTLS(r) {
		http.Error(w, "RSA export requires MPC mTLS, encrypted storage, HTTPS and an API key", http.StatusForbidden)
		return
	}
	if n.config.KeyTransfer == nil || !n.config.KeyTransfer.ExportEnabled {
		http.Error(w, "key export is disabled", http.StatusForbidden)
		return
	}
	keyID := r.PathValue("keyID")
	sid := r.Header.Get("MPC-SessionID")
	var request struct {
		WrappingKey []byte `json:"wrappingKey"`
	}
	if !keyIDPattern.MatchString(keyID) || !memorySessionPattern.MatchString(sid) ||
		decodeJSON(w, r, &request, 16384) != nil {
		http.Error(w, "invalid RSA key export request", http.StatusBadRequest)
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
	for _, peer := range players {
		if peer != n.config.PartyID && n.config.Peers[peer] == "" {
			http.Error(w, "RSA export requires static MPC peers", http.StatusBadRequest)
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
		http.Error(w, "only RSA signing keys can be exported", http.StatusForbidden)
		return
	}
	if !slices.Equal(players, data.players) {
		http.Error(w, "export players do not match key holders", http.StatusBadRequest)
		return
	}
	secret, err := data.share.MarshalBinary()
	if err != nil || !validRSAImportSecret(secret, data.publicKey.Size()) {
		clear(secret)
		http.Error(w, "invalid stored RSA signing share", http.StatusInternalServerError)
		return
	}
	defer clear(secret)

	params := keyTransferParameters{
		Route:         "rsa-export." + sid,
		KeyID:         keyID,
		SourceID:      keyID,
		Threshold:     int(data.share.Threshold) - 1,
		Players:       players,
		ImportBinding: data.publicDER,
	}
	n.serveKeyTransfer(w, r, params, request.WrappingKey,
		func(ctx context.Context, exchange *copyExchange, _ *keygenSession) ([]byte, error) {
			if err := exchange.send(ctx, copySourceRound, "", nil); err != nil {
				return nil, err
			}
			if _, err := exchange.collect(ctx, copySourceRound); err != nil {
				return nil, err
			}
			plaintext, err := json.Marshal(rsaImportShare{
				Format:    rsaImportFormat,
				SplitID:   exchange.binding[:],
				Players:   players,
				PublicKey: data.publicDER,
				Share:     secret,
			})
			if err != nil {
				return nil, err
			}
			defer clear(plaintext)
			wrapped, err := wrapKeyShare(wrappingKey, plaintext)
			if err != nil {
				return nil, err
			}
			wrappedBytes, err := json.Marshal(wrapped)
			if err != nil {
				return nil, err
			}
			return json.Marshal(struct {
				WrappedKeyShare []byte `json:"wrappedKeyShare"`
				PublicKey       []byte `json:"publicKey"`
			}{wrappedBytes, data.publicDER})
		})
}
