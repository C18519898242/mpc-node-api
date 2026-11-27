package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"slices"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

const rsaImportFormat = "circl-rsa-sign-import-v1"

type rsaImportShare struct {
	Format    string        `json:"format"`
	SplitID   []byte        `json:"splitID"`
	Players   party.IDSlice `json:"players"`
	PublicKey []byte        `json:"publicKey"`
	Share     []byte        `json:"share"`
}

func (n *node) importRSAKey(w http.ResponseWriter, r *http.Request) {
	if !n.rsaEnabled() || !n.authenticatedRESTTLS(r) || n.wrappingKey == nil {
		http.Error(w, "RSA import requires MPC mTLS, encrypted storage, a wrapping key, HTTPS and an API key", http.StatusForbidden)
		return
	}
	var request struct {
		KeyID           string `json:"keyID"`
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
	}
	sid := r.Header.Get("MPC-SessionID")
	if !memorySessionPattern.MatchString(sid) || decodeJSON(w, r, &request, 64<<10) != nil ||
		(request.KeyID != "" && !keyIDPattern.MatchString(request.KeyID)) {
		http.Error(w, "invalid RSA key import request", http.StatusBadRequest)
		return
	}
	players := n.signingPlayers(w, r, sid)
	if players == nil {
		return
	}
	for _, peer := range players {
		if peer != n.config.PartyID && n.config.Peers[peer] == "" {
			http.Error(w, "RSA import requires static MPC peers", http.StatusBadRequest)
			return
		}
	}
	var wrapped wrappedKeyShare
	if decodeSingleJSON(bytes.NewReader(request.WrappedKeyShare), &wrapped) != nil {
		http.Error(w, "invalid RSA import envelope", http.StatusBadRequest)
		return
	}
	raw, err := unwrapKeyShare(n.wrappingKey, wrapped)
	if err != nil {
		http.Error(w, "could not authenticate RSA import share", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	var payload rsaImportShare
	err = decodeSingleJSON(bytes.NewReader(raw), &payload)
	defer clear(payload.Share)
	if err != nil || payload.Format != rsaImportFormat || len(payload.SplitID) != sha256.Size || !slices.Equal(payload.Players, players) {
		http.Error(w, "RSA import share does not match the participant group", http.StatusBadRequest)
		return
	}
	stored, err := json.Marshal(struct {
		storedRSAKeyShare
		SplitID []byte `json:"splitID"`
	}{storedRSAKeyShare{Players: players, PublicKey: payload.PublicKey, Share: payload.Share, Usage: rsaUsageSign}, payload.SplitID})
	if err != nil {
		http.Error(w, "could not encode RSA import share", http.StatusInternalServerError)
		return
	}
	defer clear(stored)
	data, err := decodeStoredRSAKeyShare(stored, n.config.PartyID)
	if err != nil || !validRSAImportSecret(payload.Share, data.publicKey.Size()) {
		http.Error(w, "invalid RSA import share", http.StatusBadRequest)
		return
	}
	route := "rsa-import." + sid
	if request.KeyID == "" {
		id := sha256.Sum256([]byte(route))
		request.KeyID = base64.RawURLEncoding.EncodeToString(id[:21])
	}
	key := keystore.Key{Algorithm: "rsa", SessionID: "import." + sid, KeyID: request.KeyID, Threshold: int(data.share.Threshold) - 1}
	app := applicationID(r.Context())
	release := n.lockKeyOperation(w, app, "rsa", key.KeyID, true)
	if release == nil {
		return
	}
	defer release()

	identity := sha256.Sum256(append(payload.SplitID, data.publicDER...))
	params := keyTransferParameters{
		Route: route, KeyID: key.KeyID, Threshold: key.Threshold, Players: players, ImportBinding: identity[:],
	}
	params.reserve = func() bool {
		reservation, err := n.keys.Reserve(r.Context(), app, key)
		switch {
		case err != nil:
			http.Error(w, "could not reserve RSA import", http.StatusInternalServerError)
		case reservation == keystore.Conflict:
			http.Error(w, "RSA import session or key ID already used", http.StatusConflict)
		case reservation == keystore.Completed:
			saved, err := n.keys.Load(r.Context(), app, "rsa", key.KeyID)
			defer clear(saved)
			if err != nil {
				http.Error(w, "could not load completed RSA import", http.StatusInternalServerError)
			} else if !bytes.Equal(saved, stored) {
				http.Error(w, "completed RSA import does not match the request", http.StatusConflict)
			} else {
				writeImportedKey(w, key.KeyID)
			}
		default:
			return true
		}
		return false
	}
	localBinding := sha256.Sum256(stored)
	n.serveKeyTransfer(w, r, params, localBinding[:],
		func(ctx context.Context, exchange *copyExchange, _ *keygenSession) ([]byte, error) {
			if err := verifyRSAImport(ctx, exchange, data); err != nil {
				return nil, err
			}
			if err := n.keys.Save(ctx, app, key, stored); err != nil {
				return nil, err
			}
			return json.Marshal(generateKeyResponse{KeyID: key.KeyID})
		})
}

func validRSAImportSecret(share []byte, modulusSize int) bool {
	if len(share) < 12 {
		return false
	}
	// CIRCL v1 encodes four uint16 fields, the secret, and the cache flag and length.
	// Derive the private exponent locally instead of accepting a cached exponent.
	size := int(binary.BigEndian.Uint16(share[6:8]))
	return size > 0 && size <= modulusSize && len(share) == 11+size &&
		(size == 1 || share[8] != 0) && bytes.Equal(share[8+size:], []byte{0, 0, 0})
}

func verifyRSAImport(ctx context.Context, exchange *copyExchange, data *rsaKeyData) error {
	// The proof concerns this import session only. Share bytes stay on the
	// recipient node and the proof is exchanged only over MPC mTLS.
	digest := sha256.Sum256(append([]byte("mpc-node-api/rsa-import-proof/v1\x00"), exchange.binding[:]...))
	padded, err := (thresholdrsa.PKCS1v15Padder{}).Pad(data.publicKey, crypto.SHA256, digest[:])
	if err != nil {
		return err
	}
	proof, err := data.share.Sign(rand.Reader, data.publicKey, padded, false)
	if err != nil {
		return err
	}
	encoded, err := proof.MarshalBinary()
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := exchange.send(ctx, copySourceRound, "", encoded); err != nil {
		return err
	}
	received, err := exchange.collect(ctx, copySourceRound)
	if err != nil {
		return err
	}
	received[exchange.node.config.PartyID] = encoded
	shares := make([]thresholdrsa.SignShare, len(data.players))
	for i, player := range data.players {
		raw := received[player]
		if len(raw) <= 8 || len(raw) > 8+data.publicKey.Size() || int(binary.BigEndian.Uint16(raw[6:8])) != len(raw)-8 ||
			shares[i].UnmarshalBinary(raw) != nil || shares[i].Index != uint(i+1) ||
			shares[i].Players != data.share.Players || shares[i].Threshold != data.share.Threshold {
			return errors.New("invalid RSA import proof metadata")
		}
		value := new(big.Int).SetBytes(raw[8:])
		if value.Cmp(data.publicKey.N) >= 0 || new(big.Int).GCD(nil, nil, value, data.publicKey.N).Cmp(big.NewInt(1)) != 0 {
			return errors.New("invalid RSA import proof value")
		}
	}
	// Check a threshold quorum and substitute each remaining node into it so
	// every imported share is checked, including shares outside the first quorum.
	basis := slices.Clone(shares[:data.share.Threshold])
	for _, share := range shares[data.share.Threshold-1:] {
		basis[len(basis)-1] = share
		if _, err := thresholdrsa.CombineSignShares(data.publicKey, data.share.Players, data.share.Threshold, basis, padded); err != nil {
			return errors.New("RSA import proof does not match the public key")
		}
	}
	return nil
}
