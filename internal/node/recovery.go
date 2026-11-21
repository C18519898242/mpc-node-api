package node

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/recovery"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func (n *node) configureEmergencyRecovery() error {
	cfg := n.config.EmergencyRecovery
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if len(cfg.PublicKeys) == 0 {
		return errors.New("emergency recovery requires trusted RSA public keys")
	}
	for _, der := range cfg.PublicKeys {
		if _, err := recovery.ParsePublicKey(der); err != nil {
			return errors.New("invalid emergency recovery RSA public key")
		}
	}
	return nil
}

func (n *node) generateRecoveryData(algorithm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := n.config.EmergencyRecovery
		if cfg == nil || !cfg.Enabled {
			http.Error(w, "emergency recovery is disabled", http.StatusForbidden)
			return
		}
		var request struct {
			RecoveryKey []byte `json:"recoveryKey"`
			Label       []byte `json:"label"`
		}
		keyID, sid := r.PathValue("keyID"), r.Header.Get("MPC-SessionID")
		if !keyIDPattern.MatchString(keyID) || keyID == "_" || !memorySessionPattern.MatchString(sid) || decodeJSON(w, r, &request, 16384) != nil || len(request.Label) > 1024 {
			http.Error(w, "invalid emergency recovery request", http.StatusBadRequest)
			return
		}
		if _, err := recovery.ParsePublicKey(request.RecoveryKey); err != nil {
			http.Error(w, "invalid RSA recovery key", http.StatusBadRequest)
			return
		}
		allowed := false
		for _, der := range cfg.PublicKeys {
			allowed = allowed || bytes.Equal(der, request.RecoveryKey)
		}
		if !allowed {
			http.Error(w, "RSA recovery key is not allowed", http.StatusForbidden)
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
		manifest, secret, err := n.recoveryMaterial(r.Context(), algorithm, keyID)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "could not load recovery key", http.StatusInternalServerError)
			return
		}
		defer clear(secret)
		holders := make(party.IDSlice, len(manifest.Players))
		for i, id := range manifest.Players {
			holders[i] = party.ID(id)
		}
		if len(players) <= manifest.Threshold || !allPlayersIn(players, holders) {
			http.Error(w, "recovery players do not satisfy the key threshold", http.StatusBadRequest)
			return
		}
		manifest.SessionID, manifest.RecoveryKey, manifest.Label = sid, request.RecoveryKey, request.Label
		encoded, _ := json.Marshal(manifest)
		params := keyTransferParameters{Route: algorithm + "-recovery." + sid, KeyID: keyID, SourceID: keyID, Threshold: manifest.Threshold, Players: players}
		n.serveKeyTransfer(w, r, params, encoded, func(ctx context.Context, x *copyExchange, _ *keygenSession) ([]byte, error) {
			// Bind the recipient, label, root, chain code and sharing generation
			// across participants before releasing any encrypted recovery data.
			if err := x.send(ctx, copySourceRound, "", encoded); err != nil {
				return nil, err
			}
			received, err := x.collect(ctx, copySourceRound)
			if err != nil {
				return nil, err
			}
			for _, data := range received {
				if !bytes.Equal(data, encoded) {
					return nil, errors.New("recovery parameters differ between nodes")
				}
			}
			partial, err := recovery.Generate(manifest, string(n.config.PartyID), secret)
			if err != nil {
				return nil, err
			}
			return json.Marshal(partial)
		})
	}
}

func (n *node) recoveryMaterial(ctx context.Context, algorithm, keyID string) (m recovery.Manifest, secret []byte, err error) {
	defer func() {
		if recover() != nil {
			clear(secret)
			m, secret, err = recovery.Manifest{}, nil, errors.New("invalid stored recovery share")
		}
	}()
	data, err := n.keys.Load(ctx, applicationID(ctx), algorithm, keyID)
	if err != nil {
		return m, nil, err
	}
	defer clear(data)
	m = recovery.Manifest{Version: 1, Algorithm: algorithm, ApplicationID: applicationID(ctx), KeyID: keyID}
	if algorithm == "ecdsa" {
		key, err := n.decodeCMPShare(data)
		if err != nil {
			return m, nil, err
		}
		defer key.ECDSA.Set(key.Group.NewScalar())
		m.Threshold, m.ChainCode = key.Threshold, bytes.Clone(key.ChainKey)
		m.PublicKey, err = uncompressedECDSAPoint(key.PublicPoint())
		if err != nil {
			return m, nil, err
		}
		for _, id := range key.PartyIDs() {
			point, err := key.Public[id].ECDSA.MarshalBinary()
			if err != nil {
				return m, nil, err
			}
			m.Players = append(m.Players, string(id))
			m.PublicShares = append(m.PublicShares, point)
		}
		secret, err = key.ECDSA.MarshalBinary()
		return m, secret, err
	}
	key, err := n.decodeFROSTSigningShare(data)
	if err != nil {
		return m, nil, err
	}
	defer key.SecretKey.Secret.Set(ristretto.NewScalar())
	code := key.chainCode()
	m.Threshold, m.ChainCode, m.PublicKey = int(key.Public.Threshold), code[:], key.Public.GroupKey.ToEd25519()
	for i, id := range key.Players {
		m.Players = append(m.Players, string(id))
		m.PublicShares = append(m.PublicShares, key.Public.Shares[key.Public.PartyIDs[i]].Bytes())
	}
	return m, bytes.Clone(key.SecretKey.Secret.Bytes()), nil
}
