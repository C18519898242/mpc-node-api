package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	cmpECDSA "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// GeneratePresignatures coordinates a batch for all configured participants.
// Only public IDs leave the nodes; nonce shares remain encrypted in SQLite.
func (e *Embedded) GeneratePresignatures(algorithm, keyID string, count int) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := mobileCurve(algorithm); err != nil {
		return "", err
	}
	if e.closed || e.ctx.Err() != nil {
		return "", errors.New("mobile node is closed")
	}
	if !keyIDPattern.MatchString(keyID) || count < 1 || count > maxPresignCount {
		return "", errors.New("invalid mobile presign parameters")
	}
	sid := newMobileSession()
	route := algorithm + "-presign." + sid
	polls := make([]string, count)
	for i := range polls {
		polls[i] = fmt.Sprintf("%s.%d", route, i)
	}
	response, err := e.coordinate(fmt.Sprintf("/%s/keys/%s/%d/presiggen", algorithm, keyID, count), route, sid, nil, polls...)
	if err != nil {
		return "", err
	}
	var batch struct {
		IDs []string `json:"ids"`
	}
	if json.Unmarshal(response, &batch) != nil || len(batch.IDs) != count {
		return "", errors.New("invalid mobile presign batch")
	}
	seen := make(map[string]bool, count)
	for _, id := range batch.IDs {
		if id == "" || !validPresignatureID(id) || seen[id] {
			return "", errors.New("invalid mobile presignature ID")
		}
		seen[id] = true
	}
	return string(response), nil
}

// SignWithPresignature consumes one explicitly selected ID on every node.
// A failed attempt must not be retried with that ID: some shares may be consumed.
func (e *Embedded) SignWithPresignature(algorithm, keyID, id string, message []byte) (string, error) {
	return e.SignWithPresignatureAndPath(algorithm, keyID, id, message, nil)
}

func (e *Embedded) SignWithPresignatureAndPath(algorithm, keyID, id string, message []byte, chainPath []uint32) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	curveName, err := mobileCurve(algorithm)
	if err != nil {
		return "", err
	}
	if e.closed || e.ctx.Err() != nil {
		return "", errors.New("mobile node is closed")
	}
	if !keyIDPattern.MatchString(keyID) || id == "" || !validPresignatureID(id) || len(message) > 2048 {
		return "", errors.New("invalid mobile presign signing parameters")
	}
	public, err := e.publicKey(algorithm, keyID, chainPath)
	if err != nil {
		return "", err
	}
	players := e.node.configuredPlayers()
	indices, err := e.presignPlayerIndices(algorithm, keyID, players)
	if err != nil {
		return "", err
	}
	request := map[string]any{"presignatureId": id, "message": append([]byte{}, message...), "chainPath": chainPath}
	if algorithm == "ecdsa" {
		digest := sha256.Sum256(message)
		delete(request, "message")
		request["messageHash"] = digest[:]
	}
	body, _ := json.Marshal(request)
	path := "/" + algorithm + "/keys/" + keyID + "/signwithpresig"
	ctx, cancel := context.WithTimeout(e.ctx, keygenTimeout+5*time.Second)
	defer cancel()
	// Consume locally first, so a missing local ID never consumes server shares.
	local, err := e.localCall(ctx, path, "", body)
	if err != nil {
		return "", err
	}
	type result struct {
		index int
		data  []byte
		err   error
	}
	results := make(chan result, len(players)-1)
	partials := make([]mobilePresignPartial, len(players))
	for i, peer := range players {
		if peer == e.node.config.PartyID {
			err = json.Unmarshal(local, &partials[i])
			continue
		}
		go func() {
			data, callErr := e.remoteCall(ctx, peer, "/internal/mobile"+path, "", body, false)
			results <- result{i, data, callErr}
		}()
	}
	for range len(players) - 1 {
		response := <-results
		if response.err == nil {
			response.err = json.Unmarshal(response.data, &partials[response.index])
		}
		if err == nil && response.err != nil {
			err = response.err
			cancel()
		}
	}
	if err != nil {
		return "", fmt.Errorf("mobile presign signing failed; discard this presignature ID: %w", err)
	}
	signature, err := combineMobilePresign(algorithm, id, public, message, partials, indices)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	encoded, _ := json.Marshal(mobileKeyResult{KeyID: keyID, PresignatureID: id, Curve: curveName, PublicKey: public, Signature: signature})
	return string(encoded), nil
}

type mobilePresignPartial struct {
	ecdsaPresignPartial
	Challenge      []byte `json:"challenge"`
	SchnorrVariant string `json:"schnorr_variant"`
}

func (e *Embedded) presignPlayerIndices(algorithm, keyID string, players party.IDSlice) ([]int, error) {
	ctx := context.WithValue(e.ctx, applicationContextKey{}, e.application)
	var roster party.IDSlice
	if algorithm == "ecdsa" {
		key, err := e.node.loadECDSAShare(ctx, keyID, nil)
		if err != nil {
			return nil, err
		}
		roster = key.PartyIDs()
	} else {
		key, err := e.node.loadFROSTSigningShare(ctx, keyID)
		if err != nil {
			return nil, err
		}
		roster = key.Players
	}
	indices := make([]int, len(players))
	for i, player := range players {
		indices[i] = slices.Index(roster, player)
		if indices[i] < 0 {
			return nil, errors.New("mobile participant is not in the key roster")
		}
	}
	return indices, nil
}

func combineMobilePresign(algorithm, id string, public, message []byte, parts []mobilePresignPartial, indices []int) ([]byte, error) {
	curveName, err := mobileCurve(algorithm)
	if err != nil || len(parts) < 2 || len(indices) != len(parts) {
		return nil, errors.New("invalid mobile presign participants")
	}
	for i, p := range parts {
		if p.PresignatureID != id || p.Curve != curveName || p.Sharing != "additive" || p.Threshold != len(parts)-1 ||
			indices[i] < 0 || (i > 0 && indices[i] <= indices[i-1]) || p.PlayerIndex != indices[i] ||
			!bytes.Equal(p.PublicKey, public) || !bytes.Equal(p.R, parts[0].R) || len(p.SShare) != 32 {
			return nil, errors.New("mobile presign partial signatures disagree")
		}
	}
	if algorithm == "frost" {
		sum := ristretto.NewScalar()
		for _, p := range parts {
			if p.SchnorrVariant != "Ed25519" || len(p.R) != 32 || len(p.Challenge) != 32 || !bytes.Equal(p.Challenge, parts[0].Challenge) {
				return nil, errors.New("invalid mobile FROST partial signature")
			}
			data := bytes.Clone(p.SShare)
			slices.Reverse(data)
			s, err := ristretto.NewScalar().SetCanonicalBytes(data)
			if err != nil {
				return nil, err
			}
			sum.Add(sum, s)
		}
		signature := append(bytes.Clone(parts[0].R), sum.Bytes()...)
		if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, message, signature) {
			return nil, errors.New("mobile FROST presign signature did not verify")
		}
		return signature, nil
	}
	group := curve.Secp256k1{}
	sum := group.NewScalar()
	for _, p := range parts {
		s := group.NewScalar()
		if err := s.UnmarshalBinary(p.SShare); err != nil {
			return nil, err
		}
		sum.Add(s)
	}
	parsePoint := func(data []byte) (curve.Point, error) {
		point, err := secp256k1.ParsePubKey(data)
		if err != nil {
			return nil, err
		}
		p := group.NewPoint()
		return p, p.UnmarshalBinary(point.SerializeCompressed())
	}
	r, err := parsePoint(parts[0].R)
	if err != nil {
		return nil, err
	}
	pub, err := parsePoint(public)
	if err != nil {
		return nil, err
	}
	sig := cmpECDSA.Signature{R: r, S: sum}
	digest := sha256.Sum256(message)
	if !sig.Verify(pub, digest[:]) {
		return nil, errors.New("mobile ECDSA presign signature did not verify")
	}
	return encodeECDSASignature(&sig)
}
