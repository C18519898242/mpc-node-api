package node

import (
	"crypto/sha512"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type frostPresignPartial struct {
	PresignatureID string `json:"presignatureId"`
	SchnorrVariant string `json:"schnorr_variant"`
	Curve          string `json:"curve"`
	PlayerIndex    int    `json:"playerIndex"`
	Threshold      int    `json:"threshold"`
	Sharing        string `json:"sharing"`
	R              []byte `json:"r"`
	Challenge      []byte `json:"challenge"`
	PublicKey      []byte `json:"publicKey"`
	SShare         []byte `json:"sShare"`
}

func (n *node) signWithFROSTPresign(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var request struct {
		ChainPath      []uint32 `json:"chainPath"`
		Message        []byte   `json:"message"`
		PresignatureID string   `json:"presignatureId"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil ||
		request.Message == nil || !validPresignatureID(request.PresignatureID) {
		http.Error(w, "invalid FROST presign signing request", http.StatusBadRequest)
		return
	}
	if eddsa.ValidatePath(request.ChainPath) != nil {
		http.Error(w, "invalid FROST derivation path", http.StatusBadRequest)
		return
	}
	release := n.lockSigningKey(w, r, "frost", keyID)
	if release == nil {
		return
	}
	defer release()
	stored, err := n.loadFROSTSigningShare(r.Context(), keyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "could not load signing key", http.StatusInternalServerError)
		return
	}
	ids, _ := frostIDsFor(stored.Players)
	key := &stored.Output
	if len(request.ChainPath) != 0 {
		secret, public, err := key.Public.DeriveShare(key.SecretKey, key.Public.GroupKey.DefaultChainCode(), request.ChainPath)
		if err != nil {
			http.Error(w, "invalid FROST derivation path", http.StatusBadRequest)
			return
		}
		key = &keygen.Output{SecretKey: secret, Public: public}
	}
	record, err := n.keys.ConsumeFROSTPresign(r.Context(), applicationID(r.Context()), keyID, request.PresignatureID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "presignature unavailable", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "could not consume presignature", http.StatusInternalServerError)
		return
	}
	defer clear(record.Share)
	var presign frostPresignShare
	defer clear(presign.Nonces[:])
	if err := cbor.Unmarshal(record.Share, &presign); err != nil {
		http.Error(w, "invalid stored presignature", http.StatusInternalServerError)
		return
	}
	partial, err := makeFROSTPresignPartial(key, &presign, ids, record.ID, request.Message)
	if err != nil {
		http.Error(w, "could not create FROST partial signature", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(partial)
}

func makeFROSTPresignPartial(key *keygen.Output, presign *frostPresignShare, ids map[party.ID]frostparty.ID, id string, message []byte) (frostPresignPartial, error) {
	count := len(presign.Players)
	if count <= int(key.Public.Threshold) || count > len(ids) || count != len(presign.Commitments) {
		return frostPresignPartial{}, errors.New("invalid FROST presign roster")
	}
	signers := make(frostparty.IDSlice, count)
	commitments := make([]*messages.Sign1, count)
	self := key.SecretKey.ID
	selfIndex := -1
	identity := ristretto.NewIdentityElement()
	// Match the pinned FROST sign round's binding transcript.
	const domain = "FROST-SHA512"
	digest := sha512.Sum512(message)
	transcript := append([]byte(domain), self.Bytes()...)
	transcript = append(transcript, digest[:]...)
	for i, player := range presign.Players {
		signer := ids[player]
		if signer == 0 || (i > 0 && signer <= signers[i-1]) {
			return frostPresignPartial{}, errors.New("invalid FROST presign signer")
		}
		commitment, err := decodeFROSTMessage(presign.Commitments[i], true)
		if err != nil || commitment.Sign1 == nil || commitment.From != signer || commitment.To != 0 ||
			commitment.Sign1.Di.Equal(identity) == 1 || commitment.Sign1.Ei.Equal(identity) == 1 {
			return frostPresignPartial{}, errors.New("invalid FROST presign commitment")
		}
		signers[i], commitments[i] = signer, commitment.Sign1
		transcript = append(transcript, signer.Bytes()...)
		transcript = append(transcript, commitment.Sign1.Di.Bytes()...)
		transcript = append(transcript, commitment.Sign1.Ei.Bytes()...)
		if signer == self {
			selfIndex = i
		}
	}
	if selfIndex == -1 {
		return frostPresignPartial{}, errors.New("FROST presign roster omits local signer")
	}

	var nonces [2]ristretto.Scalar
	defer clear(nonces[:])
	local := commitments[selfIndex]
	for i, point := range []*ristretto.Element{&local.Di, &local.Ei} {
		if _, err := nonces[i].SetCanonicalBytes(presign.Nonces[i][:]); err != nil ||
			new(ristretto.Element).ScalarBaseMult(&nonces[i]).Equal(point) != 1 {
			return frostPresignPartial{}, errors.New("FROST presign nonce does not match its commitment")
		}
	}
	groupCommitment := ristretto.NewIdentityElement()
	var localBinding ristretto.Scalar
	for i, signer := range signers {
		copy(transcript[len(domain):], signer.Bytes())
		hash := sha512.Sum512(transcript)
		binding, _ := ristretto.NewScalar().SetUniformBytes(hash[:])
		commitment := commitments[i]
		point := new(ristretto.Element).ScalarMult(binding, &commitment.Ei)
		point.Add(point, &commitment.Di)
		groupCommitment.Add(groupCommitment, point)
		if signer == self {
			localBinding.Set(binding)
		}
	}
	if groupCommitment.Equal(identity) == 1 {
		return frostPresignPartial{}, errors.New("invalid FROST group commitment")
	}
	weight, err := self.Lagrange(signers)
	if err != nil {
		return frostPresignPartial{}, err
	}
	challenge := eddsa.ComputeChallenge(groupCommitment, key.Public.GroupKey, message)
	var share ristretto.Scalar
	share.Multiply(weight, &key.SecretKey.Secret)
	share.Multiply(&share, challenge)
	share.MultiplyAdd(&nonces[1], &localBinding, &share)
	share.Add(&share, &nonces[0])

	// The SDK wire format uses big-endian scalars. Ed25519 signatures use little-endian S.
	sBytes, challengeBytes := share.Bytes(), challenge.Bytes()
	slices.Reverse(sBytes)
	slices.Reverse(challengeBytes)
	return frostPresignPartial{
		PresignatureID: id, SchnorrVariant: "Ed25519", Curve: "ed25519",
		PlayerIndex: int(self) - 1, Threshold: count - 1, Sharing: "additive",
		R: groupCommitment.BytesEd25519(), Challenge: challengeBytes,
		PublicKey: key.Public.GroupKey.ToEd25519(), SShare: sBytes,
	}, nil
}
