package node

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

type ecdsaPresignPartial struct {
	PresignatureID string `json:"presignatureId"`
	Curve          string `json:"curve"`
	PlayerIndex    int    `json:"playerIndex"`
	Threshold      int    `json:"threshold"`
	Sharing        string `json:"sharing"`
	R              []byte `json:"r"`
	PublicKey      []byte `json:"publicKey"`
	SShare         []byte `json:"sShare"`
}

func (n *node) signWithECDSAPresign(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	var request struct {
		ecdsaSignRequest
		PresignatureID string `json:"presignatureId"`
	}
	if !keyIDPattern.MatchString(keyID) || decodeJSON(w, r, &request, 4096) != nil ||
		len(request.MessageHash) != sha256.Size || !validPresignatureID(request.PresignatureID) {
		http.Error(w, "invalid ECDSA presign signing request", http.StatusBadRequest)
		return
	}
	release := n.lockSigningKey(w, r, "ecdsa", keyID)
	if release == nil {
		return
	}
	defer release()
	root, err := n.loadECDSAShare(r.Context(), keyID, nil)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not load signing key", http.StatusInternalServerError)
		return
	}
	key, err := deriveECDSAShare(root, request.ChainPath)
	if err != nil || key.PublicPoint().IsIdentity() {
		http.Error(w, "invalid BIP32 derivation path", http.StatusBadRequest)
		return
	}
	record, err := n.keys.ConsumeECDSAPresign(r.Context(), keyID, request.PresignatureID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "presignature unavailable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "could not consume presignature", http.StatusInternalServerError)
		return
	}
	defer clear(record.Share)
	presign := ecdsa.EmptyPreSignature(root.Group)
	if err := cbor.Unmarshal(record.Share, presign); err != nil {
		http.Error(w, "invalid stored presignature", http.StatusInternalServerError)
		return
	}
	partial, err := makeECDSAPresignPartial(root, key, presign, record.ID, request.MessageHash)
	if err != nil {
		http.Error(w, "could not create ECDSA partial signature", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(partial)
}

func validPresignatureID(id string) bool {
	if id == "" {
		return true
	}
	if len(id) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(decoded) == 32
}

func makeECDSAPresignPartial(root, key *cmp.Config, presign *ecdsa.PreSignature, id string, digest []byte) (ecdsaPresignPartial, error) {
	if presign.R == nil || presign.RBar == nil || presign.S == nil || presign.KShare == nil || presign.ChiShare == nil {
		return ecdsaPresignPartial{}, errors.New("incomplete presignature")
	}
	if err := presign.Validate(); err != nil {
		return ecdsaPresignPartial{}, err
	}
	signers := presign.SignerIDs()
	if base64.RawURLEncoding.EncodeToString(presign.ID) != id || !root.CanSign(signers) {
		return ecdsaPresignPartial{}, errors.New("presignature ID or roster does not match")
	}
	s := presign.SignatureShare(digest)
	if len(presign.VerifySignatureShares(map[party.ID]ecdsa.SignatureShare{root.ID: s}, digest)) != 0 {
		return ecdsaPresignPartial{}, errors.New("invalid local presignature share")
	}
	// A non-hardened child adds the same scalar delta to every Shamir share.
	// Adjust the additive signature share by r*k_i*delta for the child key.
	delta := root.Group.NewScalar().Set(key.ECDSA).Sub(root.ECDSA)
	s.Add(presign.R.XScalar().Mul(presign.KShare).Mul(delta))
	sBytes, err := s.MarshalBinary()
	if err != nil {
		return ecdsaPresignPartial{}, err
	}
	r, err := uncompressedECDSAPoint(presign.R)
	if err != nil {
		return ecdsaPresignPartial{}, err
	}
	publicKey, err := uncompressedECDSAPoint(key.PublicPoint())
	if err != nil {
		return ecdsaPresignPartial{}, err
	}
	return ecdsaPresignPartial{
		PresignatureID: id, Curve: "secp256k1", PlayerIndex: slices.Index(root.PartyIDs(), root.ID),
		Threshold: len(signers) - 1, Sharing: "additive", R: r, PublicKey: publicKey, SShare: sBytes,
	}, nil
}
