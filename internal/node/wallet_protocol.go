package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

const (
	walletContributions   = "wallet/contributions"
	walletContributionAck = "wallet/contribution-ack"
	walletFROSTBroadcast  = "wallet/frost-broadcast"
	walletFROSTAck        = "wallet/frost-broadcast-ack"
	walletReady           = "wallet/ready"
)

type walletContribution struct {
	BackupKeyID string                             `json:"backupKeyID"`
	ECDSA       recovery.CMPPublicContribution     `json:"ecdsa"`
	FROST       recovery.Ed25519PublicContribution `json:"frost"`
}

type walletManifest struct {
	Version int                                `json:"version"`
	Players party.IDSlice                      `json:"players"`
	Public  [3]walletContribution              `json:"publicContributions"`
	ECDSA   recovery.CMPPublicContribution     `json:"ecdsa"`
	FROST   recovery.Ed25519PublicContribution `json:"frost"`
}

func (n *node) generateWallet(ctx context.Context, sid string, receipt walletReceipt, session *keygenSession, plan walletBackupPlan) (string, error) {
	app := applicationID(ctx)
	mnemonic, err := recovery.GenerateMnemonic()
	if err != nil {
		return "mnemonic", err
	}
	ecdsa, err := recovery.DeriveCMPContribution(mnemonic)
	if err != nil {
		return "mnemonic", err
	}
	defer clear(ecdsa.Scalar[:])
	ed25519, err := recovery.DeriveEd25519Contribution(mnemonic)
	if err != nil {
		return "mnemonic", err
	}
	defer clear(ed25519.Scalar[:])
	backup, err := n.sealMnemonic(app, receipt.WalletID, mnemonic, plan)
	if err != nil {
		return "backup", err
	}
	local := walletContribution{backup.KeyID, ecdsa.Public, ed25519.Public}
	binding := []byte("wallet/v1/" + sid + "/" + receipt.WalletID)
	if plan.keyIDs[0] != "" {
		binding = append(append(binding, 0), session.signBinding[:]...)
	}
	x := &copyExchange{
		node: n, route: "wallet." + sid, players: session.players, incoming: session.incoming,
		binding: sha256.Sum256(applicationBinding(app, binding)),
		received: map[string]map[party.ID][]byte{
			walletContributions: {}, walletContributionAck: {}, walletFROSTBroadcast: {}, walletFROSTAck: {}, walletReady: {},
		},
	}
	manifest, err := x.walletManifest(ctx, local, plan.keyIDs)
	if err != nil {
		return "contributions", err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "contributions", err
	}
	if err := x.agreeWalletDigest(ctx, walletContributionAck, sha256.Sum256(encoded)); err != nil {
		return "contributions", err
	}
	cmpID := x.route + ".cmp"
	cmpBinding := sha256.Sum256(append([]byte(cmpID+"\x00"), encoded...))
	cmpStart := cmp.ImportKey(n.config.PartyID, session.players, ecdsa.Scalar[:], manifest.ECDSA.PublicKey[:], manifest.ECDSA.ChainCode[:], nil)
	result, err := n.runCMP(ctx, cmpID, cmpBinding[:], cmpStart, session.walletInboxes[0], session.players)
	if err != nil {
		return "cmp", err
	}
	cmpShare, err := result.(*cmp.Config).MarshalBinary()
	if err != nil {
		return "cmp", err
	}
	defer clear(cmpShare)
	frostShare, err := n.generateWalletFROST(ctx, x, encoded, manifest, ed25519.Scalar[:], session.walletInboxes[1])
	if err != nil {
		return "frost", err
	}
	defer clear(frostShare)
	if err := x.agreeWalletDigest(ctx, walletReady, sha256.Sum256(encoded)); err != nil {
		return "ready", err
	}
	return "storage", n.keys.SaveWallet(ctx, app, sid, receipt.WalletID, receipt.ECDSAKeyID, receipt.FROSTKeyID, encoded, backup, cmpShare, frostShare)
}

func (x *copyExchange) walletManifest(ctx context.Context, local walletContribution, expectedKeyIDs [3]string) (walletManifest, error) {
	manifest := walletManifest{Version: 1, Players: x.players}
	body, err := json.Marshal(local)
	if err != nil {
		return manifest, err
	}
	if err := x.send(ctx, walletContributions, "", body); err != nil {
		return manifest, err
	}
	received, err := x.collect(ctx, walletContributions)
	if err != nil {
		return manifest, err
	}
	received[x.node.config.PartyID] = body
	var ecdsa [3]recovery.CMPPublicContribution
	var frost [3]recovery.Ed25519PublicContribution
	keys := map[string]bool{}
	for i, player := range x.players {
		public := &manifest.Public[i]
		if err := json.Unmarshal(received[player], public); err != nil {
			return manifest, err
		}
		key, err := hex.DecodeString(public.BackupKeyID)
		if err != nil || len(key) != sha256.Size || public.BackupKeyID != hex.EncodeToString(key) || keys[public.BackupKeyID] {
			return manifest, errors.New("wallet nodes require distinct backup RSA keys")
		}
		if expectedKeyIDs[i] != "" && public.BackupKeyID != expectedKeyIDs[i] {
			return manifest, errors.New("wallet backup RSA key differs from the request")
		}
		keys[public.BackupKeyID] = true
		ecdsa[i], frost[i] = public.ECDSA, public.FROST
	}
	manifest.ECDSA, err = recovery.CombineCMPPublicContributions(ecdsa)
	if err != nil {
		return manifest, err
	}
	manifest.FROST, err = recovery.CombineEd25519PublicContributions(frost)
	return manifest, err
}

func (x *copyExchange) agreeWalletDigest(ctx context.Context, phase string, digest [32]byte) error {
	if err := x.send(ctx, phase, "", digest[:]); err != nil {
		return err
	}
	received, err := x.collect(ctx, phase)
	if err != nil {
		return err
	}
	for _, data := range received {
		if !bytes.Equal(digest[:], data) {
			return errors.New("wallet participants disagree on the transcript")
		}
	}
	return nil
}

func (n *node) generateWalletFROST(ctx context.Context, x *copyExchange, manifestJSON []byte, manifest walletManifest, scalar []byte, incoming chan *protocol.Message) ([]byte, error) {
	self := n.config.PartyID
	ids, frostIDs := frostIDsFor(x.players)
	route := x.route + ".frost"
	binding := sha256.Sum256(append([]byte(route+"\x00"), manifestJSON...))
	state, output, err := frost.NewKeygenStateWithContribution(ids[self], frostIDs, scalar, manifest.FROST.PublicKey[:], applicationBinding(applicationID(ctx), binding[:]), 0)
	if err != nil {
		return nil, err
	}
	out := state.ProcessAll()
	if len(out) != 1 || out[0].Type != messages.MessageTypeKeyGen1 || !out[0].IsBroadcast() {
		return nil, errors.New("expected a FROST commitment broadcast")
	}
	local, err := out[0].MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := x.send(ctx, walletFROSTBroadcast, "", local); err != nil {
		return nil, err
	}
	broadcasts, err := x.collect(ctx, walletFROSTBroadcast)
	if err != nil {
		return nil, err
	}
	broadcasts[self] = local
	// Confirm a common view of the broadcast before FROST sends private evaluations.
	var hashes [96]byte
	for i, player := range x.players {
		digest := sha256.Sum256(broadcasts[player])
		copy(hashes[i*32:], digest[:])
	}
	if err := x.agreeWalletDigest(ctx, walletFROSTAck, sha256.Sum256(hashes[:])); err != nil {
		return nil, err
	}
	for i, player := range x.players {
		if player == self {
			continue
		}
		message, err := decodeFROSTMessage(broadcasts[player], false)
		if err != nil || message.Type != messages.MessageTypeKeyGen1 || message.From != ids[player] || !message.IsBroadcast() ||
			message.KeyGen1.Commitments.Degree() != 2 ||
			!bytes.Equal(message.KeyGen1.Commitments.Constant().BytesEd25519(), manifest.Public[i].FROST.PublicKey[:]) {
			return nil, errors.New("FROST broadcast does not match the agreed contribution")
		}
		if err := state.HandleMessage(message); err != nil {
			return nil, err
		}
	}
	session := &keygenSession{incoming: incoming}
	if err := n.runFROST(ctx, route, session, binding, state, x.players, ids, x.players, false); err != nil {
		return nil, err
	}
	return marshalFROSTShareWithChainCode(output, x.players, manifest.FROST.ChainCode[:])
}
