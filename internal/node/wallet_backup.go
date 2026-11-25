package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func (n *node) getWalletBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if n.config.RESTAuth == nil {
		http.Error(w, "wallet backup requires REST API key authentication", http.StatusForbidden)
		return
	}
	walletID := r.PathValue("walletID")
	if !keyIDPattern.MatchString(walletID) {
		http.Error(w, "invalid wallet ID", http.StatusBadRequest)
		return
	}
	app, partyID := applicationID(r.Context()), string(n.config.PartyID)
	backup, manifest, err := n.keys.LoadWalletBackup(r.Context(), app, walletID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil || backup.Version != 1 || !json.Valid(manifest) {
		http.Error(w, "could not read wallet backup", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		FormatVersion int             `json:"formatVersion"`
		ApplicationID string          `json:"applicationID"`
		PartyID       string          `json:"partyID"`
		WalletID      string          `json:"walletID"`
		BackupKeyID   string          `json:"backupKeyID"`
		WrappedKey    []byte          `json:"wrappedKey"`
		Ciphertext    []byte          `json:"ciphertext"`
		AAD           []byte          `json:"aad"`
		Manifest      json.RawMessage `json:"manifest"`
	}{
		FormatVersion: backup.Version, ApplicationID: app, PartyID: partyID,
		WalletID: walletID, BackupKeyID: backup.KeyID, WrappedKey: backup.WrappedKey,
		Ciphertext: backup.Ciphertext, AAD: mnemonicBackupAAD(app, partyID, walletID, backup.KeyID),
		Manifest: manifest,
	})
}

func (n *node) configureWalletBackup() error {
	cfg := n.config.WalletBackup
	if cfg == nil {
		return nil
	}
	if len(n.config.Peers) != 2 || len(n.config.MobilePeers) != 0 || n.config.MPCTLS == nil ||
		n.config.RESTAuth == nil || n.config.EncryptorMasterPasswordEnv == "" {
		return errors.New("walletBackup requires three server nodes, mTLS, REST authentication and a storage master password")
	}
	if len(cfg.PublicKey) == 0 && cfg.AllowRequestPublicKeys {
		return nil
	}
	key, err := parseWrappingKey(cfg.PublicKey)
	if err != nil {
		return errors.New("walletBackup requires a valid PKIX RSA public key")
	}
	n.walletBackup = key
	return nil
}

type walletBackupPlan struct {
	publicKey *rsa.PublicKey
	keyID     string
	keyIDs    [3]string // Request public key fingerprints in the session's sorted party order.
}

func (n *node) prepareWalletBackup(players party.IDSlice, request json.RawMessage) (walletBackupPlan, error) {
	if request == nil {
		fingerprint := sha256.Sum256(n.config.WalletBackup.PublicKey)
		return walletBackupPlan{publicKey: n.walletBackup, keyID: hex.EncodeToString(fingerprint[:])}, nil
	}
	var keys map[party.ID][]byte
	if json.Unmarshal(request, &keys) != nil || len(keys) != len(players) {
		return walletBackupPlan{}, errors.New("backupPublicKeys must contain a key for each configured party")
	}
	var plan walletBackupPlan
	moduli := make(map[string]bool, len(players))
	for i, id := range players {
		key, err := parseWrappingKey(keys[id])
		if err != nil || key.N.Bit(0) != 1 || key.E&1 != 1 || key.E > (1<<31)-1 {
			return walletBackupPlan{}, errors.New("backupPublicKeys must contain valid PKIX DER RSA keys for all configured parties")
		}
		modulus := string(key.N.Bytes())
		if moduli[modulus] {
			return walletBackupPlan{}, errors.New("wallet parties require distinct backup RSA keys")
		}
		moduli[modulus] = true
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return walletBackupPlan{}, errors.New("invalid backup RSA public key")
		}
		fingerprint := sha256.Sum256(der)
		plan.keyIDs[i] = hex.EncodeToString(fingerprint[:])
		if id == n.config.PartyID {
			plan.publicKey, plan.keyID = key, plan.keyIDs[i]
		}
	}
	return plan, nil
}

func mnemonicBackupAAD(app, node, wallet, backupKeyID string) []byte {
	// These five strings are the stable, versioned on-disk AAD format.
	aad, _ := json.Marshal([5]string{"mpc-node-api/wallet-backup/v1", app, node, wallet, backupKeyID})
	return aad
}

func (n *node) sealMnemonic(app, wallet, mnemonic string, plan walletBackupPlan) (keystore.MnemonicBackup, error) {
	backup := keystore.MnemonicBackup{Version: 1, KeyID: plan.keyID}
	var key [32]byte
	rand.Read(key[:])
	defer clear(key[:])
	var err error
	backup.WrappedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, plan.publicKey, key[:], nil)
	if err != nil {
		return keystore.MnemonicBackup{}, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return keystore.MnemonicBackup{}, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return keystore.MnemonicBackup{}, err
	}
	words := []byte(mnemonic)
	defer clear(words)
	backup.Ciphertext = aead.Seal(nil, nil, words, mnemonicBackupAAD(app, string(n.config.PartyID), wallet, backup.KeyID))
	return backup, nil
}
