package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

func (n *node) configureWalletBackup() error {
	cfg := n.config.WalletBackup
	if cfg == nil {
		return nil
	}
	if len(n.config.Peers) != 2 || len(n.config.MobilePeers) != 0 || n.config.MPCTLS == nil ||
		n.config.RESTAuth == nil || n.config.EncryptorMasterPasswordEnv == "" {
		return errors.New("walletBackup requires three server nodes, mTLS, REST authentication and a storage master password")
	}
	key, err := parseWrappingKey(cfg.PublicKey)
	if err != nil {
		return errors.New("walletBackup requires a valid PKIX RSA public key")
	}
	n.walletBackup = key
	return nil
}

func mnemonicBackupAAD(app, node, wallet, backupKeyID string) []byte {
	// These five strings are the stable, versioned on-disk AAD format.
	aad, _ := json.Marshal([5]string{"mpc-node-api/wallet-backup/v1", app, node, wallet, backupKeyID})
	return aad
}

func (n *node) sealMnemonic(app, wallet, mnemonic string) (keystore.MnemonicBackup, error) {
	fingerprint := sha256.Sum256(n.config.WalletBackup.PublicKey)
	backup := keystore.MnemonicBackup{Version: 1, KeyID: hex.EncodeToString(fingerprint[:])}
	var key [32]byte
	rand.Read(key[:])
	defer clear(key[:])
	var err error
	backup.WrappedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, n.walletBackup, key[:], nil)
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
