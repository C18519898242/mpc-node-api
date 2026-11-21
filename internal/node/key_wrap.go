package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

const keyWrapLabel = "mpc-node-api/key-transfer/v1"

type wrappedKeyShare struct {
	Version    int    `json:"version"`
	WrappedKey []byte `json:"wrappedKey"`
	Ciphertext []byte `json:"ciphertext"`
}

func parseWrappingKey(der []byte) (*rsa.PublicKey, error) {
	value, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := value.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 65537 {
		return nil, errors.New("expected a 2048 to 8192 bit RSA wrapping key")
	}
	return key, nil
}

func wrapKeyShare(key *rsa.PublicKey, data []byte) (wrappedKeyShare, error) {
	secret := make([]byte, 32)
	rand.Read(secret)
	defer clear(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		return wrappedKeyShare{}, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return wrappedKeyShare{}, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, secret, []byte(keyWrapLabel))
	if err != nil {
		return wrappedKeyShare{}, err
	}
	return wrappedKeyShare{Version: 1, WrappedKey: wrapped,
		Ciphertext: aead.Seal(nil, nil, data, []byte(keyWrapLabel))}, nil
}

func unwrapKeyShare(key *rsa.PrivateKey, wrapped wrappedKeyShare) ([]byte, error) {
	if key == nil || wrapped.Version != 1 || len(wrapped.WrappedKey) != key.Size() ||
		len(wrapped.Ciphertext) < 28 || len(wrapped.Ciphertext) > 1<<18 {
		return nil, errors.New("invalid wrapped key share")
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped.WrappedKey, []byte(keyWrapLabel))
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	if len(secret) != 32 {
		return nil, errors.New("invalid content key")
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, wrapped.Ciphertext, []byte(keyWrapLabel))
}

func (n *node) configureKeyTransfer() error {
	cfg := n.config.KeyTransfer
	if cfg == nil {
		return nil
	}
	if cfg.WrappingPrivateKeyFile != "" {
		data, err := os.ReadFile(cfg.WrappingPrivateKeyFile)
		if err != nil {
			return err
		}
		defer clear(data)
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PRIVATE KEY" {
			return errors.New("expected a PKCS8 PEM RSA private key")
		}
		defer clear(block.Bytes)
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		key, ok := value.(*rsa.PrivateKey)
		if !ok || key.Validate() != nil {
			return errors.New("invalid wrapping private key")
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		if _, err := parseWrappingKey(der); err != nil {
			return err
		}
		n.wrappingKey = key
	}
	for _, der := range cfg.ExportWrappingKeys {
		if _, err := parseWrappingKey(der); err != nil {
			return err
		}
	}
	return nil
}
