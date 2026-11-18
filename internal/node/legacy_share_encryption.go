package node

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	legacyShareHeader  = "\x00MPCSHARE\x01"
	legacySharePurpose = "legacy-file"
)

func (n *node) sealLegacyShare(appID, id string, share []byte) ([]byte, error) {
	ciphertext, err := n.shareCipher.Seal(legacySharePurpose, appID, "ecdsa", id, share)
	if err != nil {
		return nil, err
	}
	return append([]byte(legacyShareHeader), ciphertext...), nil
}

func (n *node) openLegacyShare(appID, id string, data []byte) ([]byte, error) {
	payload, ok := bytes.CutPrefix(data, []byte(legacyShareHeader))
	if !ok {
		return nil, errors.New("invalid legacy share encryption header")
	}
	return n.shareCipher.Open(legacySharePurpose, appID, "ecdsa", id, payload)
}

func (n *node) encryptLegacyShares() error {
	if err := n.encryptLegacyShareDir(n.config.DataDir, defaultApplication); err != nil {
		return err
	}
	root := filepath.Join(n.config.DataDir, "applications")
	dirs, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		id, err := hex.DecodeString(dir.Name())
		if !dir.IsDir() || err != nil || !applicationIDPattern.Match(id) || string(id) == defaultApplication {
			continue
		}
		if err := n.encryptLegacyShareDir(filepath.Join(root, dir.Name()), string(id)); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) encryptLegacyShareDir(dir, appID string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		id, found := strings.CutPrefix(file.Name(), "cmp-")
		id, share := strings.CutSuffix(id, ".share")
		if !file.Type().IsRegular() || !found || !share || !sessionIDPattern.MatchString(id) {
			continue
		}
		path := filepath.Join(dir, file.Name())
		if err := n.encryptLegacyShareFile(path, appID, id); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) encryptLegacyShareFile(path, appID, id string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	if bytes.HasPrefix(data, []byte(legacyShareHeader)) {
		return nil
	}
	if _, err := n.decodeCMPShare(data); err != nil {
		return err
	}
	ciphertext, err := n.sealLegacyShare(appID, id, data)
	if err != nil {
		return err
	}
	return writeShareFile(path, ciphertext)
}
