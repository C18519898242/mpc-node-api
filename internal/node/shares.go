package node

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func (n *node) loadECDSAShare(ctx context.Context, keyID string, path []uint32) (*cmp.Config, error) {
	data, err := n.keys.Load(ctx, applicationID(ctx), "ecdsa", keyID)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	share, err := n.decodeCMPShare(data)
	if err != nil {
		return nil, err
	}
	return deriveECDSAShare(share, path)
}

func deriveECDSAShare(share *cmp.Config, path []uint32) (*cmp.Config, error) {
	for _, index := range path {
		if index >= 1<<31 {
			return nil, errInvalidChainPath
		}
		child, err := share.DeriveBIP32(index)
		if err != nil {
			return nil, errInvalidChainPath
		}
		share = child
	}
	return share, nil
}

func (n *node) loadKeygenStatus(appID, id string) (keygenStatus, error) {
	data, err := os.ReadFile(n.sharePath(appID, id))
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(n.sharePath(appID, id) + ".started"); markerErr == nil {
			return keygenStatus{SessionID: id, State: "failed"}, nil
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return keygenStatus{}, markerErr
		}
	}
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	config, err := n.decodeCMPShare(data)
	if err != nil {
		return keygenStatus{}, err
	}
	return completedStatus(id, config)
}

func (n *node) decodeCMPShare(data []byte) (*cmp.Config, error) {
	config := cmp.EmptyConfig(curve.Secp256k1{})
	if err := config.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	if config.ID != n.config.PartyID {
		return nil, errors.New("stored share belongs to a different node")
	}
	return config, nil
}

func (n *node) sharePath(appID, id string) string {
	dir := n.config.DataDir
	if appID != defaultApplication {
		dir = filepath.Join(dir, "applications", hex.EncodeToString([]byte(appID)))
	}
	return filepath.Join(dir, "cmp-"+id+".share")
}

func (n *node) recordKeygenAttempt(appID, id string) error {
	path := n.sharePath(appID, id)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path+".started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return file.Close()
}

func (n *node) saveShare(appID, id string, config *cmp.Config) (keygenStatus, error) {
	status, err := completedStatus(id, config)
	if err != nil {
		return keygenStatus{}, err
	}
	data, err := config.MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	file, err := os.CreateTemp(filepath.Dir(n.sharePath(appID, id)), ".share-*")
	if err != nil {
		return keygenStatus{}, err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return keygenStatus{}, err
	}
	return status, os.Rename(file.Name(), n.sharePath(appID, id))
}

func completedStatus(id string, config *cmp.Config) (keygenStatus, error) {
	publicKey, err := config.PublicPoint().MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	return keygenStatus{SessionID: id, State: "succeeded", PublicKey: hex.EncodeToString(publicKey)}, nil
}
