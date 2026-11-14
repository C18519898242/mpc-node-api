package node

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func (n *node) loadKeygenStatus(id string) (keygenStatus, error) {
	data, err := os.ReadFile(n.sharePath(id))
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(n.sharePath(id) + ".started"); markerErr == nil {
			return keygenStatus{SessionID: id, State: "failed"}, nil
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return keygenStatus{}, markerErr
		}
	}
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	config := cmp.EmptyConfig(curve.Secp256k1{})
	if err := config.UnmarshalBinary(data); err != nil {
		return keygenStatus{}, err
	}
	if config.ID != n.config.PartyID {
		return keygenStatus{}, errors.New("stored share belongs to a different node")
	}
	return completedStatus(id, config)
}

func (n *node) sharePath(id string) string {
	return filepath.Join(n.config.DataDir, "cmp-"+id+".share")
}

func (n *node) recordKeygenAttempt(id string) error {
	file, err := os.OpenFile(n.sharePath(id)+".started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return file.Close()
}

func (n *node) saveShare(id string, config *cmp.Config) (keygenStatus, error) {
	status, err := completedStatus(id, config)
	if err != nil {
		return keygenStatus{}, err
	}
	data, err := config.MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	file, err := os.CreateTemp(n.config.DataDir, ".share-*")
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
	return status, os.Rename(file.Name(), n.sharePath(id))
}

func completedStatus(id string, config *cmp.Config) (keygenStatus, error) {
	publicKey, err := config.PublicPoint().MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	return keygenStatus{SessionID: id, State: "succeeded", PublicKey: hex.EncodeToString(publicKey)}, nil
}
