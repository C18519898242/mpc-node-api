package node

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	if n.config.DataDir == "" {
		return keygenStatus{}, errors.New("legacy /v1/keygen requires dataDir")
	}
	data, err := os.ReadFile(n.sharePath(appID, id))
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(n.sharePath(appID, id) + ".started"); markerErr == nil {
			return keygenStatus{SessionID: id, State: "failed"}, nil
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return keygenStatus{}, markerErr
		}
		if n.keys != nil {
			used, lookupErr := n.keys.HasSession(context.Background(), appID, "legacy-keygen."+id)
			if lookupErr != nil {
				return keygenStatus{}, lookupErr
			}
			if used {
				return keygenStatus{SessionID: id, State: "failed"}, nil
			}
		}
	}
	if err != nil {
		return keygenStatus{}, err
	}
	defer clear(data)
	if n.shareCipher != nil {
		data, err = n.openLegacyShare(appID, id, data)
		if err != nil {
			return keygenStatus{}, err
		}
		defer clear(data)
	}
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

func (n *node) recordKeygenAttempt(ctx context.Context, appID, id string) error {
	if n.config.DataDir == "" {
		return errors.New("legacy /v1/keygen requires dataDir")
	}
	if n.keys != nil {
		fresh, err := n.keys.ReserveSession(ctx, appID, "legacy-keygen."+id)
		if err != nil {
			return err
		}
		if !fresh {
			return os.ErrExist
		}
		// Share files still live beside the database, including per-application directories.
		return os.MkdirAll(filepath.Dir(n.sharePath(appID, id)), 0700)
	}
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
	if n.shareCipher != nil {
		data, err = n.sealLegacyShare(appID, id, data)
		if err != nil {
			return keygenStatus{}, err
		}
	}
	if err := writeShareFile(n.sharePath(appID, id), data); err != nil {
		return keygenStatus{}, err
	}
	// The share file now makes the attempt self-describing; the marker is no
	// longer needed to distinguish a failed attempt from a completed one.
	_ = os.Remove(n.sharePath(appID, id) + ".started")
	return status, nil
}

const legacyArtifactRetention = 7 * 24 * time.Hour

// Old markers are compacted into durable used-ID records before removal.
// Abandoned temporary files can be removed without affecting replay protection.
func (n *node) cleanupLegacyArtifacts() error {
	cutoff := time.Now().Add(-legacyArtifactRetention)
	if err := n.cleanupLegacyArtifactDir(defaultApplication, n.config.DataDir, cutoff); err != nil {
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
		if err := n.cleanupLegacyArtifactDir(string(id), filepath.Join(root, dir.Name()), cutoff); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) cleanupLegacyArtifactDir(appID, dir string, cutoff time.Time) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		stale := strings.HasPrefix(name, ".share-")
		markerID := ""
		if rest, ok := strings.CutSuffix(name, ".share.started"); ok {
			id, ok := strings.CutPrefix(rest, "cmp-")
			stale = ok && sessionIDPattern.MatchString(id)
			if stale {
				markerID = id
			}
		}
		if !stale {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if markerID != "" {
			if n.keys == nil {
				continue
			}
			if _, err := n.keys.ReserveSession(context.Background(), appID, "legacy-keygen."+markerID); err != nil {
				return err
			}
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeShareFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".share-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func completedStatus(id string, config *cmp.Config) (keygenStatus, error) {
	publicKey, err := config.PublicPoint().MarshalBinary()
	if err != nil {
		return keygenStatus{}, err
	}
	return keygenStatus{SessionID: id, State: "succeeded", PublicKey: hex.EncodeToString(publicKey)}, nil
}
