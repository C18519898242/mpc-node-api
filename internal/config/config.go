package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Config struct {
	PartyID            party.ID            `json:"partyId"`
	RESTAddr           string              `json:"restAddr"`
	MPCAddr            string              `json:"mpcAddr"`
	DataDir            string              `json:"dataDir"`
	Peers              map[party.ID]string `json:"peers"`
	LegacyFROSTPlayers []party.ID          `json:"legacyFrostPlayers,omitempty"`
	MPCTLS             *MPCTLSConfig       `json:"mpcTLS,omitempty"`
}

type MPCTLSConfig struct {
	CAFile   string `json:"caFile"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Load reads and validates a local node configuration.
func Load(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decode %s: %w", path, err)
	}
	if !validPartyID(cfg.PartyID) || cfg.DataDir == "" || len(cfg.Peers) == 0 {
		return cfg, fmt.Errorf("%s: expected partyId, dataDir and at least one peer", path)
	}

	addrs := []string{cfg.RESTAddr, cfg.MPCAddr}
	for id, addr := range cfg.Peers {
		if !validPartyID(id) || id == cfg.PartyID {
			return cfg, fmt.Errorf("%s: invalid peer ID %q", path, id)
		}
		addrs = append(addrs, addr)
	}
	if cfg.LegacyFROSTPlayers != nil {
		seenPlayers := make(map[party.ID]bool)
		for _, id := range cfg.LegacyFROSTPlayers {
			if !validPartyID(id) || seenPlayers[id] {
				return cfg, fmt.Errorf("%s: invalid legacyFrostPlayers", path)
			}
			seenPlayers[id] = true
		}
		if len(seenPlayers) < 2 || !seenPlayers[cfg.PartyID] {
			return cfg, fmt.Errorf("%s: legacyFrostPlayers must include this node and another player", path)
		}
	}
	seen := make(map[netip.AddrPort]bool, len(addrs))
	for i, raw := range addrs {
		addr, err := netip.ParseAddrPort(raw)
		if err != nil || addr.Port() == 0 || seen[addr] || (i >= 2 && addr.Addr().IsUnspecified()) {
			return cfg, fmt.Errorf("%s: invalid or duplicate address %q", path, raw)
		}
		if (i == 0 || cfg.MPCTLS == nil) && !addr.Addr().IsLoopback() {
			return cfg, fmt.Errorf("%s: plaintext listeners and peers must use loopback addresses, got %q", path, raw)
		}
		seen[addr] = true
	}
	if cfg.MPCTLS != nil {
		for _, file := range []*string{&cfg.MPCTLS.CAFile, &cfg.MPCTLS.CertFile, &cfg.MPCTLS.KeyFile} {
			if *file == "" {
				return cfg, fmt.Errorf("%s: mpcTLS requires caFile, certFile and keyFile", path)
			}
			if !filepath.IsAbs(*file) {
				*file = filepath.Join(filepath.Dir(path), *file)
			}
		}
	}
	if !filepath.IsAbs(cfg.DataDir) {
		cfg.DataDir = filepath.Join(filepath.Dir(path), cfg.DataDir)
	}
	return cfg, os.MkdirAll(cfg.DataDir, 0700)
}

func validPartyID(id party.ID) bool {
	// CMP treats an ID as a big-endian number. Reject noncanonical encodings.
	return len(id) > 0 && len(id) <= 32 && id[0] != 0
}
