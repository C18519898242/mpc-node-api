package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type nodeConfig struct {
	PartyID  party.ID            `json:"partyId"`
	RESTAddr string              `json:"restAddr"`
	MPCAddr  string              `json:"mpcAddr"`
	DataDir  string              `json:"dataDir"`
	Peers    map[party.ID]string `json:"peers"`
}

func loadNodeConfig(path string) (nodeConfig, error) {
	var cfg nodeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decode %s: %w", path, err)
	}
	if cfg.PartyID == "" || cfg.DataDir == "" || len(cfg.Peers) != 2 {
		return cfg, fmt.Errorf("%s: expected partyId, dataDir and exactly two peers", path)
	}

	addrs := []string{cfg.RESTAddr, cfg.MPCAddr}
	for id, addr := range cfg.Peers {
		if id == "" || id == cfg.PartyID {
			return cfg, fmt.Errorf("%s: invalid peer ID %q", path, id)
		}
		addrs = append(addrs, addr)
	}
	seen := make(map[netip.AddrPort]bool, len(addrs))
	for _, raw := range addrs {
		addr, err := netip.ParseAddrPort(raw)
		if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 || seen[addr] {
			return cfg, fmt.Errorf("%s: expected distinct loopback addresses, got %q", path, raw)
		}
		seen[addr] = true
	}
	if !filepath.IsAbs(cfg.DataDir) {
		cfg.DataDir = filepath.Join(filepath.Dir(path), cfg.DataDir)
	}
	return cfg, os.MkdirAll(cfg.DataDir, 0700)
}
