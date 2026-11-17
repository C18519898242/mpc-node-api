package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/peertls"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func main() {
	out := flag.String("out", "certs/mpc-dev", "new directory for development certificates")
	flag.Parse()
	if err := generate(*out, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Generated MPC development certificates in %s\n", *out)
}

func generate(out string, paths []string) error {
	if len(paths) < 2 {
		return errors.New("provide at least two node config files")
	}
	configs := make([]config.Config, 0, len(paths))
	players := make([]party.ID, 0, len(paths))
	seen := make(map[party.ID]bool)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var cfg config.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if cfg.PartyID == "" || len(cfg.PartyID) > 32 || cfg.PartyID[0] == 0 || seen[cfg.PartyID] {
			return fmt.Errorf("%s: expected a distinct valid partyId", path)
		}
		seen[cfg.PartyID] = true
		configs = append(configs, cfg)
		players = append(players, cfg.PartyID)
	}
	for _, cfg := range configs {
		for peer := range cfg.Peers {
			if !seen[peer] || peer == cfg.PartyID {
				return fmt.Errorf("node %q references peer %q without a matching peer config", cfg.PartyID, peer)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	return peertls.GenerateDevDirectory(out, players)
}
