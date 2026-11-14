package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/node"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	configPath := flag.String("config", "", "path to a local MPC node JSON config")
	flag.Parse()
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			slog.Error("startup failed", "stage", "config")
			os.Exit(1)
		}
		if err := node.Serve(cfg); err != nil {
			slog.Error("node stopped", "node_id", string(cfg.PartyID), "result", "failed")
			os.Exit(1)
		}
		return
	}

	addr := os.Getenv("MPC_NODE_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	if err := node.ServeHealth(addr); err != nil {
		slog.Error("health server stopped", "result", "failed")
		os.Exit(1)
	}
}
