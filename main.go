package main

import (
	"flag"
	"log"
	"os"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/node"
)

func main() {
	configPath := flag.String("config", "", "path to a local MPC node JSON config")
	flag.Parse()
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal(node.Serve(cfg))
	}

	addr := os.Getenv("MPC_NODE_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	log.Fatal(node.ServeHealth(addr))
}
