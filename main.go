package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	configPath := flag.String("config", "", "path to a local MPC node JSON config")
	flag.Parse()
	if *configPath != "" {
		cfg, err := loadNodeConfig(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal(serveNode(newNode(cfg)))
	}

	addr := os.Getenv("MPC_NODE_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	log.Printf("mpc-node-api listening on %s", addr)
	log.Fatal(httpServer(addr, newHandler()).ListenAndServe())
}

func httpServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

func serveNode(n *node) error {
	rest, err := net.Listen("tcp", n.config.RESTAddr)
	if err != nil {
		return err
	}
	defer rest.Close()
	mpc, err := net.Listen("tcp", n.config.MPCAddr)
	if err != nil {
		return err
	}
	defer mpc.Close()

	errors := make(chan error, 2)
	go func() { errors <- httpServer(n.config.RESTAddr, n.restHandler()).Serve(rest) }()
	go func() { errors <- httpServer(n.config.MPCAddr, n.peerHandler()).Serve(mpc) }()
	log.Printf("node %s listening on REST %s and MPC %s", n.config.PartyID, rest.Addr(), mpc.Addr())
	return <-errors
}

func newHandler() http.Handler {
	return healthMux()
}

func healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	return mux
}
