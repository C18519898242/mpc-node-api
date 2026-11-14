package node

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

// ServeHealth runs the health-only HTTP server.
func ServeHealth(addr string) error {
	log.Printf("mpc-node-api listening on %s", addr)
	return httpServer(addr, healthMux()).ListenAndServe()
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

// Serve runs the REST and peer listeners for a single node.
func Serve(cfg config.Config) error {
	n := newNode(cfg)
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

	serveErrors := make(chan error, 2)
	restServer := httpServer(n.config.RESTAddr, n.restHandler())
	restServer.WriteTimeout = keygenTimeout + restServer.ReadTimeout + 5*time.Second
	go func() { serveErrors <- restServer.Serve(rest) }()
	go func() { serveErrors <- httpServer(n.config.MPCAddr, n.peerHandler()).Serve(mpc) }()
	log.Printf("node %s listening on REST %s and MPC %s", n.config.PartyID, rest.Addr(), mpc.Addr())
	return <-serveErrors
}
