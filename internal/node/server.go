package node

import (
	"log"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

// ServeHealth runs the health-only HTTP server.
func ServeHealth(addr string) error {
	slog.Info("health server starting")
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
		ErrorLog:          log.New(httpErrorLog{}, "", 0),
	}
}

// Serve runs the REST and peer listeners for a single node.
func Serve(cfg config.Config) error {
	n := newNode(cfg)
	keys, err := keystore.OpenNodeSQLite(cfg.DataDir, string(cfg.PartyID))
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "storage")
		return err
	}
	defer keys.Close()
	n.keys = keys
	rest, err := net.Listen("tcp", n.config.RESTAddr)
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "rest_listener")
		return err
	}
	defer rest.Close()
	mpc, err := net.Listen("tcp", n.config.MPCAddr)
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "mpc_listener")
		return err
	}
	defer mpc.Close()

	serveErrors := make(chan error, 2)
	restServer := httpServer(n.config.RESTAddr, n.restHandler())
	restServer.WriteTimeout = keygenTimeout + restServer.ReadTimeout + 5*time.Second
	go func() { serveErrors <- restServer.Serve(rest) }()
	go func() { serveErrors <- httpServer(n.config.MPCAddr, n.peerHandler()).Serve(mpc) }()
	n.logger.Info("node listening", "node_id", string(cfg.PartyID), "rest_port", rest.Addr().(*net.TCPAddr).Port,
		"mpc_port", mpc.Addr().(*net.TCPAddr).Port)
	return <-serveErrors
}
