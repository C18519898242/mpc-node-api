package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("MPC_NODE_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mpc-node-api listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	return mux
}
