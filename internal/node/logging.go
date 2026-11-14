package node

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Log only fixed operation labels and safe metadata. Request fields and errors
// from protocol peers or storage must never be forwarded to the logger.
func (n *node) logRequest(operation, algorithm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		response := &statusWriter{ResponseWriter: w}
		next(response, r)
		level, result := slog.LevelInfo, "succeeded"
		switch {
		case response.status >= 500:
			level, result = slog.LevelError, "failed"
		case response.status >= 400:
			level, result = slog.LevelWarn, "rejected"
		case response.status == http.StatusAccepted:
			result = "accepted"
		case response.status == 0 && r.Context().Err() != nil:
			level, result = slog.LevelWarn, "canceled"
		}
		if response.status == 0 && result != "canceled" {
			response.status = http.StatusOK
		}
		n.logger.Log(r.Context(), level, "http operation", "node_id", string(n.config.PartyID),
			"operation", operation, "algorithm", algorithm, "status", response.status,
			"result", result, "duration_ms", time.Since(start).Milliseconds())
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

// net/http can include panic values and stack traces in its diagnostic text.
type httpErrorLog struct{}

func (httpErrorLog) Write(message []byte) (int, error) {
	slog.Error("http server error")
	return len(message), nil
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (n *node) logMPCResult(operation, algorithm, stage string, start time.Time, err error) {
	level, result := slog.LevelInfo, "succeeded"
	if err != nil {
		level, result = slog.LevelError, "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			result = "timeout"
		}
	}
	n.logger.Log(context.Background(), level, "mpc operation", "node_id", string(n.config.PartyID),
		"operation", operation, "algorithm", algorithm, "stage", stage,
		"result", result, "duration_ms", time.Since(start).Milliseconds())
}
