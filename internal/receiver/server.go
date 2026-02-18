package receiver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	tracev1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// maxBodyBytes is the maximum accepted size for an OTLP request body (32 MiB).
const maxBodyBytes = 32 << 20

// Server is the OTLP/HTTP receiver.
type Server struct {
	db      *storage.DB
	log     *slog.Logger
	metrics *metrics.Metrics
	srv     *http.Server
}

// New creates a new receiver Server.
func New(endpoint string, db *storage.DB, log *slog.Logger, m *metrics.Metrics) (*Server, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid OTel endpoint %q: %w", endpoint, err)
	}
	addr := net.JoinHostPort(host, port)

	s := &Server{
		db:      db,
		log:     log,
		metrics: m,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", s.handleTraces)

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,  // abort if headers arrive slowly
		ReadTimeout:       30 * time.Second,  // abort if full request takes too long
		WriteTimeout:      30 * time.Second,  // abort if response takes too long
		IdleTimeout:       120 * time.Second, // close idle keep-alive connections
	}
	return s, nil
}

// Start begins listening and serving. It blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.log.Info("OTLP receiver listening", "addr", s.srv.Addr)

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("receiver: %w", err)
	case <-ctx.Done():
		s.log.Info("shutting down OTLP receiver")
		return s.srv.Shutdown(context.Background())
	}
}

func (s *Server) handleTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader returns a 413-flavoured error on overflow.
		s.log.Debug("failed to read request body", "error", err)
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	req := &tracev1.ExportTraceServiceRequest{}

	ct := r.Header.Get("Content-Type")
	switch {
	case ct == "application/json" || ct == "application/x-protobuf-json":
		if err := protojson.Unmarshal(body, req); err != nil {
			s.log.Debug("failed to parse JSON trace request", "error", err)
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
	default:
		// Treat everything else as binary protobuf (application/x-protobuf).
		if err := proto.Unmarshal(body, req); err != nil {
			s.log.Debug("failed to parse protobuf trace request", "error", err)
			http.Error(w, "invalid protobuf body", http.StatusBadRequest)
			return
		}
	}

	records := parseTraces(req.GetResourceSpans(), s.log, s.metrics)
	if len(records) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := s.db.BatchRecordPrivilegeUsage(r.Context(), records); err != nil {
		s.log.Error("failed to record privilege usage", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.log.Debug("recorded privilege usage from spans", "count", len(records))
	w.WriteHeader(http.StatusOK)
}
