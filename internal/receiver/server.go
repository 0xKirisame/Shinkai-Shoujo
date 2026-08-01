package receiver

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	logsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// maxBodyBytes is the maximum decompressed size of an OTLP request body.
const maxBodyBytes = 32 << 20

type eventStore interface {
	BatchRecordUsageEvents(context.Context, []storage.UsageEvent) error
	RecordCollectorHeartbeat(context.Context, time.Time, uint64, uint64) error
}

// Server is the OTLP/HTTP logs receiver.
type Server struct {
	store         eventStore
	log           *slog.Logger
	metrics       *metrics.Metrics
	roleAttribute string
	authToken     string
	srv           *http.Server
}

// New creates a new receiver Server.
func New(endpoint, roleAttribute, authToken string, store eventStore, log *slog.Logger, m *metrics.Metrics) (*Server, error) {
	addr, err := endpointAddress(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid OTel endpoint %q: %w", endpoint, err)
	}

	s := &Server{
		store:         store,
		log:           log,
		metrics:       m,
		roleAttribute: roleAttribute,
		authToken:     authToken,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", s.handleLogs)

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, nil
}

func endpointAddress(endpoint string) (string, error) {
	addr := endpoint
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return "", err
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "", fmt.Errorf("https is not supported because the receiver has no TLS configuration")
		}
		if !strings.EqualFold(u.Scheme, "http") {
			return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("endpoint URL must contain only a host and port")
		}
		addr = u.Host
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if port == "" {
		return "", fmt.Errorf("missing port")
	}
	return net.JoinHostPort(host, port), nil
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
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err := s.srv.Shutdown(shutdownCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			if closeErr := s.srv.Close(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
		}
		return err
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="otlp"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !supportedMediaType(mediaType) {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	contentEncoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if contentEncoding != "" && contentEncoding != "identity" && contentEncoding != "gzip" {
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	defer r.Body.Close()

	var reader io.Reader = r.Body
	if contentEncoding == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))
	if err != nil {
		s.log.Debug("failed to read request body", "error", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	req := &logsv1.ExportLogsServiceRequest{}
	if err := proto.Unmarshal(body, req); err != nil {
		s.log.Debug("failed to parse protobuf logs request", "error", err)
		http.Error(w, "invalid protobuf body", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	events, received := parseLogs(req.GetResourceLogs(), s.roleAttribute, now, s.log, s.metrics)
	if len(events) != 0 {
		if err := s.store.BatchRecordUsageEvents(r.Context(), events); err != nil {
			s.log.Error("failed to record usage events", "error", err)
			if heartbeatErr := s.store.RecordCollectorHeartbeat(r.Context(), now, received, 0); heartbeatErr != nil {
				s.log.Error("failed to record collector heartbeat", "error", heartbeatErr)
			}
			s.writeUnavailable(w)
			return
		}
	}
	if err := s.store.RecordCollectorHeartbeat(r.Context(), now, received, uint64(len(events))); err != nil {
		s.log.Error("failed to record collector heartbeat", "error", err)
	}

	s.log.Debug("processed usage events from logs", "received", received, "accepted", len(events))
	s.writeOTLPResponse(w, received-uint64(len(events)))
}

func supportedMediaType(mediaType string) bool {
	return mediaType == "application/x-protobuf"
}

func (s *Server) authorized(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) == 1
}

func (s *Server) writeOTLPResponse(w http.ResponseWriter, rejected uint64) {
	response := &logsv1.ExportLogsServiceResponse{}
	if rejected != 0 {
		response.PartialSuccess = &logsv1.ExportLogsPartialSuccess{
			RejectedLogRecords: int64(rejected),
			ErrorMessage:       fmt.Sprintf("%d log record(s) rejected", rejected),
		}
	}
	body, err := proto.Marshal(response)
	if err != nil {
		s.log.Error("failed to marshal OTLP response", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	if len(body) != 0 {
		_, _ = w.Write(body)
	}
}

func (s *Server) writeUnavailable(w http.ResponseWriter) {
	body, err := proto.Marshal(&statuspb.Status{
		Code:    int32(codes.Unavailable),
		Message: "usage event storage is unavailable",
	})
	if err != nil {
		s.log.Error("failed to marshal OTLP error response", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(body)
}
