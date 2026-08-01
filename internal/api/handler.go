// Package api exposes read-only JSON endpoints for dashboards and automation.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

const maxWindowDays = 3650

// Store is the storage surface used by the query API.
type Store interface {
	Ping(context.Context) error
	QueryPermissionUsage(context.Context, storage.UsageQuery) ([]storage.PermissionUsage, error)
	GetCollectorCoverage(context.Context, time.Time) (storage.CollectorCoverage, error)
	LatestIAMSnapshot(context.Context, string) (storage.IAMSnapshot, bool, error)
}

var _ Store = (*storage.DB)(nil)

// Config supplies query defaults when request parameters are omitted.
type Config struct {
	DefaultTenantID    string
	DefaultAccountID   string
	DefaultWindowDays  int
	MinObservationDays int
	AuthToken          string
}

type handler struct {
	store    Store
	metrics  *metrics.Metrics
	logger   *slog.Logger
	defaults Config
}

// NewHandler returns the API routes. HTTP server timeouts are the caller's responsibility.
func NewHandler(store Store, m *metrics.Metrics, logger *slog.Logger, defaults Config) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{store: store, metrics: m, logger: logger, defaults: defaults}

	mux := http.NewServeMux()
	mux.Handle("/healthz", getOnly(http.HandlerFunc(h.health)))
	mux.Handle("/metrics", bearerAuth(h.defaults.AuthToken, getOnly(h.metricsHandler())))
	mux.Handle("/api/v1/usage", bearerAuth(h.defaults.AuthToken, getOnly(http.HandlerFunc(h.usage))))
	mux.Handle("/api/v1/inventory", bearerAuth(h.defaults.AuthToken, getOnly(http.HandlerFunc(h.inventory))))
	mux.Handle("/api/v1/analysis", bearerAuth(h.defaults.AuthToken, getOnly(http.HandlerFunc(h.analysis))))
	return mux
}

func bearerAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, supplied, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="shinkai-api"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) metricsHandler() http.Handler {
	if h.metrics != nil {
		return h.metrics.Handler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusServiceUnavailable, "metrics unavailable")
	})
}

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Ping(r.Context()); err != nil {
		h.logger.Error("API health check failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

type permissionUsage struct {
	RoleARN          string    `json:"role_arn"`
	IAMAction        string    `json:"iam_action"`
	SuccessfulEvents uint64    `json:"successful_events"`
	DeniedEvents     uint64    `json:"denied_events"`
	FailedEvents     uint64    `json:"failed_events"`
	FirstSuccess     time.Time `json:"first_success"`
	LastSuccess      time.Time `json:"last_success"`
}

type usageResponse struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Since       time.Time         `json:"since"`
	Until       time.Time         `json:"until"`
	Usage       []permissionUsage `json:"usage"`
}

func (h *handler) usage(w http.ResponseWriter, r *http.Request) {
	query, errMessage, internal := h.usageQuery(r)
	if errMessage != "" {
		if internal {
			h.logger.Error("invalid API default configuration", "error", errMessage)
			writeError(w, http.StatusInternalServerError, "internal server error")
		} else {
			writeError(w, http.StatusBadRequest, errMessage)
		}
		return
	}

	rows, err := h.store.QueryPermissionUsage(r.Context(), query)
	if err != nil {
		h.logger.Error("API usage query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	usage := make([]permissionUsage, 0, len(rows))
	for _, row := range rows {
		usage = append(usage, permissionUsage{
			RoleARN:          row.RoleARN,
			IAMAction:        row.IAMAction,
			SuccessfulEvents: row.SuccessfulEvents,
			DeniedEvents:     row.DeniedEvents,
			FailedEvents:     row.FailedEvents,
			FirstSuccess:     row.FirstSuccess,
			LastSuccess:      row.LastSuccess,
		})
	}
	writeJSON(w, http.StatusOK, usageResponse{
		GeneratedAt: time.Now().UTC(),
		Since:       query.Since,
		Until:       query.Until,
		Usage:       usage,
	})
}

func (h *handler) usageQuery(r *http.Request) (storage.UsageQuery, string, bool) {
	values := r.URL.Query()
	until := time.Now().UTC()
	if raw := strings.TrimSpace(values.Get("until")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return storage.UsageQuery{}, "until must be an RFC3339 timestamp", false
		}
		until = parsed
	}

	var since time.Time
	if raw := strings.TrimSpace(values.Get("since")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return storage.UsageQuery{}, "since must be an RFC3339 timestamp", false
		}
		since = parsed
	} else {
		if h.defaults.DefaultWindowDays <= 0 || h.defaults.DefaultWindowDays > maxWindowDays {
			return storage.UsageQuery{}, "DefaultWindowDays must be between 1 and 3650", true
		}
		since = until.AddDate(0, 0, -h.defaults.DefaultWindowDays)
	}
	if !since.Before(until) {
		return storage.UsageQuery{}, "since must be before until", false
	}

	return storage.UsageQuery{
		TenantID:    valueOrDefault(values.Get("tenant_id"), h.defaults.DefaultTenantID),
		AccountID:   valueOrDefault(values.Get("account_id"), h.defaults.DefaultAccountID),
		RoleARN:     strings.TrimSpace(values.Get("role_arn")),
		Workload:    strings.TrimSpace(values.Get("workload")),
		Environment: strings.TrimSpace(values.Get("environment")),
		Since:       since,
		Until:       until,
	}, "", false
}

type iamSnapshot struct {
	SnapshotID  string    `json:"snapshot_id"`
	AccountID   string    `json:"account_id"`
	CollectedAt time.Time `json:"collected_at"`
	Roles       []iamRole `json:"roles"`
}

type iamRole struct {
	RoleARN    string               `json:"role_arn"`
	RoleName   string               `json:"role_name"`
	RoleID     string               `json:"role_id"`
	Path       string               `json:"path"`
	Statements []iamPolicyStatement `json:"statements"`
}

type iamPolicyStatement struct {
	Origin          string   `json:"origin"`
	PolicyARN       string   `json:"policy_arn"`
	PolicyName      string   `json:"policy_name"`
	PolicyVersionID string   `json:"policy_version_id"`
	StatementID     string   `json:"statement_id"`
	Effect          string   `json:"effect"`
	Actions         []string `json:"actions"`
	NotActions      []string `json:"not_actions"`
	Resources       []string `json:"resources"`
	NotResources    []string `json:"not_resources"`
	ConditionJSON   string   `json:"condition_json"`
	RawDocument     string   `json:"raw_document"`
}

func (h *handler) inventory(w http.ResponseWriter, r *http.Request) {
	accountID := valueOrDefault(r.URL.Query().Get("account_id"), h.defaults.DefaultAccountID)
	if accountID == "" {
		writeError(w, http.StatusBadRequest, "account_id is required")
		return
	}

	snapshot, found, err := h.store.LatestIAMSnapshot(r.Context(), accountID)
	if err != nil {
		h.logger.Error("API inventory query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "inventory not found")
		return
	}
	writeJSON(w, http.StatusOK, snapshotJSON(snapshot))
}

type actionUsage struct {
	Action           string    `json:"action"`
	SuccessfulEvents uint64    `json:"successful_events"`
	DeniedEvents     uint64    `json:"denied_events"`
	FailedEvents     uint64    `json:"failed_events"`
	FirstSuccess     time.Time `json:"first_success"`
	LastSuccess      time.Time `json:"last_success"`
}

type analysisResult struct {
	AccountID        string        `json:"account_id"`
	IAMRole          string        `json:"iam_role"`
	Assigned         []string      `json:"assigned"`
	Used             []string      `json:"used"`
	Unused           []string      `json:"unused"`
	Unresolved       []string      `json:"unresolved"`
	Warnings         []string      `json:"warnings"`
	Usage            []actionUsage `json:"usage"`
	ObservationStart time.Time     `json:"observation_start"`
	AnalyzedAt       time.Time     `json:"analyzed_at"`
	RiskLevel        string        `json:"risk_level"`
}

type analysisResponse struct {
	SnapshotID       string           `json:"snapshot_id"`
	GeneratedAt      time.Time        `json:"generated_at"`
	ObservationStart time.Time        `json:"observation_start"`
	Results          []analysisResult `json:"results"`
}

func (h *handler) analysis(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	accountID := valueOrDefault(values.Get("account_id"), h.defaults.DefaultAccountID)
	if accountID == "" {
		writeError(w, http.StatusBadRequest, "account_id is required")
		return
	}
	tenantID := valueOrDefault(values.Get("tenant_id"), h.defaults.DefaultTenantID)
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	windowDays, fromRequest, errMessage := h.windowDays(values.Get("window_days"))
	if errMessage != "" {
		if fromRequest {
			writeError(w, http.StatusBadRequest, errMessage)
		} else {
			h.logger.Error("invalid API default configuration", "error", errMessage)
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	snapshot, found, err := h.store.LatestIAMSnapshot(r.Context(), accountID)
	if err != nil {
		h.logger.Error("API analysis inventory query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "inventory not found")
		return
	}

	engine := correlation.NewEngine(h.store, tenantID, accountID, windowDays, h.defaults.MinObservationDays, h.logger, h.metrics)
	results, err := engine.Run(r.Context(), snapshot)
	if err != nil {
		h.logger.Error("API correlation analysis failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	generatedAt := time.Now().UTC()
	observationStart := generatedAt.AddDate(0, 0, -windowDays)
	if len(results) > 0 {
		generatedAt = results[0].AnalyzedAt
		observationStart = results[0].ObservationStart
	}
	writeJSON(w, http.StatusOK, analysisResponse{
		SnapshotID:       snapshot.SnapshotID,
		GeneratedAt:      generatedAt,
		ObservationStart: observationStart,
		Results:          analysisResultsJSON(results),
	})
}

func (h *handler) windowDays(raw string) (days int, fromRequest bool, errMessage string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		days = h.defaults.DefaultWindowDays
	} else {
		fromRequest = true
		var err error
		days, err = strconv.Atoi(raw)
		if err != nil {
			return 0, true, "window_days must be an integer between 1 and 3650"
		}
	}
	if days <= 0 || days > maxWindowDays {
		return 0, fromRequest, "window_days must be between 1 and 3650"
	}
	return days, fromRequest, ""
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func snapshotJSON(snapshot storage.IAMSnapshot) iamSnapshot {
	result := iamSnapshot{
		SnapshotID:  snapshot.SnapshotID,
		AccountID:   snapshot.AccountID,
		CollectedAt: snapshot.CollectedAt,
		Roles:       make([]iamRole, 0, len(snapshot.Roles)),
	}
	for _, role := range snapshot.Roles {
		item := iamRole{
			RoleARN:    role.RoleARN,
			RoleName:   role.RoleName,
			RoleID:     role.RoleID,
			Path:       role.Path,
			Statements: make([]iamPolicyStatement, 0, len(role.Statements)),
		}
		for _, statement := range role.Statements {
			item.Statements = append(item.Statements, iamPolicyStatement{
				Origin:          statement.Origin,
				PolicyARN:       statement.PolicyARN,
				PolicyName:      statement.PolicyName,
				PolicyVersionID: statement.PolicyVersionID,
				StatementID:     statement.StatementID,
				Effect:          statement.Effect,
				Actions:         nonNilStrings(statement.Actions),
				NotActions:      nonNilStrings(statement.NotActions),
				Resources:       nonNilStrings(statement.Resources),
				NotResources:    nonNilStrings(statement.NotResources),
				ConditionJSON:   statement.ConditionJSON,
				RawDocument:     statement.RawDocument,
			})
		}
		result.Roles = append(result.Roles, item)
	}
	return result
}

func analysisResultsJSON(results []correlation.Result) []analysisResult {
	response := make([]analysisResult, 0, len(results))
	for _, result := range results {
		item := analysisResult{
			AccountID:        result.AccountID,
			IAMRole:          result.IAMRole,
			Assigned:         nonNilStrings(result.Assigned),
			Used:             nonNilStrings(result.Used),
			Unused:           nonNilStrings(result.Unused),
			Unresolved:       nonNilStrings(result.Unresolved),
			Warnings:         nonNilStrings(result.Warnings),
			Usage:            make([]actionUsage, 0, len(result.Usage)),
			ObservationStart: result.ObservationStart,
			AnalyzedAt:       result.AnalyzedAt,
			RiskLevel:        result.RiskLevel,
		}
		for _, usage := range result.Usage {
			item.Usage = append(item.Usage, actionUsage{
				Action:           usage.Action,
				SuccessfulEvents: usage.SuccessfulEvents,
				DeniedEvents:     usage.DeniedEvents,
				FailedEvents:     usage.FailedEvents,
				FirstSuccess:     usage.FirstSuccess,
				LastSuccess:      usage.LastSuccess,
			})
		}
		response = append(response, item)
	}
	return response
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
