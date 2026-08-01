package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	testTenant  = "tenant-default"
	testAccount = "123456789012"
)

type fakeStore struct {
	pingErr     error
	usage       []storage.PermissionUsage
	usageErr    error
	usageQuery  storage.UsageQuery
	snapshot    storage.IAMSnapshot
	snapshotOK  bool
	snapshotErr error
	accountID   string
	coverage    storage.CollectorCoverage
	coverageErr error
}

func (f *fakeStore) Ping(context.Context) error {
	return f.pingErr
}

func (f *fakeStore) QueryPermissionUsage(_ context.Context, query storage.UsageQuery) ([]storage.PermissionUsage, error) {
	f.usageQuery = query
	return append([]storage.PermissionUsage(nil), f.usage...), f.usageErr
}

func (f *fakeStore) GetCollectorCoverage(context.Context, time.Time) (storage.CollectorCoverage, error) {
	if f.coverage.FirstHeartbeat.IsZero() {
		f.coverage.FirstHeartbeat = time.Now().Add(-30 * 24 * time.Hour)
		f.coverage.LastHeartbeat = time.Now()
	}
	return f.coverage, f.coverageErr
}

func (f *fakeStore) LatestIAMSnapshot(_ context.Context, accountID string) (storage.IAMSnapshot, bool, error) {
	f.accountID = accountID
	return f.snapshot, f.snapshotOK, f.snapshotErr
}

func testHandler(store *fakeStore, defaults Config) http.Handler {
	registry := prometheus.NewRegistry()
	m := metrics.NewWithRegistry(registry)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(store, m, logger, defaults)
}

func request(t *testing.T, handler http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder
}

func TestUsageDefaults(t *testing.T) {
	store := &fakeStore{}
	handler := testHandler(store, Config{
		DefaultTenantID:   testTenant,
		DefaultAccountID:  testAccount,
		DefaultWindowDays: 7,
	})

	response := request(t, handler, http.MethodGet, "/api/v1/usage")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if store.usageQuery.TenantID != testTenant || store.usageQuery.AccountID != testAccount {
		t.Fatalf("query scope = %#v", store.usageQuery)
	}
	if got := store.usageQuery.Until.Sub(store.usageQuery.Since); got != 7*24*time.Hour {
		t.Fatalf("default window = %s, want 168h", got)
	}

	var body usageResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Usage == nil {
		t.Fatal("usage is null, want an empty array")
	}
	if !body.Since.Equal(store.usageQuery.Since) || !body.Until.Equal(store.usageQuery.Until) {
		t.Fatalf("response window = %s to %s, query = %#v", body.Since, body.Until, store.usageQuery)
	}
}

func TestUsageFiltersAndTimes(t *testing.T) {
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	until := since.Add(48 * time.Hour)
	store := &fakeStore{usage: []storage.PermissionUsage{{
		RoleARN:          "arn:aws:iam::999999999999:role/app",
		IAMAction:        "s3:GetObject",
		SuccessfulEvents: 4,
	}}}
	handler := testHandler(store, Config{DefaultWindowDays: 30})
	target := "/api/v1/usage?tenant_id=tenant-x&account_id=999999999999" +
		"&role_arn=role-x&workload=checkout&environment=prod" +
		"&since=" + since.Format(time.RFC3339) + "&until=" + until.Format(time.RFC3339)

	response := request(t, handler, http.MethodGet, target)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	want := storage.UsageQuery{
		TenantID: "tenant-x", AccountID: "999999999999", RoleARN: "role-x",
		Workload: "checkout", Environment: "prod", Since: since, Until: until,
	}
	if store.usageQuery != want {
		t.Fatalf("query = %#v, want %#v", store.usageQuery, want)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body["usage"], &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["iam_action"] != "s3:GetObject" || rows[0]["successful_events"] != float64(4) {
		t.Fatalf("usage = %#v", rows)
	}
}

func TestInventoryDefaultAndNotFound(t *testing.T) {
	snapshot := storage.IAMSnapshot{
		SnapshotID: "snapshot-1", AccountID: testAccount,
		CollectedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Roles: []storage.IAMRole{{
			RoleARN: "arn:aws:iam::123456789012:role/app", RoleName: "app",
			Statements: []storage.IAMPolicyStatement{{Effect: "Allow", Actions: []string{"s3:GetObject"}}},
		}},
	}
	store := &fakeStore{snapshot: snapshot, snapshotOK: true}
	handler := testHandler(store, Config{DefaultAccountID: testAccount, DefaultWindowDays: 30})

	response := request(t, handler, http.MethodGet, "/api/v1/inventory")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if store.accountID != testAccount {
		t.Fatalf("account = %q", store.accountID)
	}
	var body iamSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SnapshotID != snapshot.SnapshotID || len(body.Roles) != 1 || len(body.Roles[0].Statements) != 1 {
		t.Fatalf("inventory = %#v", body)
	}

	store.snapshotOK = false
	response = request(t, handler, http.MethodGet, "/api/v1/inventory")
	if response.Code != http.StatusNotFound {
		t.Fatalf("not-found status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestAnalysis(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/app"
	store := &fakeStore{
		snapshotOK: true,
		snapshot: storage.IAMSnapshot{
			SnapshotID: "snapshot-analysis", AccountID: testAccount,
			Roles: []storage.IAMRole{{
				RoleARN: roleARN,
				Statements: []storage.IAMPolicyStatement{{
					Origin: storage.IAMStatementOriginManaged, Effect: "Allow",
					Actions: []string{"s3:GetObject", "s3:PutObject"},
				}},
			}},
		},
		usage: []storage.PermissionUsage{{
			RoleARN: roleARN, IAMAction: "s3:GetObject", SuccessfulEvents: 2,
		}},
	}
	handler := testHandler(store, Config{
		DefaultTenantID: testTenant, DefaultAccountID: testAccount, DefaultWindowDays: 90,
	})

	response := request(t, handler, http.MethodGet, "/api/v1/analysis?window_days=30")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if store.accountID != testAccount || store.usageQuery.TenantID != testTenant || store.usageQuery.AccountID != testAccount {
		t.Fatalf("analysis scope: inventory=%q usage=%#v", store.accountID, store.usageQuery)
	}
	if got := store.usageQuery.Until.Sub(store.usageQuery.Since); got != 30*24*time.Hour {
		t.Fatalf("analysis window = %s", got)
	}

	var body analysisResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SnapshotID != "snapshot-analysis" || len(body.Results) != 1 {
		t.Fatalf("analysis = %#v", body)
	}
	if len(body.Results[0].Used) != 1 || body.Results[0].Used[0] != "s3:GetObject" {
		t.Fatalf("used = %#v", body.Results[0].Used)
	}
	if len(body.Results[0].Unused) != 1 || body.Results[0].Unused[0] != "s3:PutObject" {
		t.Fatalf("unused = %#v", body.Results[0].Unused)
	}
	if !body.ObservationStart.Equal(store.usageQuery.Since) {
		t.Fatalf("observation_start = %s, query since = %s", body.ObservationStart, store.usageQuery.Since)
	}
}

func TestHealth(t *testing.T) {
	store := &fakeStore{}
	handler := testHandler(store, Config{DefaultWindowDays: 30})

	response := request(t, handler, http.MethodGet, "/healthz")
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("healthy response: status=%d body=%s", response.Code, response.Body.String())
	}

	store.pingErr = errors.New("password=secret database unavailable")
	response = request(t, handler, http.MethodGet, "/healthz")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("health response leaked error: %s", response.Body.String())
	}
}

func TestMethods(t *testing.T) {
	handler := testHandler(&fakeStore{}, Config{DefaultWindowDays: 30})
	paths := []string{"/healthz", "/metrics", "/api/v1/usage", "/api/v1/inventory", "/api/v1/analysis"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			response := request(t, handler, http.MethodPost, path)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d", response.Code)
			}
			if allow := response.Header().Get("Allow"); allow != http.MethodGet {
				t.Fatalf("Allow = %q", allow)
			}
			if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
				t.Fatalf("Content-Type = %q", contentType)
			}
		})
	}
}

func TestBearerAuthentication(t *testing.T) {
	handler := testHandler(&fakeStore{}, Config{
		DefaultTenantID:   testTenant,
		DefaultAccountID:  testAccount,
		DefaultWindowDays: 30,
		AuthToken:         "test-secret",
	})

	response := request(t, handler, http.MethodGet, "/api/v1/usage")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/usage", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want %d", recorder.Code, http.StatusOK)
	}

	response = request(t, handler, http.MethodGet, "/healthz")
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestMalformedParameters(t *testing.T) {
	defaults := Config{DefaultTenantID: testTenant, DefaultAccountID: testAccount, DefaultWindowDays: 30}
	tests := []string{
		"/api/v1/usage?since=not-a-time",
		"/api/v1/usage?until=not-a-time",
		"/api/v1/usage?since=2026-02-01T00:00:00Z&until=2026-01-01T00:00:00Z",
		"/api/v1/analysis?window_days=nope",
		"/api/v1/analysis?window_days=0",
		"/api/v1/analysis?window_days=3651",
	}
	handler := testHandler(&fakeStore{}, defaults)
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			response := request(t, handler, http.MethodGet, target)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}

	missingDefaults := testHandler(&fakeStore{}, Config{DefaultWindowDays: 30})
	for _, target := range []string{"/api/v1/inventory", "/api/v1/analysis?tenant_id=tenant", "/api/v1/analysis?account_id=123"} {
		response := request(t, missingDefaults, http.MethodGet, target)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body = %s", target, response.Code, response.Body.String())
		}
	}
}

func TestInternalErrorsAreGeneric(t *testing.T) {
	store := &fakeStore{usageErr: errors.New("clickhouse password=hunter2")}
	handler := testHandler(store, Config{DefaultWindowDays: 30})
	response := request(t, handler, http.MethodGet, "/api/v1/usage")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "hunter2") {
		t.Fatalf("response leaked storage error: %s", response.Body.String())
	}
}
