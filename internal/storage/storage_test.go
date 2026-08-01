package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func TestNormalizeOptionsDefaults(t *testing.T) {
	opts, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatalf("normalizeOptions() error: %v", err)
	}
	if !reflect.DeepEqual(opts.Addresses, []string{defaultAddress}) {
		t.Errorf("addresses = %v, want [%q]", opts.Addresses, defaultAddress)
	}
	if opts.Database != defaultDatabase {
		t.Errorf("database = %q, want %q", opts.Database, defaultDatabase)
	}
	if opts.Username != "default" {
		t.Errorf("username = %q, want default", opts.Username)
	}
	if opts.DialTimeout != defaultDialTimeout {
		t.Errorf("dial timeout = %v, want %v", opts.DialTimeout, defaultDialTimeout)
	}
	if opts.RetentionDays != defaultRetentionDays {
		t.Errorf("retention days = %d, want %d", opts.RetentionDays, defaultRetentionDays)
	}
}

func TestNormalizeOptionsValidation(t *testing.T) {
	tests := []struct {
		name       string
		opts       Options
		errorMatch string
	}{
		{
			name:       "multiple addresses",
			opts:       Options{Addresses: []string{"clickhouse-1:9000", "clickhouse-2:9000"}},
			errorMatch: "cluster-aware ON CLUSTER migrations",
		},
		{name: "empty address", opts: Options{Addresses: []string{" "}}},
		{name: "negative timeout", opts: Options{DialTimeout: -time.Second}},
		{name: "negative retention", opts: Options{RetentionDays: -1}},
		{name: "database starts with digit", opts: Options{Database: "1events"}},
		{name: "database punctuation", opts: Options{Database: "events-prod"}},
		{name: "database injection", opts: Options{Database: "events; DROP DATABASE default"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeOptions(test.opts)
			if err == nil {
				t.Fatal("normalizeOptions() unexpectedly succeeded")
			}
			if test.errorMatch != "" && !strings.Contains(err.Error(), test.errorMatch) {
				t.Fatalf("normalizeOptions() error = %q, want it to contain %q", err, test.errorMatch)
			}
		})
	}
}

func TestSchemaMigrations(t *testing.T) {
	migrations := schemaMigrations(37)
	schema := strings.Join(migrations, "\n")
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS usage_events",
		"ENGINE = MergeTree",
		"PARTITION BY toYYYYMM(event_time)",
		"ORDER BY (tenant_id, account_id, role_arn, iam_action, event_time, event_id)",
		"TTL toDateTime(event_time) + INTERVAL 37 DAY DELETE",
		"CREATE TABLE IF NOT EXISTS permission_usage_hourly",
		"ENGINE = AggregatingMergeTree",
		"uniqExactState(event_id)",
		"CREATE MATERIALIZED VIEW IF NOT EXISTS permission_usage_hourly_mv",
		"CREATE TABLE IF NOT EXISTS collector_heartbeats",
		"CREATE TABLE IF NOT EXISTS iam_snapshots",
		"CREATE TABLE IF NOT EXISTS iam_roles",
		"CREATE TABLE IF NOT EXISTS iam_policy_statements",
		"collected_at DateTime64(9, 'UTC')",
		"actions Array(String)",
		"not_actions Array(String)",
		"resources Array(String)",
		"not_resources Array(String)",
		"condition_json String",
		"raw_document String",
		"ALTER TABLE iam_roles ADD COLUMN IF NOT EXISTS collected_at DateTime64(9, 'UTC')",
		"ALTER TABLE iam_policy_statements ADD COLUMN IF NOT EXISTS collected_at DateTime64(9, 'UTC')",
		"ALTER TABLE iam_roles UPDATE collected_at = now64(9)",
		"ALTER TABLE iam_policy_statements UPDATE collected_at = now64(9)",
		"ALTER TABLE collector_heartbeats MODIFY TTL toDateTime(heartbeat_time) + INTERVAL 37 DAY DELETE",
		"ALTER TABLE iam_snapshots MODIFY TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
		"ALTER TABLE iam_roles MODIFY TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
		"ALTER TABLE iam_policy_statements MODIFY TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
	} {
		if !strings.Contains(schema, expected) {
			t.Errorf("schema does not contain %q", expected)
		}
	}
	for table, ttl := range map[string]string{
		"collector_heartbeats":  "TTL toDateTime(heartbeat_time) + INTERVAL 37 DAY DELETE",
		"iam_snapshots":         "TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
		"iam_roles":             "TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
		"iam_policy_statements": "TTL toDateTime(collected_at) + INTERVAL 37 DAY DELETE",
	} {
		var definition string
		for _, migration := range migrations {
			if strings.Contains(migration, "CREATE TABLE IF NOT EXISTS "+table) {
				definition = migration
				break
			}
		}
		if definition == "" {
			t.Errorf("missing CREATE definition for %s", table)
			continue
		}
		if !strings.Contains(definition, ttl) {
			t.Errorf("%s CREATE definition does not contain %q", table, ttl)
		}
	}
	for _, table := range []string{"iam_roles", "iam_policy_statements"} {
		addColumn := strings.Index(schema, "ALTER TABLE "+table+" ADD COLUMN IF NOT EXISTS collected_at")
		modifyTTL := strings.Index(schema, "ALTER TABLE "+table+" MODIFY TTL")
		if addColumn < 0 || modifyTTL < 0 || addColumn > modifyTTL {
			t.Errorf("%s collected_at migration must precede its TTL migration", table)
		}
	}
	for _, forbidden := range []string{"analysis_results", "PRAGMA"} {
		if strings.Contains(schema, forbidden) {
			t.Errorf("schema unexpectedly contains %q", forbidden)
		}
	}
}

func TestIAMModelsPreserveRawSemantics(t *testing.T) {
	statement := IAMPolicyStatement{
		Origin:        IAMStatementOriginBoundary,
		Effect:        "Deny",
		Actions:       []string{"s3:GetObject"},
		NotActions:    []string{"iam:*"},
		Resources:     []string{"arn:aws:s3:::example/*"},
		NotResources:  []string{"arn:aws:s3:::public/*"},
		ConditionJSON: `{"StringEquals":{"aws:PrincipalOrgID":"o-example"}}`,
		RawDocument:   `{"Version":"2012-10-17","Statement":[]}`,
	}
	snapshot := IAMSnapshot{
		SnapshotID: "snapshot-1",
		AccountID:  "123456789012",
		Roles: []IAMRole{{
			RoleARN:    "arn:aws:iam::123456789012:role/example",
			Statements: []IAMPolicyStatement{statement},
		}},
	}
	got := snapshot.Roles[0].Statements[0]
	if !reflect.DeepEqual(got, statement) {
		t.Fatalf("statement changed: got %#v, want %#v", got, statement)
	}
}

func TestUsageModels(t *testing.T) {
	now := time.Now().UTC()
	event := UsageEvent{
		EventID:      "event-1",
		EventTime:    now,
		ReceivedAt:   now.Add(time.Second),
		TenantID:     "tenant",
		AccountID:    "123456789012",
		RoleARN:      "arn:aws:iam::123456789012:role/example",
		Workload:     "api",
		Environment:  "production",
		AWSService:   "s3",
		SDKOperation: "GetObject",
		IAMAction:    "s3:GetObject",
		Outcome:      "success",
		RequestID:    "request-1",
		TraceID:      "trace-1",
		SpanID:       "span-1",
	}
	if event.EventID == "" || event.EventTime.IsZero() || event.IAMAction == "" {
		t.Fatalf("usage event did not preserve required fields: %#v", event)
	}

	usage := PermissionUsage{
		RoleARN:          event.RoleARN,
		IAMAction:        event.IAMAction,
		SuccessfulEvents: 2,
		DeniedEvents:     1,
		FailedEvents:     3,
		FirstSuccess:     now,
		LastSuccess:      now.Add(time.Minute),
	}
	if usage.SuccessfulEvents+usage.DeniedEvents+usage.FailedEvents != 6 {
		t.Fatalf("permission usage did not preserve aggregate counts: %#v", usage)
	}

	coverage := CollectorCoverage{
		FirstHeartbeat: now,
		LastHeartbeat:  now.Add(time.Minute),
		Received:       11,
		Accepted:       7,
	}
	if coverage.FirstHeartbeat.IsZero() || coverage.LastHeartbeat.IsZero() || coverage.Received != 11 || coverage.Accepted != 7 {
		t.Fatalf("collector coverage did not preserve aggregate values: %#v", coverage)
	}
}

func TestClickHouseIntegration(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}

	secure := os.Getenv("CLICKHOUSE_TEST_SECURE") == "1"
	database := fmt.Sprintf("shinkai_storage_test_%d", time.Now().UnixNano())
	opts := Options{
		Addresses:     []string{address},
		Database:      database,
		Username:      os.Getenv("CLICKHOUSE_TEST_USER"),
		Password:      os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
		Secure:        secure,
		DialTimeout:   10 * time.Second,
		RetentionDays: 7,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer func() {
		_ = db.Close()
		adminOptions := &clickhouse.Options{
			Addr: []string{address},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: opts.Username,
				Password: opts.Password,
			},
			DialTimeout: opts.DialTimeout,
		}
		if adminOptions.Auth.Username == "" {
			adminOptions.Auth.Username = "default"
		}
		if secure {
			adminOptions.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		admin, openErr := clickhouse.Open(adminOptions)
		if openErr != nil {
			t.Errorf("opening cleanup connection: %v", openErr)
			return
		}
		defer admin.Close()
		if dropErr := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdentifier(database)); dropErr != nil {
			t.Errorf("dropping integration database: %v", dropErr)
		}
	}()

	for _, migration := range []string{
		"ALTER TABLE collector_heartbeats REMOVE TTL",
		"ALTER TABLE iam_snapshots REMOVE TTL",
		"ALTER TABLE iam_roles REMOVE TTL",
		"ALTER TABLE iam_policy_statements REMOVE TTL",
		"ALTER TABLE iam_roles DROP COLUMN collected_at",
		"ALTER TABLE iam_policy_statements DROP COLUMN collected_at",
	} {
		if err := db.conn.Exec(ctx, migration); err != nil {
			t.Fatalf("preparing existing-schema migration test with %q: %v", migration, err)
		}
	}
	if err := db.migrate(ctx, opts.RetentionDays); err != nil {
		t.Fatalf("migrate() existing schema error: %v", err)
	}
	if err := db.migrate(ctx, opts.RetentionDays); err != nil {
		t.Fatalf("migrate() idempotent rerun error: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	emptyCoverage, err := db.GetCollectorCoverage(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetCollectorCoverage() empty error: %v", err)
	}
	if emptyCoverage != (CollectorCoverage{}) {
		t.Fatalf("empty collector coverage = %#v, want zero value", emptyCoverage)
	}
	if err := db.RecordCollectorHeartbeat(ctx, now.Add(-2*time.Minute), 10, 8); err != nil {
		t.Fatalf("RecordCollectorHeartbeat() first error: %v", err)
	}
	if err := db.RecordCollectorHeartbeat(ctx, now.Add(-time.Minute), 7, 6); err != nil {
		t.Fatalf("RecordCollectorHeartbeat() second error: %v", err)
	}
	if err := db.RecordCollectorHeartbeat(ctx, now.Add(time.Hour), 100, 100); err != nil {
		t.Fatalf("RecordCollectorHeartbeat() future error: %v", err)
	}
	coverage, err := db.GetCollectorCoverage(ctx, now.Add(-90*time.Second))
	if err != nil {
		t.Fatalf("GetCollectorCoverage() error: %v", err)
	}
	expectedHeartbeat := now.Add(-time.Minute).Truncate(time.Second)
	if !coverage.FirstHeartbeat.Equal(expectedHeartbeat) || !coverage.LastHeartbeat.Equal(expectedHeartbeat) || coverage.Received != 7 || coverage.Accepted != 6 {
		t.Fatalf("unexpected collector coverage: %#v", coverage)
	}

	events := []UsageEvent{
		{EventID: "success-1", EventTime: now.Add(-time.Minute), ReceivedAt: now, TenantID: "tenant", AccountID: "123456789012", RoleARN: "role/test", IAMAction: "s3:GetObject", Outcome: "success"},
		{EventID: "success-1", EventTime: now.Add(-time.Minute), ReceivedAt: now, TenantID: "tenant", AccountID: "123456789012", RoleARN: "role/test", IAMAction: "s3:GetObject", Outcome: "success"},
		{EventID: "denied-1", EventTime: now, ReceivedAt: now, TenantID: "tenant", AccountID: "123456789012", RoleARN: "role/test", IAMAction: "s3:GetObject", Outcome: "denied"},
		{EventID: "failed-1", EventTime: now, ReceivedAt: now, TenantID: "tenant", AccountID: "123456789012", RoleARN: "role/test", IAMAction: "s3:GetObject", Outcome: "failed"},
	}
	if err := db.BatchRecordUsageEvents(ctx, events); err != nil {
		t.Fatalf("BatchRecordUsageEvents() error: %v", err)
	}
	usage, err := db.QueryPermissionUsage(ctx, UsageQuery{TenantID: "tenant", Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("QueryPermissionUsage() error: %v", err)
	}
	if len(usage) != 1 {
		t.Fatalf("permission usage rows = %d, want 1", len(usage))
	}
	if usage[0].SuccessfulEvents != 1 || usage[0].DeniedEvents != 1 || usage[0].FailedEvents != 1 {
		t.Fatalf("unexpected unique outcome counts: %#v", usage[0])
	}

	snapshot := IAMSnapshot{
		SnapshotID:  "snapshot-1",
		AccountID:   "123456789012",
		CollectedAt: now,
		Roles: []IAMRole{{
			RoleARN:  "arn:aws:iam::123456789012:role/test",
			RoleName: "test",
			Statements: []IAMPolicyStatement{{
				Origin:        IAMStatementOriginManaged,
				PolicyARN:     "arn:aws:iam::123456789012:policy/test",
				Effect:        "Allow",
				Actions:       []string{"s3:GetObject"},
				Resources:     []string{"arn:aws:s3:::example/*"},
				ConditionJSON: `{}`,
				RawDocument:   `{"Statement":[]}`,
			}},
		}},
	}
	if err := db.SaveIAMSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("SaveIAMSnapshot() error: %v", err)
	}
	latest, found, err := db.LatestIAMSnapshot(ctx, snapshot.AccountID)
	if err != nil {
		t.Fatalf("LatestIAMSnapshot() error: %v", err)
	}
	if !found {
		t.Fatal("LatestIAMSnapshot() did not find saved snapshot")
	}
	if latest.SnapshotID != snapshot.SnapshotID || len(latest.Roles) != 1 || len(latest.Roles[0].Statements) != 1 {
		t.Fatalf("unexpected latest snapshot: %#v", latest)
	}
}
