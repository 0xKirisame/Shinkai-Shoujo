package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const (
	defaultAddress       = "localhost:9000"
	defaultDatabase      = "shinkai_shoujo"
	defaultDialTimeout   = 5 * time.Second
	defaultRetentionDays = 90
)

var databaseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Options configures a ClickHouse connection and the storage schema.
type Options struct {
	Addresses     []string
	Database      string
	Username      string
	Password      string
	Secure        bool
	DialTimeout   time.Duration
	RetentionDays int
}

// DB owns the native ClickHouse connection used by storage operations.
type DB struct {
	conn driver.Conn
}

// Open creates the configured database when necessary, connects to it, and
// applies the storage schema.
func Open(ctx context.Context, options Options) (*DB, error) {
	opts, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}

	admin, err := openConnection(opts, "default")
	if err != nil {
		return nil, fmt.Errorf("opening ClickHouse default database: %w", err)
	}
	if err := admin.Ping(ctx); err != nil {
		_ = admin.Close()
		return nil, fmt.Errorf("pinging ClickHouse default database: %w", err)
	}
	if err := admin.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdentifier(opts.Database)); err != nil {
		_ = admin.Close()
		return nil, fmt.Errorf("creating ClickHouse database %q: %w", opts.Database, err)
	}
	if err := admin.Close(); err != nil {
		return nil, fmt.Errorf("closing ClickHouse default database connection: %w", err)
	}

	conn, err := openConnection(opts, opts.Database)
	if err != nil {
		return nil, fmt.Errorf("opening ClickHouse database %q: %w", opts.Database, err)
	}
	db := &DB{conn: conn}
	if err := db.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := db.migrate(ctx, opts.RetentionDays); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return db, nil
}

func normalizeOptions(opts Options) (Options, error) {
	if len(opts.Addresses) == 0 {
		opts.Addresses = []string{defaultAddress}
	} else {
		if len(opts.Addresses) > 1 {
			return Options{}, fmt.Errorf("multiple ClickHouse addresses are not supported until cluster-aware ON CLUSTER migrations are implemented")
		}
		opts.Addresses = append([]string(nil), opts.Addresses...)
	}
	for i, address := range opts.Addresses {
		opts.Addresses[i] = strings.TrimSpace(address)
		if opts.Addresses[i] == "" {
			return Options{}, fmt.Errorf("ClickHouse address %d is empty", i)
		}
	}

	opts.Database = strings.TrimSpace(opts.Database)
	if opts.Database == "" {
		opts.Database = defaultDatabase
	}
	if !databaseIdentifier.MatchString(opts.Database) {
		return Options{}, fmt.Errorf("invalid ClickHouse database identifier %q", opts.Database)
	}
	if opts.Username == "" {
		opts.Username = "default"
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	} else if opts.DialTimeout < 0 {
		return Options{}, fmt.Errorf("ClickHouse dial timeout must not be negative")
	}
	if opts.RetentionDays == 0 {
		opts.RetentionDays = defaultRetentionDays
	} else if opts.RetentionDays < 0 {
		return Options{}, fmt.Errorf("ClickHouse retention days must not be negative")
	}
	return opts, nil
}

func openConnection(opts Options, database string) (driver.Conn, error) {
	config := &clickhouse.Options{
		Addr: opts.Addresses,
		Auth: clickhouse.Auth{
			Database: database,
			Username: opts.Username,
			Password: opts.Password,
		},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		DialTimeout: opts.DialTimeout,
	}
	if opts.Secure {
		config.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return clickhouse.Open(config)
}

func quoteIdentifier(identifier string) string {
	return "`" + identifier + "`"
}

func (db *DB) migrate(ctx context.Context, retentionDays int) error {
	for _, migration := range schemaMigrations(retentionDays) {
		if err := db.conn.Exec(ctx, migration); err != nil {
			return fmt.Errorf("applying ClickHouse storage schema: %w", err)
		}
	}
	return nil
}

func schemaMigrations(retentionDays int) []string {
	retention := fmt.Sprintf("INTERVAL %d DAY", retentionDays)
	return []string{
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS usage_events (
    event_id String,
    event_time DateTime64(9, 'UTC'),
    received_at DateTime64(9, 'UTC'),
    tenant_id String,
    account_id String,
    role_arn String,
    workload String,
    environment String,
    aws_service String,
    sdk_operation String,
    iam_action String,
    outcome LowCardinality(String),
    request_id String,
    trace_id String,
    span_id String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, account_id, role_arn, iam_action, event_time, event_id)
TTL toDateTime(event_time) + %s DELETE`, retention),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS permission_usage_hourly (
    hour DateTime('UTC'),
    tenant_id String,
    account_id String,
    role_arn String,
    iam_action String,
    successful_events AggregateFunction(uniqExact, String),
    first_success AggregateFunction(min, DateTime64(9, 'UTC')),
    last_success AggregateFunction(max, DateTime64(9, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, account_id, role_arn, iam_action, hour)
TTL hour + %s DELETE`, retention),
		`
CREATE MATERIALIZED VIEW IF NOT EXISTS permission_usage_hourly_mv
TO permission_usage_hourly AS
SELECT
    toStartOfHour(event_time) AS hour,
    tenant_id,
    account_id,
    role_arn,
    iam_action,
    uniqExactState(event_id) AS successful_events,
    minState(event_time) AS first_success,
    maxState(event_time) AS last_success
FROM usage_events
WHERE lowerUTF8(outcome) IN ('success', 'succeeded', 'successful', 'ok')
GROUP BY hour, tenant_id, account_id, role_arn, iam_action`,
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS collector_heartbeats (
    heartbeat_time DateTime64(9, 'UTC'),
    received UInt64,
    accepted UInt64
)
ENGINE = MergeTree
ORDER BY heartbeat_time
TTL toDateTime(heartbeat_time) + %s DELETE`, retention),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS iam_snapshots (
    snapshot_id String,
    account_id String,
    collected_at DateTime64(9, 'UTC')
)
ENGINE = MergeTree
ORDER BY (account_id, collected_at, snapshot_id)
TTL toDateTime(collected_at) + %s DELETE`, retention),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS iam_roles (
    snapshot_id String,
    account_id String,
    collected_at DateTime64(9, 'UTC'),
    role_arn String,
    role_name String,
    role_id String,
    path String
)
ENGINE = MergeTree
ORDER BY (snapshot_id, account_id, role_arn)
TTL toDateTime(collected_at) + %s DELETE`, retention),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS iam_policy_statements (
    snapshot_id String,
    account_id String,
    collected_at DateTime64(9, 'UTC'),
    role_arn String,
    statement_index UInt32,
    origin LowCardinality(String),
    policy_arn String,
    policy_name String,
    policy_version_id String,
    statement_id String,
    effect LowCardinality(String),
    actions Array(String),
    not_actions Array(String),
    resources Array(String),
    not_resources Array(String),
    condition_json String,
    raw_document String
)
ENGINE = MergeTree
ORDER BY (snapshot_id, account_id, role_arn, statement_index)
TTL toDateTime(collected_at) + %s DELETE`, retention),
		"ALTER TABLE iam_roles ADD COLUMN IF NOT EXISTS collected_at DateTime64(9, 'UTC')",
		"ALTER TABLE iam_policy_statements ADD COLUMN IF NOT EXISTS collected_at DateTime64(9, 'UTC')",
		// Older schemas had no child timestamp. Preserve those published snapshots
		// for one full retention period instead of expiring their child rows at epoch.
		"ALTER TABLE iam_roles UPDATE collected_at = now64(9) WHERE collected_at = toDateTime64(0, 9, 'UTC') SETTINGS mutations_sync = 2",
		"ALTER TABLE iam_policy_statements UPDATE collected_at = now64(9) WHERE collected_at = toDateTime64(0, 9, 'UTC') SETTINGS mutations_sync = 2",
		fmt.Sprintf("ALTER TABLE usage_events MODIFY TTL toDateTime(event_time) + %s DELETE", retention),
		fmt.Sprintf("ALTER TABLE permission_usage_hourly MODIFY TTL hour + %s DELETE", retention),
		fmt.Sprintf("ALTER TABLE collector_heartbeats MODIFY TTL toDateTime(heartbeat_time) + %s DELETE", retention),
		fmt.Sprintf("ALTER TABLE iam_snapshots MODIFY TTL toDateTime(collected_at) + %s DELETE", retention),
		fmt.Sprintf("ALTER TABLE iam_roles MODIFY TTL toDateTime(collected_at) + %s DELETE", retention),
		fmt.Sprintf("ALTER TABLE iam_policy_statements MODIFY TTL toDateTime(collected_at) + %s DELETE", retention),
	}
}

// Ping verifies that the configured ClickHouse database is reachable.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.conn.Ping(ctx); err != nil {
		return fmt.Errorf("pinging ClickHouse: %w", err)
	}
	return nil
}

// Close closes the native ClickHouse connection.
func (db *DB) Close() error {
	return db.conn.Close()
}
