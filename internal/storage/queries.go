package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const successfulOutcomeSQL = "lowerUTF8(outcome) IN ('success', 'succeeded', 'successful', 'ok')"

// BatchRecordUsageEvents inserts events with ClickHouse's native batch API.
func (db *DB) BatchRecordUsageEvents(ctx context.Context, events []UsageEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := db.conn.PrepareBatch(ctx, `INSERT INTO usage_events (
		event_id, event_time, received_at, tenant_id, account_id, role_arn,
		workload, environment, aws_service, sdk_operation, iam_action, outcome,
		request_id, trace_id, span_id
	)`)
	if err != nil {
		return fmt.Errorf("preparing usage event batch: %w", err)
	}
	defer batch.Abort() // Releases the connection if an append fails before Send.
	for i, event := range events {
		if err := batch.Append(
			event.EventID,
			event.EventTime,
			event.ReceivedAt,
			event.TenantID,
			event.AccountID,
			event.RoleARN,
			event.Workload,
			event.Environment,
			event.AWSService,
			event.SDKOperation,
			event.IAMAction,
			event.Outcome,
			event.RequestID,
			event.TraceID,
			event.SpanID,
		); err != nil {
			return fmt.Errorf("appending usage event %d: %w", i, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("sending usage event batch: %w", err)
	}
	return nil
}

// RecordCollectorHeartbeat records one collector liveness and throughput sample.
func (db *DB) RecordCollectorHeartbeat(ctx context.Context, at time.Time, received, accepted uint64) error {
	if err := db.conn.Exec(ctx,
		"INSERT INTO collector_heartbeats (heartbeat_time, received, accepted) VALUES (?, ?, ?)",
		at, received, accepted,
	); err != nil {
		return fmt.Errorf("recording collector heartbeat: %w", err)
	}
	return nil
}

// GetCollectorCoverage summarizes collector heartbeats from since through now.
func (db *DB) GetCollectorCoverage(ctx context.Context, since time.Time) (CollectorCoverage, error) {
	var coverage CollectorCoverage
	var count uint64
	if err := db.conn.QueryRow(ctx, `
		SELECT
			count(),
			ifNull(minOrNull(heartbeat_time), toDateTime64(0, 9, 'UTC')),
			ifNull(maxOrNull(heartbeat_time), toDateTime64(0, 9, 'UTC')),
			ifNull(sumOrNull(received), toUInt64(0)),
			ifNull(sumOrNull(accepted), toUInt64(0))
		FROM collector_heartbeats
		WHERE heartbeat_time >= ? AND heartbeat_time <= ?`, since, time.Now().UTC()).Scan(
		&count,
		&coverage.FirstHeartbeat,
		&coverage.LastHeartbeat,
		&coverage.Received,
		&coverage.Accepted,
	); err != nil {
		return CollectorCoverage{}, fmt.Errorf("querying collector coverage: %w", err)
	}
	if count == 0 {
		return CollectorCoverage{}, nil
	}
	return coverage, nil
}

// QueryPermissionUsage groups unique event outcomes by role and IAM action.
func (db *DB) QueryPermissionUsage(ctx context.Context, query UsageQuery) ([]PermissionUsage, error) {
	where := []string{"1"}
	args := make([]any, 0, 7)
	if query.TenantID != "" {
		where = append(where, "tenant_id = ?")
		args = append(args, query.TenantID)
	}
	if query.AccountID != "" {
		where = append(where, "account_id = ?")
		args = append(args, query.AccountID)
	}
	if query.RoleARN != "" {
		where = append(where, "role_arn = ?")
		args = append(args, query.RoleARN)
	}
	if query.Workload != "" {
		where = append(where, "workload = ?")
		args = append(args, query.Workload)
	}
	if query.Environment != "" {
		where = append(where, "environment = ?")
		args = append(args, query.Environment)
	}
	if !query.Since.IsZero() {
		where = append(where, "event_time >= ?")
		args = append(args, query.Since)
	}
	if !query.Until.IsZero() {
		where = append(where, "event_time < ?")
		args = append(args, query.Until)
	}

	statement := fmt.Sprintf(`
		SELECT
			role_arn,
			iam_action,
			uniqExactIf(event_id, %s) AS successful_events,
			uniqExactIf(event_id, lowerUTF8(outcome) IN ('denied', 'accessdenied', 'access_denied')) AS denied_events,
			uniqExactIf(event_id, lowerUTF8(outcome) IN ('fail', 'failed', 'failure', 'error')) AS failed_events,
			minIf(event_time, %s) AS first_success,
			maxIf(event_time, %s) AS last_success
		FROM usage_events
		WHERE %s
		GROUP BY role_arn, iam_action
		ORDER BY role_arn, iam_action`,
		successfulOutcomeSQL,
		successfulOutcomeSQL,
		successfulOutcomeSQL,
		strings.Join(where, " AND "),
	)

	rows, err := db.conn.Query(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("querying permission usage: %w", err)
	}
	defer rows.Close()

	var usage []PermissionUsage
	for rows.Next() {
		var item PermissionUsage
		if err := rows.Scan(
			&item.RoleARN,
			&item.IAMAction,
			&item.SuccessfulEvents,
			&item.DeniedEvents,
			&item.FailedEvents,
			&item.FirstSuccess,
			&item.LastSuccess,
		); err != nil {
			return nil, fmt.Errorf("scanning permission usage: %w", err)
		}
		if item.SuccessfulEvents == 0 {
			item.FirstSuccess = time.Time{}
			item.LastSuccess = time.Time{}
		}
		usage = append(usage, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating permission usage: %w", err)
	}
	return usage, nil
}

// GetObservedRoles returns roles observed in the requested time window.
func (db *DB) GetObservedRoles(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := db.conn.Query(ctx, `
		SELECT DISTINCT role_arn
		FROM usage_events
		WHERE event_time >= ?
		ORDER BY role_arn`, since)
	if err != nil {
		return nil, fmt.Errorf("querying observed roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scanning observed role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating observed roles: %w", err)
	}
	return roles, nil
}

// GetUsedPrivilegesForRole returns distinct successful IAM actions for a role.
func (db *DB) GetUsedPrivilegesForRole(ctx context.Context, role string, since time.Time) ([]string, error) {
	rows, err := db.conn.Query(ctx, `
		SELECT DISTINCT iam_action
		FROM usage_events
		WHERE role_arn = ? AND event_time >= ? AND `+successfulOutcomeSQL+`
		ORDER BY iam_action`, role, since)
	if err != nil {
		return nil, fmt.Errorf("querying used privileges: %w", err)
	}
	defer rows.Close()

	var privileges []string
	for rows.Next() {
		var privilege string
		if err := rows.Scan(&privilege); err != nil {
			return nil, fmt.Errorf("scanning used privilege: %w", err)
		}
		privileges = append(privileges, privilege)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating used privileges: %w", err)
	}
	return privileges, nil
}

// GetOldestObservation returns false when no usage events are stored.
func (db *DB) GetOldestObservation(ctx context.Context) (time.Time, bool, error) {
	var oldest time.Time
	var count uint64
	if err := db.conn.QueryRow(ctx, "SELECT min(event_time), count() FROM usage_events").Scan(&oldest, &count); err != nil {
		return time.Time{}, false, fmt.Errorf("querying oldest observation: %w", err)
	}
	if count == 0 {
		return time.Time{}, false, nil
	}
	return oldest, true, nil
}
