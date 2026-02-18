package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// PrivilegeUsageRecord represents a single span's privilege observation.
type PrivilegeUsageRecord struct {
	Timestamp time.Time
	IAMRole   string
	Privilege string
	CallCount int
}

// AnalysisResult stores a snapshot of a role's privilege analysis.
type AnalysisResult struct {
	AnalysisDate  time.Time
	IAMRole       string
	AssignedPrivs []string
	UsedPrivs     []string
	UnusedPrivs   []string
	RiskLevel     string
}

// BatchRecordPrivilegeUsage inserts multiple records in a single transaction.
func (db *DB) BatchRecordPrivilegeUsage(ctx context.Context, records []PrivilegeUsageRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// ON CONFLICT upsert: advance timestamp to the most recent observation
	// and accumulate call_count. This keeps one row per (iam_role, privilege)
	// pair, bounding the table to the set of distinct role-privilege pairs.
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO privilege_usage (timestamp, iam_role, privilege, call_count)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(iam_role, privilege) DO UPDATE SET
		    timestamp  = MAX(privilege_usage.timestamp, excluded.timestamp),
		    call_count = privilege_usage.call_count + excluded.call_count
	`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, r := range records {
		if _, err := stmt.ExecContext(ctx, r.Timestamp.Unix(), r.IAMRole, r.Privilege, r.CallCount); err != nil {
			return fmt.Errorf("upserting record for role %s: %w", r.IAMRole, err)
		}
	}
	return tx.Commit()
}

// GetUsedPrivilegesForRole returns distinct privileges observed for a role
// within the given time window.
func (db *DB) GetUsedPrivilegesForRole(ctx context.Context, role string, since time.Time) ([]string, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT DISTINCT privilege FROM privilege_usage
		 WHERE iam_role = ? AND timestamp >= ?`,
		role, since.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("querying used privileges: %w", err)
	}
	defer rows.Close()

	var privs []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		privs = append(privs, p)
	}
	return privs, rows.Err()
}

// GetObservedRoles returns all distinct IAM roles seen in the observation window.
func (db *DB) GetObservedRoles(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT DISTINCT iam_role FROM privilege_usage WHERE timestamp >= ?`,
		since.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("querying observed roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// SaveAnalysisResult stores an analysis result snapshot.
func (db *DB) SaveAnalysisResult(ctx context.Context, r AnalysisResult) error {
	assigned, err := json.Marshal(r.AssignedPrivs)
	if err != nil {
		return fmt.Errorf("marshaling assigned privileges: %w", err)
	}
	used, err := json.Marshal(r.UsedPrivs)
	if err != nil {
		return fmt.Errorf("marshaling used privileges: %w", err)
	}
	unused, err := json.Marshal(r.UnusedPrivs)
	if err != nil {
		return fmt.Errorf("marshaling unused privileges: %w", err)
	}

	_, err = db.conn.ExecContext(ctx,
		`INSERT INTO analysis_results
		 (analysis_date, iam_role, assigned_privileges, used_privileges, unused_privileges, risk_level)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(iam_role) DO UPDATE SET
		     analysis_date       = excluded.analysis_date,
		     assigned_privileges = excluded.assigned_privileges,
		     used_privileges     = excluded.used_privileges,
		     unused_privileges   = excluded.unused_privileges,
		     risk_level          = excluded.risk_level`,
		r.AnalysisDate.Unix(), r.IAMRole, string(assigned), string(used), string(unused), r.RiskLevel,
	)
	return err
}

// GetLatestAnalysisResults returns the analysis result for each role.
// The unique index on iam_role guarantees at most one row per role.
func (db *DB) GetLatestAnalysisResults(ctx context.Context) ([]AnalysisResult, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT iam_role, analysis_date, assigned_privileges, used_privileges, unused_privileges, risk_level
		FROM analysis_results
		ORDER BY iam_role
	`)
	if err != nil {
		return nil, fmt.Errorf("querying analysis results: %w", err)
	}
	defer rows.Close()

	var results []AnalysisResult
	for rows.Next() {
		var r AnalysisResult
		var ts int64
		var assigned, used, unused string
		if err := rows.Scan(&r.IAMRole, &ts, &assigned, &used, &unused, &r.RiskLevel); err != nil {
			return nil, err
		}
		r.AnalysisDate = time.Unix(ts, 0)
		if err := json.Unmarshal([]byte(assigned), &r.AssignedPrivs); err != nil {
			return nil, fmt.Errorf("unmarshaling assigned: %w", err)
		}
		if err := json.Unmarshal([]byte(used), &r.UsedPrivs); err != nil {
			return nil, fmt.Errorf("unmarshaling used: %w", err)
		}
		if err := json.Unmarshal([]byte(unused), &r.UnusedPrivs); err != nil {
			return nil, fmt.Errorf("unmarshaling unused: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// GetOldestObservation returns the timestamp of the earliest privilege_usage record.
// Returns (zero, false, nil) when the table is empty.
func (db *DB) GetOldestObservation(ctx context.Context) (time.Time, bool, error) {
	var ts sql.NullInt64
	err := db.conn.QueryRowContext(ctx, `SELECT MIN(timestamp) FROM privilege_usage`).Scan(&ts)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("querying oldest observation: %w", err)
	}
	if !ts.Valid {
		return time.Time{}, false, nil
	}
	return time.Unix(ts.Int64, 0), true, nil
}

// PurgeOldRecords deletes privilege_usage records older than the given cutoff.
func (db *DB) PurgeOldRecords(ctx context.Context, before time.Time) (int64, error) {
	res, err := db.conn.ExecContext(ctx,
		`DELETE FROM privilege_usage WHERE timestamp < ?`,
		before.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("purging old records: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
