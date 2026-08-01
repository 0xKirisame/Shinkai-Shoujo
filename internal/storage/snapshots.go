package storage

import (
	"context"
	"fmt"
)

// SaveIAMSnapshot writes child rows before metadata. Consequently, readers that
// join iam_snapshots can only observe snapshots whose complete write succeeded.
func (db *DB) SaveIAMSnapshot(ctx context.Context, snapshot IAMSnapshot) error {
	if snapshot.SnapshotID == "" {
		return fmt.Errorf("IAM snapshot ID must not be empty")
	}
	if snapshot.AccountID == "" {
		return fmt.Errorf("IAM snapshot account ID must not be empty")
	}

	if len(snapshot.Roles) > 0 {
		batch, err := db.conn.PrepareBatch(ctx, `INSERT INTO iam_roles (
			snapshot_id, account_id, collected_at, role_arn, role_name, role_id, path
		)`)
		if err != nil {
			return fmt.Errorf("preparing IAM role batch: %w", err)
		}
		defer batch.Abort() // Releases the connection if an append fails before Send.
		for i, role := range snapshot.Roles {
			if err := batch.Append(
				snapshot.SnapshotID,
				snapshot.AccountID,
				snapshot.CollectedAt,
				role.RoleARN,
				role.RoleName,
				role.RoleID,
				role.Path,
			); err != nil {
				return fmt.Errorf("appending IAM role %d: %w", i, err)
			}
		}
		if err := batch.Send(); err != nil {
			return fmt.Errorf("sending IAM role batch: %w", err)
		}
	}

	statementCount := 0
	for _, role := range snapshot.Roles {
		statementCount += len(role.Statements)
	}
	if statementCount > 0 {
		batch, err := db.conn.PrepareBatch(ctx, `INSERT INTO iam_policy_statements (
			snapshot_id, account_id, collected_at, role_arn, statement_index, origin,
			policy_arn, policy_name, policy_version_id, statement_id, effect,
			actions, not_actions, resources, not_resources, condition_json, raw_document
		)`)
		if err != nil {
			return fmt.Errorf("preparing IAM policy statement batch: %w", err)
		}
		defer batch.Abort() // Releases the connection if an append fails before Send.
		for _, role := range snapshot.Roles {
			for i, statement := range role.Statements {
				if err := batch.Append(
					snapshot.SnapshotID,
					snapshot.AccountID,
					snapshot.CollectedAt,
					role.RoleARN,
					uint32(i),
					statement.Origin,
					statement.PolicyARN,
					statement.PolicyName,
					statement.PolicyVersionID,
					statement.StatementID,
					statement.Effect,
					statement.Actions,
					statement.NotActions,
					statement.Resources,
					statement.NotResources,
					statement.ConditionJSON,
					statement.RawDocument,
				); err != nil {
					return fmt.Errorf("appending IAM policy statement for role %q at index %d: %w", role.RoleARN, i, err)
				}
			}
		}
		if err := batch.Send(); err != nil {
			return fmt.Errorf("sending IAM policy statement batch: %w", err)
		}
	}

	if err := db.conn.Exec(ctx,
		"INSERT INTO iam_snapshots (snapshot_id, account_id, collected_at) VALUES (?, ?, ?)",
		snapshot.SnapshotID, snapshot.AccountID, snapshot.CollectedAt,
	); err != nil {
		return fmt.Errorf("publishing IAM snapshot metadata: %w", err)
	}
	return nil
}

// LatestIAMSnapshot returns the newest complete snapshot for an account.
func (db *DB) LatestIAMSnapshot(ctx context.Context, accountID string) (IAMSnapshot, bool, error) {
	snapshot := IAMSnapshot{AccountID: accountID}
	var count uint64
	err := db.conn.QueryRow(ctx, `
		SELECT
			argMax(snapshot_id, tuple(collected_at, snapshot_id)),
			argMax(collected_at, tuple(collected_at, snapshot_id)),
			count()
		FROM iam_snapshots
		WHERE account_id = ?`, accountID).Scan(&snapshot.SnapshotID, &snapshot.CollectedAt, &count)
	if err != nil {
		return IAMSnapshot{}, false, fmt.Errorf("querying latest IAM snapshot: %w", err)
	}
	if count == 0 {
		return IAMSnapshot{}, false, nil
	}

	rows, err := db.conn.Query(ctx, `
		SELECT r.role_arn, r.role_name, r.role_id, r.path
		FROM iam_roles AS r
		ANY INNER JOIN iam_snapshots AS complete
			ON complete.snapshot_id = r.snapshot_id AND complete.account_id = r.account_id
		WHERE r.snapshot_id = ? AND r.account_id = ?
		ORDER BY r.role_arn`, snapshot.SnapshotID, snapshot.AccountID)
	if err != nil {
		return IAMSnapshot{}, false, fmt.Errorf("querying IAM snapshot roles: %w", err)
	}
	roleIndexes := make(map[string]int)
	for rows.Next() {
		var role IAMRole
		if err := rows.Scan(&role.RoleARN, &role.RoleName, &role.RoleID, &role.Path); err != nil {
			rows.Close()
			return IAMSnapshot{}, false, fmt.Errorf("scanning IAM snapshot role: %w", err)
		}
		roleIndexes[role.RoleARN] = len(snapshot.Roles)
		snapshot.Roles = append(snapshot.Roles, role)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return IAMSnapshot{}, false, fmt.Errorf("iterating IAM snapshot roles: %w", err)
	}
	rows.Close()

	statementRows, err := db.conn.Query(ctx, `
		SELECT
			s.role_arn, s.origin, s.policy_arn, s.policy_name, s.policy_version_id,
			s.statement_id, s.effect, s.actions, s.not_actions, s.resources,
			s.not_resources, s.condition_json, s.raw_document
		FROM iam_policy_statements AS s
		ANY INNER JOIN iam_snapshots AS complete
			ON complete.snapshot_id = s.snapshot_id AND complete.account_id = s.account_id
		WHERE s.snapshot_id = ? AND s.account_id = ?
		ORDER BY s.role_arn, s.statement_index`, snapshot.SnapshotID, snapshot.AccountID)
	if err != nil {
		return IAMSnapshot{}, false, fmt.Errorf("querying IAM snapshot statements: %w", err)
	}
	defer statementRows.Close()
	for statementRows.Next() {
		var roleARN string
		var statement IAMPolicyStatement
		if err := statementRows.Scan(
			&roleARN,
			&statement.Origin,
			&statement.PolicyARN,
			&statement.PolicyName,
			&statement.PolicyVersionID,
			&statement.StatementID,
			&statement.Effect,
			&statement.Actions,
			&statement.NotActions,
			&statement.Resources,
			&statement.NotResources,
			&statement.ConditionJSON,
			&statement.RawDocument,
		); err != nil {
			return IAMSnapshot{}, false, fmt.Errorf("scanning IAM policy statement: %w", err)
		}
		index, ok := roleIndexes[roleARN]
		if !ok {
			return IAMSnapshot{}, false, fmt.Errorf("IAM statement references missing role %q", roleARN)
		}
		snapshot.Roles[index].Statements = append(snapshot.Roles[index].Statements, statement)
	}
	if err := statementRows.Err(); err != nil {
		return IAMSnapshot{}, false, fmt.Errorf("iterating IAM snapshot statements: %w", err)
	}
	return snapshot, true, nil
}
