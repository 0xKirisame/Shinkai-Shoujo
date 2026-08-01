package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// ActionUsage is the observed event aggregate for one IAM action.
type ActionUsage struct {
	Action           string
	SuccessfulEvents uint64
	DeniedEvents     uint64
	FailedEvents     uint64
	FirstSuccess     time.Time
	LastSuccess      time.Time
}

// Result holds the correlation analysis for a single IAM role.
type Result struct {
	AccountID        string
	IAMRole          string
	Assigned         []string
	Used             []string
	Unused           []string
	Unresolved       []string
	Warnings         []string
	Usage            []ActionUsage
	ObservationStart time.Time
	AnalyzedAt       time.Time
	RiskLevel        string
}

type usageStore interface {
	GetCollectorCoverage(context.Context, time.Time) (storage.CollectorCoverage, error)
	QueryPermissionUsage(context.Context, storage.UsageQuery) ([]storage.PermissionUsage, error)
}

// Engine correlates an IAM snapshot with observed permission usage.
type Engine struct {
	store              usageStore
	tenantID           string
	accountID          string
	windowDays         int
	minObservationDays int
	log                *slog.Logger
	metrics            *metrics.Metrics
}

// NewEngine creates a correlation engine scoped to one tenant and AWS account.
func NewEngine(
	store usageStore,
	tenantID, accountID string,
	windowDays, minObservationDays int,
	log *slog.Logger,
	m *metrics.Metrics,
) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		store:              store,
		tenantID:           tenantID,
		accountID:          accountID,
		windowDays:         windowDays,
		minObservationDays: minObservationDays,
		log:                log,
		metrics:            m,
	}
}

// Run correlates successful, denied, and failed usage aggregates with a point-in-time IAM snapshot.
func (e *Engine) Run(ctx context.Context, snapshot storage.IAMSnapshot) ([]Result, error) {
	started := time.Now()
	analyzedAt := started.UTC()
	observationStart := analyzedAt.AddDate(0, 0, -e.windowDays)

	if e.metrics != nil {
		e.metrics.AnalysisRuns.Inc()
	}

	coverage, err := e.store.GetCollectorCoverage(ctx, observationStart)
	if err != nil {
		return nil, fmt.Errorf("querying collector coverage: %w", err)
	}
	coverageStart := coverage.FirstHeartbeat
	if coverageStart.Before(observationStart) {
		coverageStart = observationStart
	}
	observedDuration := time.Duration(0)
	if !coverage.FirstHeartbeat.IsZero() && coverageStart.Before(analyzedAt) {
		observedDuration = analyzedAt.Sub(coverageStart)
	}
	requiredDuration := time.Duration(e.minObservationDays) * 24 * time.Hour
	coverageSufficient := !coverage.FirstHeartbeat.IsZero() && observedDuration >= requiredDuration
	coverageFresh := !coverage.LastHeartbeat.IsZero() &&
		!coverage.LastHeartbeat.Before(analyzedAt.Add(-24*time.Hour))

	usageRows, err := e.store.QueryPermissionUsage(ctx, storage.UsageQuery{
		TenantID:  e.tenantID,
		AccountID: e.accountID,
		Since:     observationStart,
		Until:     analyzedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("querying permission usage: %w", err)
	}

	roleAliases := make(map[string]int, len(snapshot.Roles)*3)
	for i, role := range snapshot.Roles {
		for _, alias := range []string{role.RoleARN, normalizeRoleARN(role.RoleARN), role.RoleName} {
			if alias != "" {
				roleAliases[strings.ToLower(alias)] = i
			}
		}
	}

	usageByRole := make(map[int]map[string]ActionUsage)
	for _, row := range usageRows {
		if row.SuccessfulEvents+row.DeniedEvents+row.FailedEvents == 0 {
			continue
		}
		roleIndex, ok := findRole(roleAliases, row.RoleARN)
		if !ok {
			e.log.Warn("usage role not found in IAM snapshot", "role", row.RoleARN)
			continue
		}

		actionKey := strings.ToLower(row.IAMAction)
		if usageByRole[roleIndex] == nil {
			usageByRole[roleIndex] = make(map[string]ActionUsage)
		}
		item := usageByRole[roleIndex][actionKey]
		if item.Action == "" || lessFold(row.IAMAction, item.Action) {
			item.Action = row.IAMAction
		}
		item.SuccessfulEvents += row.SuccessfulEvents
		item.DeniedEvents += row.DeniedEvents
		item.FailedEvents += row.FailedEvents
		if row.SuccessfulEvents > 0 {
			if !row.FirstSuccess.IsZero() && (item.FirstSuccess.IsZero() || row.FirstSuccess.Before(item.FirstSuccess)) {
				item.FirstSuccess = row.FirstSuccess
			}
			if row.LastSuccess.After(item.LastSuccess) {
				item.LastSuccess = row.LastSuccess
			}
		}
		usageByRole[roleIndex][actionKey] = item
	}

	results := make([]Result, 0, len(usageByRole))
	for roleIndex, roleUsage := range usageByRole {
		role := snapshot.Roles[roleIndex]
		assigned, candidates, unresolved, warnings := inventory(role.Statements)

		usage := make([]ActionUsage, 0, len(roleUsage))
		observedSuccessful := make([]string, 0, len(roleUsage))
		var firstRoleSuccess time.Time
		for _, item := range roleUsage {
			usage = append(usage, item)
			if item.SuccessfulEvents > 0 {
				observedSuccessful = append(observedSuccessful, item.Action)
			}
			if !item.FirstSuccess.IsZero() && (firstRoleSuccess.IsZero() || item.FirstSuccess.Before(firstRoleSuccess)) {
				firstRoleSuccess = item.FirstSuccess
			}
		}
		sort.Slice(usage, func(i, j int) bool { return lessFold(usage[i].Action, usage[j].Action) })
		roleObservedDuration := time.Duration(0)
		if !firstRoleSuccess.IsZero() && firstRoleSuccess.Before(analyzedAt) {
			roleObservedDuration = analyzedAt.Sub(firstRoleSuccess)
		}
		roleObservationSufficient := roleObservedDuration >= requiredDuration
		effectiveObservedDuration := observedDuration
		if roleObservedDuration < effectiveObservedDuration {
			effectiveObservedDuration = roleObservedDuration
		}

		used, unused, observedUnresolved, correlationWarnings := analyzePrivileges(assigned, candidates, observedSuccessful)
		unresolved = append(unresolved, observedUnresolved...)
		warnings = append(warnings, correlationWarnings...)
		if !coverageSufficient || !coverageFresh || !roleObservationSufficient {
			unresolved = append(unresolved, unused...)
			unused = nil
			if !coverageFresh {
				warnings = append(warnings, "collector coverage is stale; last heartbeat is older than 24 hours; unused candidates suppressed")
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"observed collection duration is %.1f days; required duration is %d days; unused candidates suppressed",
					effectiveObservedDuration.Hours()/24,
					e.minObservationDays,
				))
			}
		}

		assigned = dedupeSortedFold(assigned)
		used = dedupeSortedFold(used)
		unused = dedupeSortedFold(unused)
		unresolved = dedupeSortedFold(unresolved)
		warnings = dedupeSortedFold(warnings)

		riskInputs := append(append([]string(nil), unused...), unresolved...)
		iamRole := role.RoleARN
		if iamRole == "" {
			iamRole = role.RoleName
		}
		result := Result{
			AccountID:        e.accountID,
			IAMRole:          iamRole,
			Assigned:         assigned,
			Used:             used,
			Unused:           unused,
			Unresolved:       unresolved,
			Warnings:         warnings,
			Usage:            usage,
			ObservationStart: observationStart,
			AnalyzedAt:       analyzedAt,
			RiskLevel:        string(ClassifySet(riskInputs)),
		}
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool { return lessFold(results[i].IAMRole, results[j].IAMRole) })
	if e.metrics != nil {
		var candidateCount, unresolvedCount int
		for _, result := range results {
			candidateCount += len(result.Unused)
			unresolvedCount += len(result.Unresolved)
		}
		e.metrics.CandidatePermissions.Set(float64(candidateCount))
		e.metrics.UnresolvedPermissions.Set(float64(unresolvedCount))
		e.metrics.AnalysisDuration.Observe(time.Since(started).Seconds())
	}
	e.log.Info("correlation analysis complete",
		"roles_analyzed", len(results),
		"duration_s", time.Since(started).Seconds(),
	)
	return results, nil
}

func inventory(statements []storage.IAMPolicyStatement) (assigned, candidates, unresolved, warnings []string) {
	for _, statement := range statements {
		isBoundary := strings.EqualFold(statement.Origin, storage.IAMStatementOriginBoundary)
		isIdentity := strings.EqualFold(statement.Origin, storage.IAMStatementOriginManaged) ||
			strings.EqualFold(statement.Origin, storage.IAMStatementOriginInline)
		isAllow := strings.EqualFold(statement.Effect, "Allow")

		if isBoundary {
			warnings = append(warnings, "permissions boundary statements constrain but do not grant permissions")
		}
		if strings.EqualFold(statement.Effect, "Deny") {
			warnings = append(warnings, "Deny statement semantics may constrain assigned permissions")
		}
		if len(statement.NotActions) > 0 {
			warnings = append(warnings, "NotAction statement semantics cannot be resolved to exact grants")
		}
		if strings.TrimSpace(statement.ConditionJSON) != "" {
			warnings = append(warnings, "condition semantics may constrain assigned permissions")
		}

		if !isIdentity || !isAllow {
			continue
		}
		if len(statement.NotActions) > 0 {
			unresolved = append(unresolved, statement.NotActions...)
			continue
		}
		hasCondition := strings.TrimSpace(statement.ConditionJSON) != ""
		for _, action := range statement.Actions {
			assigned = append(assigned, action)
			if hasCondition || hasWildcard(action) {
				unresolved = append(unresolved, action)
			} else {
				candidates = append(candidates, action)
			}
		}
	}
	return assigned, candidates, unresolved, warnings
}

// analyzePrivileges separates successful observations and exact unused candidates.
func analyzePrivileges(assigned, candidates, observed []string) (used, unused, unresolved, warnings []string) {
	var uncovered []string
	for _, action := range dedupeSortedFold(observed) {
		if isCovered(action, assigned) {
			used = append(used, action)
			continue
		}
		uncovered = append(uncovered, action)
		unresolved = append(unresolved, action)
	}

	unused = setDifference(candidates, used)
	if len(uncovered) > 0 {
		unresolved = append(unresolved, unused...)
		unused = []string{}
		warnings = append(warnings, fmt.Sprintf(
			"%d successful observed action(s) are not covered by identity Allow actions; unused candidates suppressed",
			len(uncovered),
		))
	}
	return used, unused, unresolved, warnings
}

// setDifference returns exact assigned actions that were not successfully observed.
func setDifference(assigned, used []string) []string {
	usedSet := make(map[string]struct{}, len(used))
	for _, action := range used {
		usedSet[strings.ToLower(action)] = struct{}{}
	}

	unused := make([]string, 0, len(assigned))
	for _, action := range assigned {
		if hasWildcard(action) {
			continue
		}
		if _, ok := usedSet[strings.ToLower(action)]; !ok {
			unused = append(unused, action)
		}
	}
	return dedupeSortedFold(unused)
}

func findRole(roleMap map[string]int, observedRole string) (int, bool) {
	for _, alias := range []string{observedRole, normalizeRoleARN(observedRole), roleNameFromARN(observedRole)} {
		if role, ok := roleMap[strings.ToLower(alias)]; ok {
			return role, true
		}
	}
	return 0, false
}

// normalizeRoleARN converts an STS assumed-role ARN to its IAM role ARN.
func normalizeRoleARN(role string) string {
	parts := strings.SplitN(role, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sts" || !strings.HasPrefix(parts[5], "assumed-role/") {
		return role
	}
	assumedRole := strings.TrimPrefix(parts[5], "assumed-role/")
	separator := strings.LastIndexByte(assumedRole, '/')
	if separator <= 0 || separator == len(assumedRole)-1 {
		return role
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", parts[1], parts[4], assumedRole[:separator])
}

func roleNameFromARN(role string) string {
	normalized := normalizeRoleARN(role)
	parts := strings.SplitN(normalized, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return normalized
	}
	resource := strings.TrimPrefix(parts[5], "role/")
	if separator := strings.LastIndexByte(resource, '/'); separator >= 0 {
		return resource[separator+1:]
	}
	return resource
}

func isCovered(action string, assigned []string) bool {
	for _, pattern := range assigned {
		if matchPrivilege(pattern, action) {
			return true
		}
	}
	return false
}

func hasWildcard(action string) bool {
	return strings.ContainsAny(action, "*?")
}

// matchPrivilege implements case-insensitive IAM-style '*' and '?' matching.
func matchPrivilege(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	matched := make([]bool, len(action)+1)
	matched[0] = true
	for i := 0; i < len(pattern); i++ {
		next := make([]bool, len(action)+1)
		switch pattern[i] {
		case '*':
			next[0] = matched[0]
			for j := 1; j <= len(action); j++ {
				next[j] = matched[j] || next[j-1]
			}
		case '?':
			for j := 1; j <= len(action); j++ {
				next[j] = matched[j-1]
			}
		default:
			for j := 1; j <= len(action); j++ {
				next[j] = matched[j-1] && pattern[i] == action[j-1]
			}
		}
		matched = next
	}
	return matched[len(action)]
}

func dedupeSortedFold(values []string) []string {
	unique := make(map[string]string, len(values))
	for _, value := range values {
		key := strings.ToLower(value)
		if existing, ok := unique[key]; !ok || lessFold(value, existing) {
			unique[key] = value
		}
	}
	result := make([]string, 0, len(unique))
	for _, value := range unique {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return lessFold(result[i], result[j]) })
	return result
}

func lessFold(left, right string) bool {
	leftFold, rightFold := strings.ToLower(left), strings.ToLower(right)
	if leftFold == rightFold {
		return left < right
	}
	return leftFold < rightFold
}
