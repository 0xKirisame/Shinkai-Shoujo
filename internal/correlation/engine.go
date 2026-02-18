package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/scraper"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// Result holds the correlation analysis for a single IAM role.
type Result struct {
	IAMRole    string
	Assigned   []string
	Used       []string
	Unused     []string
	RiskLevel  string
	AnalyzedAt time.Time
}

// Engine performs correlation between observed OTel privileges and IAM assignments.
type Engine struct {
	db         *storage.DB
	windowDays int
	log        *slog.Logger
	metrics    *metrics.Metrics
}

// NewEngine creates a new correlation Engine.
func NewEngine(db *storage.DB, windowDays int, log *slog.Logger, m *metrics.Metrics) *Engine {
	return &Engine{
		db:         db,
		windowDays: windowDays,
		log:        log,
		metrics:    m,
	}
}

// Run performs a full correlation analysis for the given role assignments.
// Results are saved to the database and returned.
func (e *Engine) Run(ctx context.Context, assignments []scraper.RoleAssignment) ([]Result, error) {
	timer := time.Now()
	since := time.Now().AddDate(0, 0, -e.windowDays)
	now := time.Now()

	e.metrics.AnalysisRuns.Inc()

	// Build a map from role ARN/name → assignment for quick lookup.
	roleMap := make(map[string]scraper.RoleAssignment, len(assignments))
	for _, a := range assignments {
		roleMap[a.RoleARN] = a
		roleMap[a.RoleName] = a
	}

	// Get all roles observed in the OTel window.
	observedRoles, err := e.db.GetObservedRoles(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("getting observed roles: %w", err)
	}

	results := make([]Result, 0, len(assignments))
	processedRoles := make(map[string]bool)

	// Process roles that appear in OTel traces.
	for _, role := range observedRoles {
		assignment, ok := roleMap[role]
		if !ok {
			e.log.Warn("role observed in OTel but not found in IAM, skipping", "role", role)
			continue
		}

		result, err := e.correlateRole(ctx, assignment, role, since, now)
		if err != nil {
			e.log.Warn("failed to correlate role", "role", role, "error", err)
			continue
		}

		results = append(results, result)
		processedRoles[assignment.RoleARN] = true
		processedRoles[assignment.RoleName] = true
	}

	// Process IAM roles with no OTel observations → all privileges are "unused".
	for _, assignment := range assignments {
		if processedRoles[assignment.RoleARN] || processedRoles[assignment.RoleName] {
			continue
		}
		result := Result{
			IAMRole:    assignment.RoleARN,
			Assigned:   assignment.Privileges,
			Used:       []string{},
			Unused:     assignment.Privileges,
			RiskLevel:  string(ClassifySet(assignment.Privileges)),
			AnalyzedAt: now,
		}
		results = append(results, result)
		if err := e.saveResult(ctx, result); err != nil {
			e.log.Warn("failed to save analysis result", "role", assignment.RoleARN, "error", err)
		}
	}

	// Update metrics.
	for _, r := range results {
		e.metrics.UnusedPrivileges.WithLabelValues(r.IAMRole, r.RiskLevel).Set(float64(len(r.Unused)))
	}

	elapsed := time.Since(timer).Seconds()
	e.metrics.AnalysisDuration.Observe(elapsed)
	e.log.Info("correlation analysis complete",
		"roles_analyzed", len(results),
		"duration_s", elapsed,
	)

	return results, nil
}

func (e *Engine) correlateRole(
	ctx context.Context,
	assignment scraper.RoleAssignment,
	observedRole string,
	since, now time.Time,
) (Result, error) {
	usedRaw, err := e.db.GetUsedPrivilegesForRole(ctx, observedRole, since)
	if err != nil {
		return Result{}, fmt.Errorf("getting used privileges: %w", err)
	}

	// Map SDK operation names to IAM action names.
	used := make([]string, 0, len(usedRaw))
	for _, p := range usedRaw {
		used = append(used, MapSDKToIAM(p))
	}

	unused := setDifference(assignment.Privileges, used)
	riskLevel := ClassifySet(unused)

	result := Result{
		IAMRole:    observedRole,
		Assigned:   assignment.Privileges,
		Used:       used,
		Unused:     unused,
		RiskLevel:  string(riskLevel),
		AnalyzedAt: now,
	}

	if err := e.saveResult(ctx, result); err != nil {
		e.log.Warn("failed to save analysis result", "role", observedRole, "error", err)
	}

	return result, nil
}

func (e *Engine) saveResult(ctx context.Context, r Result) error {
	return e.db.SaveAnalysisResult(ctx, storage.AnalysisResult{
		AnalysisDate:  r.AnalyzedAt,
		IAMRole:       r.IAMRole,
		AssignedPrivs: r.Assigned,
		UsedPrivs:     r.Used,
		UnusedPrivs:   r.Unused,
		RiskLevel:     r.RiskLevel,
	})
}

// setDifference computes assigned - used, respecting wildcard matching.
// A privilege from assigned is considered "used" if:
//   - It exactly matches a used privilege
//   - It is a wildcard "svc:*" and any "svc:X" was observed
//   - It is "*" (global wildcard) and any privilege was observed
//   - A used privilege is a wildcard that covers it
func setDifference(assigned, used []string) []string {
	if len(assigned) == 0 {
		return nil
	}

	usedSet := make(map[string]struct{}, len(used))
	for _, u := range used {
		usedSet[u] = struct{}{}
	}

	var unused []string
	for _, a := range assigned {
		if isPrivilegeUsed(a, used, usedSet) {
			continue
		}
		unused = append(unused, a)
	}
	return unused
}

// isPrivilegeUsed checks whether an assigned privilege is covered by the used set.
func isPrivilegeUsed(assigned string, used []string, usedSet map[string]struct{}) bool {
	// Direct match.
	if _, ok := usedSet[assigned]; ok {
		return true
	}

	aParts := strings.SplitN(assigned, ":", 2)
	aService := ""
	aAction := assigned
	if len(aParts) == 2 {
		aService = aParts[0]
		aAction = aParts[1]
	}

	// Global wildcard: used if ANY privilege was observed.
	if assigned == "*" {
		return len(used) > 0
	}

	// Service wildcard "svc:*": used if any "svc:X" was observed.
	if aAction == "*" {
		for _, u := range used {
			uParts := strings.SplitN(u, ":", 2)
			if len(uParts) == 2 && strings.EqualFold(uParts[0], aService) {
				return true
			}
		}
		return false
	}

	// Check if any used privilege is a wildcard that covers this action.
	for _, u := range used {
		if u == "*" {
			return true
		}
		uParts := strings.SplitN(u, ":", 2)
		if len(uParts) == 2 {
			if strings.EqualFold(uParts[0], aService) && uParts[1] == "*" {
				return true
			}
		}
	}

	return false
}
