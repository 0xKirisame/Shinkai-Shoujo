package generator

import (
	"encoding/json"
	"io"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

// JSONReport is the top-level structure for JSON output.
type JSONReport struct {
	GeneratedAt time.Time  `json:"generated_at" yaml:"generated_at"`
	Roles       []JSONRole `json:"roles"        yaml:"roles"`
}

// JSONRole holds the analysis for a single IAM role.
type JSONRole struct {
	AccountID            string      `json:"account_id"             yaml:"account_id"`
	IAMRole              string      `json:"iam_role"               yaml:"iam_role"`
	RiskLevel            string      `json:"risk_level"             yaml:"risk_level"`
	ObservationStart     time.Time   `json:"observation_start"      yaml:"observation_start"`
	AnalyzedAt           time.Time   `json:"analyzed_at"            yaml:"analyzed_at"`
	Assigned             []string    `json:"assigned"               yaml:"assigned"`
	AssignedCount        int         `json:"assigned_count"         yaml:"assigned_count"`
	Used                 []string    `json:"used"                   yaml:"used"`
	UsedCount            int         `json:"used_count"             yaml:"used_count"`
	CandidateUnused      []string    `json:"candidate_unused"       yaml:"candidate_unused"`
	CandidateUnusedCount int         `json:"candidate_unused_count" yaml:"candidate_unused_count"`
	Unresolved           []string    `json:"unresolved"             yaml:"unresolved"`
	UnresolvedCount      int         `json:"unresolved_count"       yaml:"unresolved_count"`
	Warnings             []string    `json:"warnings"               yaml:"warnings"`
	Usage                []JSONUsage `json:"usage"                  yaml:"usage"`
}

// JSONUsage holds observed event counts and successful-use timestamps for an IAM action.
type JSONUsage struct {
	Action           string    `json:"action"            yaml:"action"`
	SuccessfulEvents uint64    `json:"successful_events" yaml:"successful_events"`
	DeniedEvents     uint64    `json:"denied_events"     yaml:"denied_events"`
	FailedEvents     uint64    `json:"failed_events"     yaml:"failed_events"`
	FirstSuccess     time.Time `json:"first_success"     yaml:"first_success"`
	LastSuccess      time.Time `json:"last_success"      yaml:"last_success"`
}

// JSONGenerator produces JSON-formatted reports.
type JSONGenerator struct{}

// Generate writes a JSON report to w.
func (g *JSONGenerator) Generate(results []correlation.Result, w io.Writer) error {
	report := buildReport(results)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// buildReport converts correlation results into a JSONReport.
func buildReport(results []correlation.Result) JSONReport {
	roles := make([]JSONRole, 0, len(results))
	for _, r := range results {
		usage := make([]JSONUsage, 0, len(r.Usage))
		for _, item := range r.Usage {
			usage = append(usage, JSONUsage{
				Action:           item.Action,
				SuccessfulEvents: item.SuccessfulEvents,
				DeniedEvents:     item.DeniedEvents,
				FailedEvents:     item.FailedEvents,
				FirstSuccess:     item.FirstSuccess,
				LastSuccess:      item.LastSuccess,
			})
		}

		role := JSONRole{
			AccountID:            r.AccountID,
			IAMRole:              r.IAMRole,
			RiskLevel:            r.RiskLevel,
			ObservationStart:     r.ObservationStart,
			AnalyzedAt:           r.AnalyzedAt,
			Assigned:             nonNilStrings(r.Assigned),
			AssignedCount:        len(r.Assigned),
			Used:                 nonNilStrings(r.Used),
			UsedCount:            len(r.Used),
			CandidateUnused:      nonNilStrings(r.Unused),
			CandidateUnusedCount: len(r.Unused),
			Unresolved:           nonNilStrings(r.Unresolved),
			UnresolvedCount:      len(r.Unresolved),
			Warnings:             nonNilStrings(r.Warnings),
			Usage:                usage,
		}
		roles = append(roles, role)
	}
	return JSONReport{
		GeneratedAt: time.Now(),
		Roles:       roles,
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
