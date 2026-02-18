package generator

import (
	"encoding/json"
	"io"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

// JSONReport is the top-level structure for JSON output.
type JSONReport struct {
	GeneratedAt time.Time   `json:"generated_at" yaml:"generated_at"`
	Roles       []JSONRole  `json:"roles"        yaml:"roles"`
}

// JSONRole holds the analysis for a single IAM role.
type JSONRole struct {
	IAMRole           string   `json:"iam_role"            yaml:"iam_role"`
	RiskLevel         string   `json:"risk_level"          yaml:"risk_level"`
	AssignedCount     int      `json:"assigned_count"      yaml:"assigned_count"`
	UsedCount         int      `json:"used_count"          yaml:"used_count"`
	UnusedCount       int      `json:"unused_count"        yaml:"unused_count"`
	AssignedPrivileges []string `json:"assigned_privileges" yaml:"assigned_privileges"`
	UsedPrivileges    []string `json:"used_privileges"     yaml:"used_privileges"`
	UnusedPrivileges  []string `json:"unused_privileges"   yaml:"unused_privileges"`
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
		role := JSONRole{
			IAMRole:            r.IAMRole,
			RiskLevel:          r.RiskLevel,
			AssignedCount:      len(r.Assigned),
			UsedCount:          len(r.Used),
			UnusedCount:        len(r.Unused),
			AssignedPrivileges: r.Assigned,
			UsedPrivileges:     r.Used,
			UnusedPrivileges:   r.Unused,
		}
		if role.AssignedPrivileges == nil {
			role.AssignedPrivileges = []string{}
		}
		if role.UsedPrivileges == nil {
			role.UsedPrivileges = []string{}
		}
		if role.UnusedPrivileges == nil {
			role.UnusedPrivileges = []string{}
		}
		roles = append(roles, role)
	}
	return JSONReport{
		GeneratedAt: time.Now(),
		Roles:       roles,
	}
}
